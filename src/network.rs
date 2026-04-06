//! `network.rs` — P2P транспортный слой на базе `iroh`.
//!
//! Стратегия:
//!  * `iroh::Endpoint` (MagicSock) — пробивка NAT через QUIC.
//!  * `LocalSwarmDiscovery` — mDNS-подобное обнаружение пиров в локальной сети.
//!  * `RelayMode::Default` — community DERP/relay серверы Iroh без аренды серверов.
//!  * `add_peer_by_addr` — ручной обмен контактами (QR-рукопожатие).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use iroh::{
    discovery::mdns::MdnsDiscovery, endpoint::Connection, Endpoint, NodeAddr, NodeId, RelayMode,
    SecretKey,
};
use rand::rngs::OsRng;
use tracing::{info, warn};

use crate::{storage, sync_protocol, transport, PlexError};

/// ALPN-идентификаторы протоколов Plex.
/// Изоляция по ALPN гарантирует, что синхронизирующий узел  
/// не может быть принудительно обращён в чат- или звонок-хендлер.
pub const SYNC_ALPN: &[u8] = b"plex/sync/1";
pub const CHAT_ALPN: &[u8] = b"plex/chat/1";
pub const CALL_ALPN: &[u8] = b"plex/call/1";

/// Опциональный callback, вызываемый после успешного sync с пиром.
/// Аргументы: `from_peer_id: String`, `new_events: u64`.
/// Используется `PlexNode` и `PlexReceiverNode` для wake-up уведомлений.
pub type SyncEventCallback = std::sync::Arc<dyn Fn(String, u64) + Send + Sync + 'static>;

/// Конфигурация iroh-узла, передаваемая при старте.
///
/// `secret_key_bytes` — опциональный постоянный Ed25519-ключ (32 байта).  
/// Если `None` — генерируется эфемерный ключ при каждом запуске.  
/// `relay_urls` — список HTTPS-адресов собственных DERP-серверов.  
/// Если пустой — используются community-серверы Iroh (`RelayMode::Default`).
/// `disable_mdns` — отключить mDNS-обнаружение (рекомендуется в контролируемых сетях).
pub struct NodeConfig {
    pub secret_key_bytes: Option<[u8; 32]>,
    pub relay_urls: Vec<String>,
    pub disable_mdns: bool,
    /// Если `true` — прямые UDP-адреса не публикуются и не используются.
    /// Весь трафик идёт через relay (HTTPS/TCP 443) — обходит блокировки QUIC/UDP (РКН и т.п.).
    pub relay_only: bool,
}

// ── DERP / Relay ──────────────────────────────────────────────────────────────
//
// iroh использует RelayMode::Default, который указывает на публичные DERP-серверы
// сообщества n0 (https://derp.iroh.network/).
// Ни один сервер не арендуется — только community-инфраструктура.

/// Обёртка над `iroh::Endpoint` с настроенным mDNS и DERP.
pub struct IrohNode {
    endpoint: Endpoint,
    secret_key: SecretKey,
    local_mesh_peers: Mutex<HashMap<String, LocalMeshPeer>>,
    relay_only: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PeerContact {
    /// NodeID пира в base32-строке.
    pub node_id: String,
    /// Home relay пира, если известен.
    pub relay_url: Option<String>,
    /// Текущие адреса, доступные для прямого соединения.
    pub direct_addresses: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct LocalMeshPeer {
    pub peer_id: String,
    pub medium: String,
    pub endpoint_hint: String,
    pub signal_strength: Option<i32>,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone)]
pub struct TransportInventoryEntry {
    pub kind: transport::TransportKind,
    pub is_available: bool,
    pub core_connect_supported: bool,
    pub capabilities: transport::TransportCapabilities,
    pub priority: u8,
}

impl IrohNode {
    /// Создаёт iroh-узел с дефолтными параметрами (эфемерный ключ, community DERP).
    #[allow(dead_code)]
    pub async fn start() -> Result<Self, PlexError> {
        Self::start_with_config(NodeConfig {
            secret_key_bytes: None,
            relay_urls: vec![],
            disable_mdns: false,
            relay_only: false,
        })
        .await
    }

    /// Создаёт iroh-узел с явной конфигурацией.
    ///
    /// * Если `config.secret_key_bytes` задан — использует постоянный ключ;
    ///   иначе генерирует эфемерный.
    /// * Если `config.relay_urls` не пуст — Use `RelayMode::Custom` с этими серверами;
    ///   иначе `RelayMode::Default` (community DERP).
    pub async fn start_with_config(config: NodeConfig) -> Result<Self, PlexError> {
        let secret_key = match config.secret_key_bytes {
            Some(bytes) => SecretKey::from(bytes),
            None => SecretKey::generate(&mut OsRng),
        };
        let node_id = secret_key.public();

        let relay_mode = if config.relay_urls.is_empty() {
            RelayMode::Default
        } else {
            use iroh::{RelayMap, RelayUrl};
            let relay_map: RelayMap = config
                .relay_urls
                .iter()
                .filter_map(|url| url.parse::<RelayUrl>().ok())
                .collect();
            if relay_map.is_empty() {
                RelayMode::Default
            } else {
                RelayMode::Custom(relay_map)
            }
        };

        // mDNS / local peer discovery — условно: в контролируемых сетях раскрывает присутствие.
        let mut builder = Endpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![
                SYNC_ALPN.to_vec(),
                CHAT_ALPN.to_vec(),
                CALL_ALPN.to_vec(),
            ])
            .relay_mode(relay_mode);

        if !config.disable_mdns {
            let local_discovery = MdnsDiscovery::new(node_id)
                .context("MdnsDiscovery init failed")
                .map_err(|e| PlexError::Network { msg: e.to_string() })?;
            builder = builder.discovery(Box::new(local_discovery));
        }

        let endpoint = builder.bind().await.map_err(|e| PlexError::Network {
            msg: format!("Endpoint bind failed: {e}"),
        })?;

        info!(
            persistent_key = config.secret_key_bytes.is_some(),
            mdns_enabled = !config.disable_mdns,
            "iroh Endpoint started"
        );

        Ok(IrohNode {
            endpoint,
            secret_key,
            local_mesh_peers: Mutex::new(HashMap::new()),
            relay_only: config.relay_only,
        })
    }

    /// Возвращает NodeID текущего узла.
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Возвращает клон `Endpoint` для передачи во вспомогательные задачи.
    pub fn endpoint_clone(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Возвращает секретный ключ узла для локальной подписи событий.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Закрывает QUIC endpoint, прерывая все активные соединения и вызывая
    /// завершение фоновых задач (incoming connection loop возвращает `None`).
    pub async fn close_endpoint(&self) {
        let _ = self.endpoint.close().await;
    }

    /// Возвращает текущие contact data узла для QR-обмена.
    pub async fn local_contact(&self) -> Result<PeerContact, PlexError> {
        let node_addr = self
            .endpoint
            .node_addr()
            .await
            .map_err(|e| PlexError::Network {
                msg: format!("Cannot resolve local NodeAddr: {e}"),
            })?;

        let mut contact = peer_contact_from_node_addr(&node_addr);
        if self.relay_only {
            // В режиме relay-only не публикуем прямые UDP-адреса.
            // Пиры будут подключаться исключительно через relay (HTTPS/TCP).
            contact.direct_addresses = vec![];
        }
        Ok(contact)
    }

    pub fn transport_inventory(&self) -> Vec<TransportInventoryEntry> {
        let has_local_mesh_candidates = self
            .local_mesh_peers
            .lock()
            .map(|peers| !peers.is_empty())
            .unwrap_or(false);

        vec![
            TransportInventoryEntry {
                kind: transport::TransportKind::IrohQuic,
                is_available: true,
                core_connect_supported: true,
                capabilities: transport::capabilities_for(transport::TransportKind::IrohQuic),
                priority: 100,
            },
            TransportInventoryEntry {
                kind: transport::TransportKind::LocalMesh,
                is_available: has_local_mesh_candidates,
                core_connect_supported: false,
                capabilities: transport::capabilities_for(transport::TransportKind::LocalMesh),
                priority: 90,
            },
        ]
    }

    pub fn report_local_mesh_peer(&self, peer: LocalMeshPeer) -> Result<(), PlexError> {
        if peer.peer_id.trim().is_empty() {
            return Err(PlexError::Network {
                msg: "Local mesh peer_id must not be empty".into(),
            });
        }

        if peer.medium.trim().is_empty() {
            return Err(PlexError::Network {
                msg: "Local mesh medium must not be empty".into(),
            });
        }

        if peer.endpoint_hint.trim().is_empty() {
            return Err(PlexError::Network {
                msg: "Local mesh endpoint hint must not be empty".into(),
            });
        }

        self.local_mesh_peers
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Local mesh registry mutex poisoned: {e}"),
            })?
            .insert(peer.peer_id.clone(), peer);

        Ok(())
    }

    pub fn local_mesh_peers(&self) -> Result<Vec<LocalMeshPeer>, PlexError> {
        let peers = self
            .local_mesh_peers
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Local mesh registry mutex poisoned: {e}"),
            })?
            .values()
            .cloned()
            .collect::<Vec<_>>();

        Ok(peers)
    }

    pub fn prune_local_mesh_peers(&self, older_than: i64) -> Result<u64, PlexError> {
        let mut peers = self
            .local_mesh_peers
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Local mesh registry mutex poisoned: {e}"),
            })?;

        let before = peers.len();
        peers.retain(|_, peer| peer.last_seen_at >= older_than);
        Ok((before.saturating_sub(peers.len())) as u64)
    }
}

// ── mDNS peer-discovery logger ────────────────────────────────────────────────

/// Фоновый цикл: логирует NodeID всех пиров,
/// которые discovery-механизмы пассивно находят в локальной сети.
///
/// В будущей итерации: отправлять события в UI через uniffi::callback.
pub async fn run_local_discovery_logger(node: Arc<IrohNode>) {
    info!("Local discovery logger started — waiting for LAN peers...");

    let mut discovery_stream = node.endpoint.discovery_stream();

    while let Some(item) = discovery_stream.next().await {
        match item {
            Ok(discovery) => {
                let peer_addr = discovery.to_node_addr();
                let direct_addresses = peer_addr
                    .direct_addresses()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>();

                info!(
                    peer = %discovery.node_id(),
                    provenance = discovery.provenance(),
                    relay = ?peer_addr.relay_url(),
                    direct_addresses = ?direct_addresses,
                    "Peer discovered"
                );
            }
            Err(lagged) => {
                warn!(
                    ?lagged,
                    "Discovery stream lagged; some peer updates were dropped"
                );
            }
        }
    }

    info!("Endpoint closed, stopping local discovery logger");
}

/// Фоновый цикл: принимает входящие QUIC-соединения и маршрутизирует по ALPN.
///
/// `plex/sync/1`  → `handle_peer_connection` (sync-протокол)  
/// `plex/chat/1`  → зарезервировано, логируется и закрывается  
/// `plex/call/1`  → зарезервировано, логируется и закрывается  
/// Любой другой ALPN → немедленный close (защита от ALPN-confusion атак).
pub async fn run_incoming_connection_loop(
    node: Arc<IrohNode>,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
    on_sync: Option<SyncEventCallback>,
) {
    info!("Incoming connection loop started");

    loop {
        match node.endpoint.accept().await {
            Some(incoming) => {
                let db = Arc::clone(&db);
                let metrics = Arc::clone(&metrics);
                let on_sync = on_sync.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let peer_id = conn.remote_node_id().ok();
                            let alpn = conn.alpn();
                            match alpn.as_deref() {
                                Some(alpn) if alpn == SYNC_ALPN => {
                                    tracing::debug!(peer = ?peer_id, "Incoming sync connection");
                                    handle_peer_connection(conn, db, metrics, on_sync).await;
                                }
                                Some(alpn) if alpn == CHAT_ALPN => {
                                    // CHAT-канал не реализован на transport-уровне; закрываем соединение.
                                    conn.close(0u32.into(), b"not-implemented");
                                }
                                Some(alpn) if alpn == CALL_ALPN => {
                                    // CALL-канал не реализован на transport-уровне; закрываем соединение.
                                    conn.close(0u32.into(), b"not-implemented");
                                }
                                other => {
                                    warn!(peer = ?peer_id, alpn = ?other, "Unexpected ALPN — closing");
                                    conn.close(0u32.into(), b"unknown alpn");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Incoming connection error: {e}");
                        }
                    }
                });
            }
            None => {
                info!("Endpoint closed, stopping incoming connection loop");
                break;
            }
        }
    }
}

/// Обрабатывает одно P2P соединение: запускает serve-loop и initiator-sync.
/// Если `on_sync` задан — вызывается при поступлении новых событий (applied > 0).
pub async fn handle_peer_connection(
    conn: Connection,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
    on_sync: Option<SyncEventCallback>,
) {
    let peer_id = conn.remote_node_id().ok();

    let serve_conn = conn.clone();
    let serve_db = Arc::clone(&db);
    tokio::spawn(async move {
        if let Err(e) = sync_protocol::serve_sync_requests(serve_conn, serve_db).await {
            warn!("Sync server loop stopped: {e}");
        }
    });

    match sync_protocol::request_sync(conn, db, Arc::clone(&metrics)).await {
        Ok(applied) => {
            tracing::debug!(peer = ?peer_id, applied_events = applied, "Initial sync completed");
            metrics
                .sync_rounds_completed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics
                .sync_events_inserted_total
                .fetch_add(applied as u64, std::sync::atomic::Ordering::Relaxed);
            if applied > 0 {
                if let Some(ref cb) = on_sync {
                    let peer_str = peer_id.map(|p| p.to_string()).unwrap_or_default();
                    cb(peer_str, applied as u64);
                }
            }
        }
        Err(_e) => {
            warn!("Initial sync failed for a peer");
        }
    }
}

// ── Manual Peer Exchange (QR-рукопожатие) ────────────────────────────────────

/// Инициирует активное исходящее QUIC-соединение (push sync) к известному пиру.
/// Вызывается фоновым Outbox-воркером сразу после отправки нового сообщения
/// для мгновенной доставки. В отличие от `add_peer_from_contact`,
/// предполагает, что iroh's MagicSock уже знает маршрут до пира из предыдущих
/// вызовов или загрузки из DB.
pub async fn trigger_sync_with_peer(
    node: Arc<IrohNode>,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
    peer_id_str: String,
    on_sync: Option<SyncEventCallback>,
) -> Result<(), PlexError> {
    let peer_id: NodeId = peer_id_str.parse().map_err(|e| PlexError::Network {
        msg: format!("Invalid NodeID '{peer_id_str}' for push sync: {e}"),
    })?;

    // Прямое подключение по NodeId; MagicSock использует ранее известные адреса/relay
    let conn = node
        .endpoint
        .connect(peer_id, SYNC_ALPN)
        .await
        .map_err(|e| PlexError::Network {
            msg: format!("Push sync to {peer_id} failed: {e}"),
        })?;

    tracing::debug!(peer = %peer_id, "Triggered opportunistic push sync connection");

    // Запускаем стандартный цикл синхронизации
    tokio::spawn(handle_peer_connection(conn, db, metrics, on_sync));

    Ok(())
}

/// Добавляет пир вручную по NodeID + адресу из QR-кода.
pub async fn add_peer_by_addr(
    node: Arc<IrohNode>,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
    node_id_str: String,
    addr_str: String,
    on_sync: Option<SyncEventCallback>,
) -> Result<(), PlexError> {
    // Парсим NodeID из base32-строки
    let peer_id: NodeId = node_id_str.parse().map_err(|e| PlexError::Network {
        msg: format!("Invalid NodeID '{node_id_str}': {e}"),
    })?;

    // Парсим SocketAddr
    let socket_addr: std::net::SocketAddr = addr_str.parse().map_err(|e| PlexError::Network {
        msg: format!("Invalid address '{addr_str}': {e}"),
    })?;

    let route = transport::TransportRoute {
        kind: transport::TransportKind::IrohQuic,
        peer_id: peer_id.to_string(),
        relay_url: None,
        direct_addresses: vec![socket_addr.to_string()],
        is_available: true,
        core_connect_supported: true,
        priority: 100,
        capabilities: transport::capabilities_for(transport::TransportKind::IrohQuic),
    };

    let conn = connect_via_route(&node, &route).await?;

    info!(
        peer  = %peer_id,
        raddr = %socket_addr,
        transport = route.kind.as_str(),
        "Manual peer connected via QR handshake"
    );

    // Фоновый обработчик для этого соединения
    tokio::spawn(handle_peer_connection(conn, db, metrics, on_sync));

    Ok(())
}

/// Добавляет пир по полным contact data, сериализованным для QR-кода.
pub async fn add_peer_from_contact(
    node: Arc<IrohNode>,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
    contact_json: String,
    on_sync: Option<SyncEventCallback>,
) -> Result<(), PlexError> {
    let contact: PeerContact =
        serde_json::from_str(&contact_json).map_err(|e| PlexError::Network {
            msg: format!("Invalid contact JSON: {e}"),
        })?;

    let peer_id: NodeId = contact.node_id.parse().map_err(|e| PlexError::Network {
        msg: format!("Invalid NodeID '{}': {e}", contact.node_id),
    })?;

    let mut routes = transport_routes_from_contact(&contact);
    routes.extend(local_mesh_routes_for_peer(&node, &contact.node_id)?);
    let route = transport::choose_best_route(
        &routes,
        transport::TransportSelectionPolicy::interactive_sync(),
    )
    .ok_or_else(|| PlexError::Network {
        msg: format!("No usable transport route found for peer {peer_id}"),
    })?;

    let conn = connect_via_route(&node, &route).await?;

    info!(peer = %peer_id, transport = route.kind.as_str(), "Manual peer connected via contact QR handshake");
    tokio::spawn(handle_peer_connection(conn, db, metrics, on_sync));

    Ok(())
}

fn transport_routes_from_contact(contact: &PeerContact) -> Vec<transport::TransportRoute> {
    vec![transport::TransportRoute {
        kind: transport::TransportKind::IrohQuic,
        peer_id: contact.node_id.clone(),
        relay_url: contact.relay_url.clone(),
        direct_addresses: contact.direct_addresses.clone(),
        is_available: true,
        core_connect_supported: true,
        priority: 100,
        capabilities: transport::capabilities_for(transport::TransportKind::IrohQuic),
    }]
}

fn local_mesh_routes_for_peer(
    node: &IrohNode,
    peer_id: &str,
) -> Result<Vec<transport::TransportRoute>, PlexError> {
    let peers = node.local_mesh_peers()?;
    Ok(peers
        .into_iter()
        .filter(|peer| peer.peer_id == peer_id)
        .map(|peer| transport::TransportRoute {
            kind: transport::TransportKind::LocalMesh,
            peer_id: peer.peer_id,
            relay_url: None,
            direct_addresses: vec![peer.endpoint_hint],
            is_available: true,
            core_connect_supported: false,
            priority: 90,
            capabilities: transport::capabilities_for(transport::TransportKind::LocalMesh),
        })
        .collect())
}

async fn connect_via_route(
    node: &IrohNode,
    route: &transport::TransportRoute,
) -> Result<Connection, PlexError> {
    match route.kind {
        transport::TransportKind::IrohQuic => {
            let peer_id: NodeId = route.peer_id.parse().map_err(|e| PlexError::Network {
                msg: format!("Invalid NodeID '{}': {e}", route.peer_id),
            })?;

            let direct_addresses: Vec<std::net::SocketAddr> = if node.relay_only {
                // relay-only: не пытаемся UDP-подключения, только relay (HTTPS/TCP)
                vec![]
            } else {
                route
                    .direct_addresses
                    .iter()
                    .filter_map(|addr| match addr.parse::<std::net::SocketAddr>() {
                        Ok(parsed) => Some(parsed),
                        Err(e) => {
                            tracing::warn!("Ignoring unparsable direct address '{}': {}", addr, e);
                            None
                        }
                    })
                    .collect()
            };

            let relay_url = match &route.relay_url {
                Some(relay_url) => Some(relay_url.parse().map_err(|e| PlexError::Network {
                    msg: format!("Invalid relay URL '{relay_url}': {e}"),
                })?),
                None => None,
            };

            let peer_addr = NodeAddr::from_parts(peer_id, relay_url, direct_addresses);

            node.endpoint
                .add_node_addr(peer_addr.clone())
                .map_err(|e| PlexError::Network {
                    msg: format!("Cannot add peer address book entry: {e}"),
                })?;

            node.endpoint
                .connect(peer_addr, SYNC_ALPN)
                .await
                .map_err(|e| PlexError::Network {
                    msg: format!("Connect to {peer_id} failed: {e}"),
                })
        }
        unsupported => Err(PlexError::Network {
            msg: format!("Transport {} is not implemented yet", unsupported.as_str()),
        }),
    }
}

fn peer_contact_from_node_addr(node_addr: &NodeAddr) -> PeerContact {
    PeerContact {
        node_id: node_addr.node_id.to_string(),
        relay_url: node_addr.relay_url().map(std::string::ToString::to_string),
        direct_addresses: node_addr
            .direct_addresses()
            .filter_map(|addr| {
                let s = addr.to_string();
                // Filter out IPv6 link-local (SLAAC) which leaks hardware MAC ("physical address")
                // and OS scope IDs (%wlan0) which fail to parse on the recipient.
                let is_link_local_ipv6 = s.starts_with("[fe80:") || s.starts_with("[FE80:");
                if s.contains('%') || is_link_local_ipv6 {
                    None
                } else {
                    Some(s)
                }
            })
            .collect(),
    }
}
