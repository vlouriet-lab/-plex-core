//! `lib.rs` — точка входа Plex Core.
//!
//! Здесь:
//!  * Регистрируется UniFFI-скаффолдинг (proc-macro режим).
//!  * Живёт `PlexNode` — главный объект, который Kotlin/Swift получают через FFI.
//!  * `init_node(db_key)` открывает зашифрованную БД и поднимает iroh-узел.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use secrecy::SecretString;
use tokio::runtime::Runtime;

use tracing::{info, warn};
use zeroize::Zeroize;

pub mod bridge;
mod call_media;
mod call_state;
mod calls;
mod chat_protocol;
pub mod connection_pool;
mod crypto;
mod dht;
pub mod events;
mod ffi_bridge;
mod ffi_call_media;
mod ffi_calls;
mod ffi_chat;
mod ffi_crypto;
mod ffi_dht;
mod ffi_identity;
mod ffi_mesh;
mod ffi_message_router;
mod ffi_metrics;
mod ffi_outbox;
mod ffi_profile;
mod ffi_receiver;
mod ffi_storage;
mod ffi_sync;
mod ffi_transfer;
mod ffi_x3dh;
mod mesh_handoff;
pub mod message_router;
mod metrics;
mod network;
mod relay_reputation;
pub mod storage;
mod sync_protocol;
pub mod transfer;
mod transport;
mod x3dh;

pub use events::{LogLevel, PlexCoreEvent};
pub use ffi_bridge::{BridgeConfigRecord, BridgeStatusRecord, PlexBridgeManager};
pub use ffi_call_media::{CallIceStateRecord, CallMediaRouteRecord, CallMediaSessionRecord};
pub use ffi_calls::{
    CallMaintenanceReport, CallSessionRecord, CallSessionStateRecord, CallSignalDirection,
    CallSignalPruneReport, CallSignalRecord, CallSignalType, SavedCallSignalRecord,
};
pub use ffi_chat::{
    ChatDialogSummaryRecord, ChatMediaMetaRecord, ChatMessageKindRecord, ChatMessageRecord,
    IncomingChatIngestReport, IngestFromEventLogReport,
};
pub use ffi_dht::DhtMaintenanceReport;
pub use ffi_identity::{PeerTrustLevel, PeerVerificationStatus, VerificationPolicy};
pub use ffi_mesh::{
    LocalMeshPeerRecord, MeshBundleExportRecord, MeshHandoffChunkRecord, MeshHandoffOfferRecord,
    MeshHandoffPreparedRecord, MeshHandoffProgressRecord, MeshHandoffRetransmitRequestRecord,
    MeshSyncImportReport,
};
pub use ffi_message_router::{DeliveryStatusRecord, OutboundMessageRecord, RoutingDecisionRecord};
pub use ffi_metrics::CoreMetricsRecord;
pub use ffi_outbox::{DeliveryMaintenanceReport, OutboxMessageRecord};
pub use ffi_profile::{
    BlockedPeerRecord, ContactRecord, DiscoveredPeerRecord, PeerConnectionStatusRecord,
    RelayNodeRecord, UserProfileRecord,
};
pub use ffi_receiver::{IncomingEventCallback, PlexReceiverNode};
pub use ffi_storage::RebuildProjectionsReport;
pub use ffi_sync::SyncHealthRecord;
pub use ffi_transfer::{FileTransferRecord, FileTransferStatusRecord, TransferProgressRecord};
pub use ffi_x3dh::{PrekeyBundleRecord, X3dhInitMessageRecord, X3dhPrekeyStatsRecord};

// ── Bridge Protocol ──────────────────────────────────────────────────────────
pub use bridge::{BridgeConfig, BridgeError, BridgeManager, BridgeProtocol, BridgeStatus};
// ── Message Routing ──────────────────────────────────────────────────────
pub use message_router::{
    DeliveryRecord, DeliveryStatus, MessageRetryQueue, MessageRouterError, OutboundMessageEnvelope,
    RoutingDecision,
};

// ── File Transfer ────────────────────────────────────────────────────────────
pub use transfer::{
    FileTransferEnvelope, FileTransferMetadata, TransferError, TransferId, TransferManager,
    TransferProgress, TransferState,
};

// ── UniFFI ────────────────────────────────────────────────────────────────────
// setup_scaffolding! регистрирует весь FFI-слой на основе #[uniffi::export].
uniffi::setup_scaffolding!();

// ── Ошибки ────────────────────────────────────────────────────────────────────
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlexError {
    #[error("Storage error: {msg}")]
    Storage { msg: String },

    #[error("Network error: {msg}")]
    Network { msg: String },

    #[error("Crypto error: {msg}")]
    Crypto { msg: String },

    #[error("Rate limit error: {msg}")]
    RateLimit { msg: String },

    #[error("Timeout error: {msg}")]
    Timeout { msg: String },

    #[error("Validation error: {msg}")]
    Validation { msg: String },

    #[error("Not found: {msg}")]
    NotFound { msg: String },

    #[error("Invalid input: {msg}")]
    InvalidInput { msg: String },

    #[error("Internal error: {msg}")]
    Internal { msg: String },
}

impl From<anyhow::Error> for PlexError {
    fn from(e: anyhow::Error) -> Self {
        PlexError::Internal { msg: e.to_string() }
    }
}

// ── PlexNode ──────────────────────────────────────────────────────────────────

/// Конфигурация Plex-узла, передаваемая при инициализации.
/// Все поля опциональны — отсутствующие значения дают разумный дефолт.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PlexNodeConfigRecord {
    /// Список HTTPS-URL собственных DERP-relay серверов.
    /// Если пустой —  используются community-серверы Iroh.
    pub relay_urls: Vec<String>,
    /// Отключает mDNS-обнаружение пиров в локальной сети.
    /// Рекомендуется включать в средах высокого риска (контролируемая WiFi-сеть,
    /// корпоративные WiFi, бортовые сети) — mDNS-мультикасты видны всем в WiFi-сегменте.
    pub disable_mdns: bool,
    /// Если `true` — прямые UDP-адреса не публикуются и не используются при подключении.
    /// Весь трафик идёт через relay (HTTPS/TCP 443) — обходит блокировки QUIC/UDP (РКН и т.п.).
    pub relay_only: bool,
}

/// Главный объект ядра. Kotlin/Swift держат его через Arc.
#[derive(uniffi::Object)]
pub struct PlexNode {
    /// Глобальный Tokio-рантайм (один на процесс).
    rt: Arc<Runtime>,
    /// iroh-узел с активными соединениями.
    iroh: Arc<network::IrohNode>,
    /// Хэндл к зашифрованной БД.
    db: Arc<storage::Db>,
    /// Защита от повторного старта фоновых сетевых задач.
    background_tasks_started: AtomicBool,
    /// In-memory сессии Double Ratchet, ключ = NodeID пира.
    ratchet_sessions: Mutex<HashMap<String, crypto::RatchetSession>>,
    /// In-memory сборка transport-neutral mesh handoff sessions.
    incoming_mesh_handoffs: Mutex<HashMap<String, mesh_handoff::IncomingMeshHandoff>>,
    /// In-memory call state machine sessions.
    call_sessions: Mutex<HashMap<String, call_state::CallSession>>,
    /// In-memory media-plane call sessions для Android call UI.
    call_media_sessions: Mutex<HashMap<String, call_media::CallMediaSession>>,
    /// Монотонные счётчики производительности (metrics/observability).
    pub(crate) metrics: Arc<metrics::CoreMetrics>,
    /// Rate-limit окна на ingestion входящих сообщений (peer_id → (count, window_start_unix_secs)).
    pub(crate) ingest_rate_limits: Mutex<HashMap<String, (u32, i64)>>,
    /// Максимальный размер DHT-кэша в байтах. 0 = без ограничения.
    pub(crate) dht_cache_max_bytes: std::sync::atomic::AtomicU64,
    /// Размер порции постепенного вытеснения DHT-кэша (записей за один maintenance tick).
    pub(crate) dht_eviction_batch_size: std::sync::atomic::AtomicU32,
    /// Callback для уведомлений о входящих sync-событиях (опционально).
    incoming_event_callback:
        Arc<std::sync::Mutex<Option<Arc<dyn ffi_receiver::IncomingEventCallback>>>>,
    /// Пул постоянных QUIC-соединений к известным контактам.
    pub(crate) connection_pool: connection_pool::ConnectionPool,
    /// Менеджер bridge-узлов для обхода цензуры.
    pub(crate) bridge_manager: Arc<bridge::BridgeManager>,
    /// Retry-очередь для неудачных сообщений с exponential backoff.
    pub(crate) message_retry_queue: Arc<message_router::MessageRetryQueue>,
    /// Менеджер трансферов файлов с progress-tracking.
    pub(crate) transfer_manager: Arc<transfer::TransferManager>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TransportInfoRecord {
    pub kind: String,
    pub is_available: bool,
    pub core_connect_supported: bool,
    pub lan_discovery: bool,
    pub internet_required: bool,
    pub store_and_forward: bool,
    pub dpi_masquerade_ready: bool,
    pub priority: u8,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContractInfoRecord {
    pub contract_version: u32,
    pub error_variants: Vec<String>,
    pub supports_typed_errors: bool,
    pub supports_argon2id_kdf: bool,
    pub supports_bounded_sync_reads: bool,
    pub supports_chat_media_v1: bool,
    pub supports_call_media_contract_v1: bool,
    /// ICE state tracking + call signal persistence (v5+).
    pub supports_call_ice_state_v1: bool,
    /// Structured observability metrics snapshot (v5+).
    pub supports_observability_v1: bool,
    /// Sync health snapshot FFI (v5+).
    pub supports_sync_health_v1: bool,
    /// Постоянный identity-ключ iroh-узла, переживает рестарты (v6+).
    pub supports_persistent_identity_v1: bool,
    /// ALPN-изоляция sync/chat/call протоколов (v6+).
    pub supports_alpn_isolation_v1: bool,
    /// Настраиваемые DERP-relay серверы (v6+).
    pub supports_configurable_relay_v1: bool,
    /// Rate-limit входящих сообщений на пира (v6+).
    pub supports_ingest_rate_limit_v1: bool,
    /// Auth gate для sync: неизвестные peer не получают event log (v7+).
    pub supports_sync_auth_gate_v1: bool,
    /// Корректное завершение QUIC endpoint при shutdown (v7+).
    pub supports_graceful_shutdown_v1: bool,
    /// peer_id в AAD шифрования ratchet snapshot (v7+).
    pub supports_ratchet_aad_v1: bool,
    /// Интеллектуальная очистка DHT-кэша с подтверждением пользователя (v8+).
    pub supports_dht_cache_eviction_v1: bool,
    /// Blocklist пиров: block_peer/unblock_peer/list_blocked_peers (v9+).
    pub supports_peer_blocklist_v1: bool,
    /// Флаг отключения mDNS в PlexNodeConfigRecord (v9+).
    pub supports_mdns_control_v1: bool,
    /// X3DH key agreement: publish_prekeys, init_session, accept_session, rotate_spk (v10+).
    pub supports_x3dh_v1: bool,
    /// Фоновый receiver-mode без Google FCM (v11+).
    pub supports_receiver_mode_v1: bool,
    /// relay-only режим: весь трафик через HTTPS/TCP, обход блокировок QUIC/UDP (v12+).
    pub supports_relay_only_v1: bool,
    /// Username-first контакты: ContactRecord.username, search_contacts_by_username (v12+).
    pub supports_username_contacts_v1: bool,
    /// DHT-анонс по username: profile_announce + username_lookup (v12+).
    pub supports_username_discovery_v1: bool,
    /// Пул постоянных соединений: connection_pool_status + pool_reconnect_all (v12+).
    pub supports_persistent_pool_v1: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CoreHealthSnapshotRecord {
    pub node_id: String,
    pub now_unix_secs: i64,
    pub latest_event_hash: Option<String>,
    pub total_events: u64,
    pub loaded_ratchet_sessions: u64,
    pub active_call_sessions: u64,
    pub active_call_media_sessions: u64,
    pub active_mesh_handoff_sessions: u64,
    pub background_tasks_started: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StartupReadinessRecord {
    pub contract_version: u32,
    pub node_id: String,
    pub db_open_ok: bool,
    pub runtime_ready: bool,
    pub background_tasks_started: bool,
    pub health_snapshot_available: bool,
    pub health_latest_error: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiErrorCatalogEntryRecord {
    pub code: String,
    pub variant: String,
    pub retryable: bool,
    pub user_message_key: String,
}

const FFI_CONTRACT_VERSION: u32 = 12;

#[uniffi::export(async_runtime = "tokio")]
impl PlexNode {
    /// Создаёт и инициализирует ядро.
    ///
    /// # Параметры
    /// * `db_key` — ключ AES-256 для SQLCipher, полученный из Keystore/Keychain.
    ///   Строка обнуляется через `SecretString` сразу после передачи в storage.
    ///   Создаёт узел с дефолтной конфигурацией (community DERP, ephemeral key).
    ///
    /// Начиная с контракта v6 рекомендуется использовать `init_node_with_config`
    /// для хранения постоянного identity.
    #[uniffi::constructor]
    pub async fn init_node(data_dir: String, db_key: String) -> Result<Arc<PlexNode>, PlexError> {
        Self::init_node_with_config(
            data_dir,
            db_key,
            PlexNodeConfigRecord {
                relay_urls: vec![],
                disable_mdns: false,
                relay_only: false,
            },
        )
        .await
    }

    /// Создаёт узел с явной конфигурацией.
    ///
    /// Загружает или генерирует постоянный Ed25519 identity-ключ iroh-узла
    /// из зашифрованной БД. При каждом запуске узел будет иметь один и тот же
    /// NodeID, что позволяет пирам переподключаться без QR-обмена.
    #[uniffi::constructor]
    pub async fn init_node_with_config(
        data_dir: String,
        db_key: String,
        config: PlexNodeConfigRecord,
    ) -> Result<Arc<PlexNode>, PlexError> {
        // Инициализируем логирование (один раз; повторные вызовы игнорируются).
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "plex_core=debug".into()),
            )
            .try_init();

        // Один Tokio-рантайм на всё приложение.
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("plex-worker")
                .build()
                .context("Failed to build Tokio runtime")
                .map_err(|e| PlexError::Internal { msg: e.to_string() })?,
        );

        // Оборачиваем ключ в SecretString, чтобы zeroize обнулил RAM при дропе.
        let mut db_key = db_key;
        let secret_key = SecretString::new(std::mem::take(&mut db_key));
        db_key.zeroize();

        // ── Открываем/мигрируем БД ─────────────────────────────────────────
        let db_path = if data_dir.is_empty() {
            "plex.db".to_string()
        } else {
            let path = std::path::Path::new(&data_dir).join("plex.db");
            path.to_string_lossy().to_string()
        };

        let db = storage::Db::open(&db_path, &secret_key)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        // ── Загружаем либо генерируем постоянный identity-ключ ─────────────
        let node_secret_key_bytes: zeroize::Zeroizing<[u8; 32]> = match db.load_node_secret_key()? {
            Some(existing) => {
                info!("Loaded persistent node identity key from DB");
                zeroize::Zeroizing::new(existing)
            }
            None => {
                use rand::RngCore;
                let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(bytes.as_mut());
                db.save_node_secret_key(&bytes)?;
                info!("Generated and saved new persistent node identity key");
                bytes
            }
        };

        // ── Поднимаем iroh-узел ────────────────────────────────────────────
        let node_config = network::NodeConfig {
            secret_key_bytes: Some(*node_secret_key_bytes),
            relay_urls: config.relay_urls,
            disable_mdns: config.disable_mdns,
            relay_only: config.relay_only,
        };
        let iroh = rt
            .spawn(network::IrohNode::start_with_config(node_config))
            .await
            .context("iroh spawn failed")
            .map_err(|e| PlexError::Network { msg: e.to_string() })?
            .map_err(|e| PlexError::Network { msg: e.to_string() })?;

        let node = Arc::new(PlexNode {
            rt,
            iroh: Arc::new(iroh),
            db: Arc::new(db),
            background_tasks_started: AtomicBool::new(false),
            ratchet_sessions: Mutex::new(HashMap::new()),
            incoming_mesh_handoffs: Mutex::new(HashMap::new()),
            call_sessions: Mutex::new(HashMap::new()),
            call_media_sessions: Mutex::new(HashMap::new()),
            metrics: Arc::new(metrics::CoreMetrics::new()),
            ingest_rate_limits: Mutex::new(HashMap::new()),
            dht_cache_max_bytes: std::sync::atomic::AtomicU64::new(
                crate::ffi_dht::DHT_DEFAULT_CACHE_MAX_BYTES,
            ),
            dht_eviction_batch_size: std::sync::atomic::AtomicU32::new(
                crate::ffi_dht::DHT_DEFAULT_EVICTION_BATCH,
            ),
            incoming_event_callback: Arc::new(std::sync::Mutex::new(None)),
            connection_pool: connection_pool::ConnectionPool::new(),
            bridge_manager: Arc::new(bridge::BridgeManager::new()),
            message_retry_queue: Arc::new(message_router::MessageRetryQueue::new()),
            transfer_manager: Arc::new(transfer::TransferManager::new()),
        });

        // ── Загружаем сохраненные ratchet sessions из БД ────────────────────
        match node.db.load_all_ratchet_sessions() {
            Ok(snapshots) => {
                let mut sessions =
                    node.ratchet_sessions
                        .lock()
                        .map_err(|e| PlexError::Internal {
                            msg: format!("Ratchet sessions mutex poisoned after creation: {e}"),
                        })?;

                for snapshot in snapshots {
                    let peer_id = snapshot.peer_id.clone();
                    match crypto::RatchetSession::from_snapshot(snapshot) {
                        Ok(session) => {
                            sessions.insert(peer_id.clone(), session);
                            info!("Loaded ratchet session for peer: {}", peer_id);
                        }
                        Err(e) => {
                            warn!("Failed to load ratchet session for peer {}: {}", peer_id, e);
                            // Продолжаем, это не критично — можно пересоздать сессию
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to load ratchet sessions from DB: {}", e);
            }
        }

        node.ensure_background_network_tasks();

        info!(node_id = %node.iroh.node_id(), "PlexNode ready");

        Ok(node)
    }

    /// Возвращает NodeID текущего узла (base32-строка).
    pub fn node_id(&self) -> String {
        self.iroh.node_id().to_string()
    }

    /// Корректно завершает работу узла: закрывает QUIC endpoint, что приводит к
    /// завершению всех фоновых задач (цикл приёма завершается, т.к. endpoint.accept() возвращает None).
    pub async fn shutdown(&self) -> Result<(), PlexError> {
        self.iroh.close_endpoint().await;
        Ok(())
    }

    /// Возвращает версию FFI-контракта и возможности ядра для мобильного слоя.
    pub fn ffi_contract_info(&self) -> FfiContractInfoRecord {
        FfiContractInfoRecord {
            contract_version: FFI_CONTRACT_VERSION,
            error_variants: vec![
                "Storage".into(),
                "Network".into(),
                "Crypto".into(),
                "RateLimit".into(),
                "Timeout".into(),
                "Validation".into(),
                "NotFound".into(),
                "InvalidInput".into(),
                "Internal".into(),
            ],
            supports_typed_errors: true,
            supports_argon2id_kdf: true,
            supports_bounded_sync_reads: true,
            supports_chat_media_v1: true,
            supports_call_media_contract_v1: true,
            supports_call_ice_state_v1: true,
            supports_observability_v1: true,
            supports_sync_health_v1: true,
            supports_persistent_identity_v1: true,
            supports_alpn_isolation_v1: true,
            supports_configurable_relay_v1: true,
            supports_ingest_rate_limit_v1: true,
            supports_sync_auth_gate_v1: true,
            supports_graceful_shutdown_v1: true,
            supports_ratchet_aad_v1: true,
            supports_dht_cache_eviction_v1: true,
            supports_peer_blocklist_v1: true,
            supports_mdns_control_v1: true,
            supports_x3dh_v1: true,
            supports_receiver_mode_v1: true,
            supports_relay_only_v1: true,
            supports_username_contacts_v1: true,
            supports_username_discovery_v1: true,
            supports_persistent_pool_v1: true,
        }
    }

    /// Возвращает стабильный каталог ошибок для Android bridge/app слоя.
    ///
    /// Используется для типизированного маппинга Rust ошибок на UI-ключи и retry policy.
    pub fn ffi_error_catalog(&self) -> Vec<FfiErrorCatalogEntryRecord> {
        vec![
            FfiErrorCatalogEntryRecord {
                code: "PLEX_STORAGE".into(),
                variant: "Storage".into(),
                retryable: false,
                user_message_key: "error.storage".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_NETWORK".into(),
                variant: "Network".into(),
                retryable: true,
                user_message_key: "error.network".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_CRYPTO".into(),
                variant: "Crypto".into(),
                retryable: false,
                user_message_key: "error.crypto".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_RATE_LIMIT".into(),
                variant: "RateLimit".into(),
                retryable: true,
                user_message_key: "error.rate_limit".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_TIMEOUT".into(),
                variant: "Timeout".into(),
                retryable: true,
                user_message_key: "error.timeout".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_VALIDATION".into(),
                variant: "Validation".into(),
                retryable: false,
                user_message_key: "error.validation".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_NOT_FOUND".into(),
                variant: "NotFound".into(),
                retryable: false,
                user_message_key: "error.not_found".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_INVALID_INPUT".into(),
                variant: "InvalidInput".into(),
                retryable: false,
                user_message_key: "error.invalid_input".into(),
            },
            FfiErrorCatalogEntryRecord {
                code: "PLEX_INTERNAL".into(),
                variant: "Internal".into(),
                retryable: false,
                user_message_key: "error.internal".into(),
            },
        ]
    }

    /// Проверка готовности ядра для startup-handshake в Android bridge.
    pub fn startup_readiness_check(&self) -> StartupReadinessRecord {
        let node_id = self.iroh.node_id().to_string();
        let background_tasks_started = self.background_tasks_started.load(Ordering::SeqCst);

        let health_result = self.core_health_snapshot();
        let (health_snapshot_available, health_latest_error) = match health_result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        StartupReadinessRecord {
            contract_version: FFI_CONTRACT_VERSION,
            node_id,
            db_open_ok: true,
            runtime_ready: true,
            background_tasks_started,
            health_snapshot_available,
            health_latest_error,
        }
    }

    /// Получает менеджер bridge-узлов для управления мостами.
    /// Используется для добавления, активации и отслеживания bridge-узлов.
    pub fn bridge_manager(&self) -> Arc<ffi_bridge::PlexBridgeManager> {
        Arc::new(ffi_bridge::PlexBridgeManager {
            inner: Arc::clone(&self.bridge_manager),
        })
    }

    /// Получает количество сообщений в retry-очереди
    pub fn pending_retry_count(&self) -> Result<u32, PlexError> {
        self.message_retry_queue
            .pending_count()
            .map(|c| c as u32)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает все сообщения для повторной отправки
    pub fn get_pending_for_retry(
        &self,
    ) -> Result<Vec<ffi_message_router::OutboundMessageRecord>, PlexError> {
        self.message_retry_queue
            .get_pending_for_retry()
            .map(|envelopes| envelopes.iter().map(|e| e.into()).collect())
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отмечает сообщение как успешно доставленное
    pub fn mark_message_delivered(&self, message_id: String) -> Result<(), PlexError> {
        self.message_retry_queue
            .mark_delivered(&message_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отмечает сообщение как неудачное
    pub fn mark_message_failed(
        &self,
        message_id: String,
        reason: Option<String>,
    ) -> Result<(), PlexError> {
        self.message_retry_queue
            .mark_failed(&message_id, reason)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает статус доставки сообщения
    pub fn get_delivery_status(
        &self,
        message_id: String,
    ) -> Result<Option<ffi_message_router::DeliveryStatusRecord>, PlexError> {
        self.message_retry_queue
            .get_delivery_record(&message_id)
            .map(|opt| opt.map(|r| (&r).into()))
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Начинает новый трансфер файла
    pub fn start_file_transfer(
        &self,
        metadata: ffi_transfer::FileTransferRecord,
    ) -> Result<String, PlexError> {
        let tr_metadata = transfer::FileTransferMetadata {
            transfer_id: metadata.transfer_id.clone(),
            peer_id: metadata.peer_id.clone(),
            file_name: metadata.file_name.clone(),
            file_size: metadata.file_size,
            mime_type: metadata.mime_type.clone(),
            checksum: metadata.checksum.clone(),
            chunk_size: metadata.chunk_size,
            encryption_key: metadata.encryption_key.clone(),
            is_inbound: metadata.is_inbound,
            created_at: metadata.created_at,
        };
        self.transfer_manager
            .start_transfer(tr_metadata)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает прогресс трансфера
    pub fn get_transfer_progress(
        &self,
        transfer_id: String,
    ) -> Result<Option<ffi_transfer::TransferProgressRecord>, PlexError> {
        self.transfer_manager
            .get_progress(&transfer_id)
            .map(|opt| opt.map(|p| (&p).into()))
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает полный статус трансфера
    pub fn get_transfer_status(
        &self,
        transfer_id: String,
    ) -> Result<Option<ffi_transfer::FileTransferStatusRecord>, PlexError> {
        self.transfer_manager
            .get_envelope(&transfer_id)
            .map(|opt| opt.map(|e| (&e).into()))
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Приостанавливает трансфер
    pub fn pause_transfer(&self, transfer_id: String) -> Result<(), PlexError> {
        self.transfer_manager
            .pause_transfer(&transfer_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Возобновляет трансфер
    pub fn resume_transfer(&self, transfer_id: String) -> Result<(), PlexError> {
        self.transfer_manager
            .resume_transfer(&transfer_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отменяет трансфер
    pub fn cancel_transfer(&self, transfer_id: String) -> Result<(), PlexError> {
        self.transfer_manager
            .cancel_transfer(&transfer_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отмечает chunk как успешно передано
    pub fn mark_transfer_chunk_done(&self, transfer_id: String) -> Result<(), PlexError> {
        self.transfer_manager
            .mark_chunk_done(&transfer_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отмечает трансфер как завершённый
    pub fn mark_transfer_completed(&self, transfer_id: String) -> Result<(), PlexError> {
        self.transfer_manager
            .mark_completed(&transfer_id)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Отмечает трансфер как неудачный
    pub fn mark_transfer_failed(
        &self,
        transfer_id: String,
        reason: String,
    ) -> Result<(), PlexError> {
        self.transfer_manager
            .mark_failed(&transfer_id, reason)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Возвращает компактный health snapshot для UI/диагностики.
    pub fn core_health_snapshot(&self) -> Result<CoreHealthSnapshotRecord, PlexError> {
        let now_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let total_events = self.db.all_events()?.len() as u64;
        let latest_event_hash = self.db.latest_event_hash()?;
        let loaded_ratchet_sessions = self
            .ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?
            .len() as u64;
        let active_call_sessions = self
            .call_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call sessions mutex poisoned: {e}"),
            })?
            .len() as u64;
        let active_call_media_sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?
            .len() as u64;
        let active_mesh_handoff_sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?
            .len() as u64;

        Ok(CoreHealthSnapshotRecord {
            node_id: self.iroh.node_id().to_string(),
            now_unix_secs,
            latest_event_hash,
            total_events,
            loaded_ratchet_sessions,
            active_call_sessions,
            active_call_media_sessions,
            active_mesh_handoff_sessions,
            background_tasks_started: self.background_tasks_started.load(Ordering::SeqCst),
        })
    }

    /// Запускает фоновый mDNS-сканер пиров в локальной сети.
    /// Найденные NodeID выводятся в лог; в будущем — передаются в UI через callback.
    pub async fn start_local_discovery(&self) -> Result<(), PlexError> {
        self.ensure_background_network_tasks();
        Ok(())
    }

    /// Регистрирует callback для уведомлений о входящих sync-событиях.
    ///
    /// Вызывается из Kotlin/Swift после создания PlexNode.
    /// Повторный вызов заменяет предыдущий callback.
    pub fn register_incoming_event_callback(
        &self,
        callback: Box<dyn ffi_receiver::IncomingEventCallback>,
    ) {
        if let Ok(mut guard) = self.incoming_event_callback.lock() {
            *guard = Some(Arc::from(callback));
        }
    }

    /// Заглушка: добавить пир вручную (QR-рукопожатие).
    pub async fn add_peer_manual(&self, node_id: String, addr: String) -> Result<(), PlexError> {
        self.rt
            .spawn(network::add_peer_by_addr(
                Arc::clone(&self.iroh),
                Arc::clone(&self.db),
                Arc::clone(&self.metrics),
                node_id,
                addr,
                self.make_sync_callback(),
            ))
            .await
            .map_err(|e| PlexError::Network { msg: e.to_string() })?
            .map_err(|e| PlexError::Network { msg: e.to_string() })
    }

    /// Возвращает текущие contact data узла в JSON-формате для QR-кода.
    /// Помимо transport-полей (node_id, relay_url, direct_addresses) включает `username`
    /// из локального профиля, чтобы импортёр мог использовать его как display name
    /// без ручного ввода.
    pub async fn export_contact_json(&self) -> Result<String, PlexError> {
        let contact = self.iroh.local_contact().await?;
        let mut json = serde_json::to_value(&contact).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize contact JSON: {e}"),
        })?;
        let my_user_id = self.iroh.node_id().to_string();
        if let Ok(Some(profile)) = self.db.load_public_profile(&my_user_id) {
            if !profile.username.is_empty() {
                json["username"] = serde_json::Value::String(profile.username);
            }
        }
        serde_json::to_string(&json).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize contact JSON: {e}"),
        })
    }

    /// Возвращает текущие contact data как структурированную запись UniFFI.
    pub async fn export_contact(&self) -> Result<network::PeerContact, PlexError> {
        self.iroh.local_contact().await
    }

    /// Возвращает доступные transport backend'ы и их capabilities.
    pub fn transport_inventory(&self) -> Vec<TransportInfoRecord> {
        self.iroh
            .transport_inventory()
            .into_iter()
            .map(|entry| TransportInfoRecord {
                kind: entry.kind.as_str().to_string(),
                is_available: entry.is_available,
                core_connect_supported: entry.core_connect_supported,
                lan_discovery: entry.capabilities.lan_discovery,
                internet_required: entry.capabilities.internet_required,
                store_and_forward: entry.capabilities.store_and_forward,
                dpi_masquerade_ready: entry.capabilities.dpi_masquerade_ready,
                priority: entry.priority,
            })
            .collect()
    }

    /// Подключает пир по contact JSON из QR-кода.
    pub async fn add_peer_from_contact_json(&self, contact_json: String) -> Result<(), PlexError> {
        self.rt
            .spawn(network::add_peer_from_contact(
                Arc::clone(&self.iroh),
                Arc::clone(&self.db),
                Arc::clone(&self.metrics),
                contact_json,
                self.make_sync_callback(),
            ))
            .await
            .map_err(|e| PlexError::Network { msg: e.to_string() })?
            .map_err(|e| PlexError::Network { msg: e.to_string() })
    }

    /// Запоминает route hints пира из contact JSON отдельно от identity-контакта.
    pub fn remember_peer_route_hint_from_contact_json(
        &self,
        contact_json: String,
        source: String,
    ) -> Result<(), PlexError> {
        let contact: network::PeerContact =
            serde_json::from_str(&contact_json).map_err(|e| PlexError::Network {
                msg: format!("Invalid contact JSON: {e}"),
            })?;

        if contact.node_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "contact node_id must not be empty".into(),
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        self.db.upsert_peer_route_hint(&storage::PeerRouteHint {
            peer_id: contact.node_id,
            relay_url: contact.relay_url,
            direct_addresses: contact.direct_addresses,
            source,
            last_success_at: None,
            last_failure_at: None,
            updated_at: now,
        })
    }

    /// Подключает известного пира по сохранённым route hints.
    pub async fn connect_peer(&self, peer_id: String) -> Result<(), PlexError> {
        let hint = self
            .db
            .load_peer_route_hint(&peer_id)?
            .ok_or_else(|| PlexError::NotFound {
                msg: format!("No route hint found for peer {peer_id}"),
            })?;

        let contact_json = serde_json::to_string(&network::PeerContact {
            node_id: hint.peer_id.clone(),
            relay_url: hint.relay_url.clone(),
            direct_addresses: hint.direct_addresses.clone(),
        })
        .map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize peer route hint: {e}"),
        })?;

        let result = self
            .rt
            .spawn(network::add_peer_from_contact(
                Arc::clone(&self.iroh),
                Arc::clone(&self.db),
                Arc::clone(&self.metrics),
                contact_json,
                self.make_sync_callback(),
            ))
            .await
            .map_err(|e| PlexError::Network { msg: e.to_string() })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        match result {
            Ok(()) => {
                let _ = self.db.mark_peer_route_hint_success(&peer_id, now);
                Ok(())
            }
            Err(error) => {
                let _ = self.db.mark_peer_route_hint_failure(&peer_id, now);
                Err(PlexError::Network {
                    msg: error.to_string(),
                })
            }
        }
    }
}

impl PlexNode {
    /// Создаёт `SyncEventCallback`-замыкание, ссылающееся на текущий callback.
    fn make_sync_callback(&self) -> Option<network::SyncEventCallback> {
        let cb_ref = Arc::clone(&self.incoming_event_callback);
        Some(Arc::new(move |peer_id: String, count: u64| {
            if let Ok(guard) = cb_ref.lock() {
                if let Some(ref cb) = *guard {
                    cb.on_sync_received(peer_id, count);
                }
            }
        }))
    }

    fn ensure_background_network_tasks(&self) {
        if self
            .background_tasks_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let iroh_for_discovery = Arc::clone(&self.iroh);
        self.rt.spawn(async move {
            network::run_local_discovery_logger(iroh_for_discovery).await;
        });

        let iroh_for_accept = Arc::clone(&self.iroh);
        let db_for_accept = Arc::clone(&self.db);
        let metrics_for_accept = Arc::clone(&self.metrics);
        let on_sync_for_accept = self.make_sync_callback();
        self.rt.spawn(async move {
            network::run_incoming_connection_loop(
                iroh_for_accept,
                db_for_accept,
                metrics_for_accept,
                on_sync_for_accept,
            )
            .await;
        });

        let iroh_for_outbox = Arc::clone(&self.iroh);
        let db_for_outbox = Arc::clone(&self.db);
        let secret_for_outbox = self.iroh.secret_key().clone();
        let metrics_for_outbox = Arc::clone(&self.metrics);
        let on_sync_for_outbox = self.make_sync_callback();
        self.rt.spawn(async move {
            PlexNode::run_outbox_dispatch_loop(
                iroh_for_outbox,
                db_for_outbox,
                secret_for_outbox,
                metrics_for_outbox,
                on_sync_for_outbox,
            )
            .await;
        });

        // ── Пул постоянных соединений ──────────────────────────────────────
        let pool_endpoint = self.iroh.endpoint_clone();
        let pool_db = Arc::clone(&self.db);
        let pool = self.connection_pool.clone();
        let pool_metrics = Arc::clone(&self.metrics);
        self.rt.spawn(async move {
            connection_pool::run_connection_pool_loop(pool_endpoint, pool_db, pool, pool_metrics)
                .await;
        });

        if let Err(err) = self.announce_profile_if_present(24 * 60 * 60) {
            warn!(err = %err, "failed to re-announce profile on startup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Открывает временную БД для тестов.
    fn open_test_db() -> storage::Db {
        static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(1);
        let key = SecretString::new("test-key".to_string());
        let nonce = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("plex-test-{nonce}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        let _ = fs::remove_file(&db_path_str);
        storage::Db::open(&db_path_str, &key).expect("open_test_db")
    }

    #[test]
    fn test_username_contacts_roundtrip() {
        let db = open_test_db();

        // Добавляем контакт с username
        let contact = storage::Contact {
            user_id: "peer-alice".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            custom_avatar_blob: None,
            trust_level: "Verified".into(),
            added_at: 100,
        };

        db.upsert_contact(&contact).expect("upsert");

        // Загружаем обратно
        let loaded = db.list_contacts().expect("list");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].username, "alice");
        assert_eq!(loaded[0].display_name, "Alice");

        // Поиск по username
        let results = db
            .search_contacts_by_username("ali")
            .expect("search_contacts_by_username");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].user_id, "peer-alice");
    }

    #[test]
    fn test_dht_announce_and_lookup() {
        let db = open_test_db();

        // Имитируемая запись для DHT-анонса
        let payload = serde_json::json!({
            "node_id": "z123abc456def789",
            "username": "bob",
            "display_name": "Bob",
            "relay_url": serde_json::Value::Null,
            "announced_at": 1712345678i64,
        });

        let value = serde_json::to_vec(&payload).expect("encode");
        let dht_key = "acct:bob";
        let now_secs = 1712345678i64;

        // Публикуем в локальный DHT-кэш
        db.publish_dht_record(dht_key, &value, 86400, now_secs)
            .expect("publish_dht_record");

        // Ищем по нику
        let found = db
            .lookup_dht_record(dht_key, now_secs)
            .expect("lookup_dht_record");

        assert!(found.is_some());
        let found_bytes = found.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&found_bytes).expect("decode found value");
        assert_eq!(v["username"].as_str(), Some("bob"));
        assert_eq!(v["node_id"].as_str(), Some("z123abc456def789"));
    }

    #[test]
    fn test_dht_ttl_expiry() {
        let db = open_test_db();

        let payload = serde_json::json!({
            "node_id": "z789xyz",
            "username": "charlie",
            "display_name": "Charlie",
            "relay_url": serde_json::Value::Null,
            "announced_at": 100i64,
        });

        let value = serde_json::to_vec(&payload).expect("encode");
        let dht_key = "acct:charlie";

        // Публикуем с TTL 10 сек, с момента 100
        db.publish_dht_record(dht_key, &value, 10, 100)
            .expect("publish");

        // Ищем в момент 105 (до истечения) — должно быть найдено
        let found_in_time = db
            .lookup_dht_record(dht_key, 105)
            .expect("lookup before expiry");
        assert!(found_in_time.is_some());

        // Ищем в момент 115 (после истечения) — не должно быть найдено
        let found_after_expiry = db
            .lookup_dht_record(dht_key, 115)
            .expect("lookup after expiry");
        assert!(found_after_expiry.is_none());
    }

    #[test]
    fn test_connection_pool_basic() {
        let pool = connection_pool::ConnectionPool::new();

        // Снимок пустого пула
        let status = pool.status_snapshot();
        assert_eq!(status.len(), 0);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_multiple_contacts_and_usernames() {
        let db = open_test_db();

        // Добавляем несколько контактов с username'ами
        for i in 0..5 {
            let contact = storage::Contact {
                user_id: format!("peer-{i}"),
                username: format!("user{i}"),
                display_name: format!("User {i}"),
                custom_avatar_blob: None,
                trust_level: "Unverified".into(),
                added_at: 100 + i as i64,
            };
            db.upsert_contact(&contact).expect("upsert");
        }

        // Проверяем список
        let all = db.list_contacts().expect("list");
        assert_eq!(all.len(), 5);

        // Проверяем, что username'ы не пустые
        for contact in &all {
            assert!(!contact.username.is_empty());
        }

        // Поиск по partial match
        let found = db.search_contacts_by_username("user").expect("search");
        assert_eq!(found.len(), 5);

        let found_specific = db.search_contacts_by_username("user2").expect("search");
        assert_eq!(found_specific.len(), 1);
        assert_eq!(found_specific[0].user_id, "peer-2");
    }

    #[test]
    fn test_username_search_case_insensitive() {
        let db = open_test_db();

        let contact = storage::Contact {
            user_id: "peer-test".into(),
            username: "TestUser".into(),
            display_name: "Test User".into(),
            custom_avatar_blob: None,
            trust_level: "Unverified".into(),
            added_at: 100,
        };
        db.upsert_contact(&contact).expect("upsert");

        // Поиск в разных регистрах
        let found_lower = db.search_contacts_by_username("testuser").expect("search");
        assert_eq!(found_lower.len(), 1);

        let found_upper = db.search_contacts_by_username("TESTUSER").expect("search");
        assert_eq!(found_upper.len(), 1);

        let found_mixed = db.search_contacts_by_username("TeSt").expect("search");
        assert_eq!(found_mixed.len(), 1);
    }

    #[test]
    fn test_file_transfer_encryption_key_persistence() {
        let db_key = "test-key-123".to_string();

        // Запускаем инициализацию в отдельном потоке, чтобы основной поток теста
        // не имел контекста Tokio. Это позволяет избежать паники при удалении
        // внутреннего рантайма PlexNode (который создается в init_node).
        let node = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async { PlexNode::init_node(".".to_string(), db_key).await.unwrap() })
        })
        .join()
        .unwrap();

        let transfer_id = "tr-123".to_string();
        let key = "secret-key-abc".to_string();

        let record = ffi_transfer::FileTransferRecord {
            transfer_id: transfer_id.clone(),
            peer_id: "peer-1".to_string(),
            file_name: "test.dat".to_string(),
            file_size: 1024,
            mime_type: "application/octet-stream".to_string(),
            checksum: "hash".to_string(),
            chunk_size: 256,
            encryption_key: key.clone(),
            is_inbound: false,
            created_at: 1000,
        };

        node.start_file_transfer(record)
            .expect("start_file_transfer");

        let status = node
            .get_transfer_status(transfer_id)
            .expect("get_transfer_status")
            .unwrap();
        assert_eq!(status.metadata.encryption_key, key);

        let node_clone = node.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                node_clone.shutdown().await.unwrap();
            })
        })
        .join()
        .unwrap();

        drop(node);
    }
}
