//! `ffi_receiver.rs` — Лёгкий фоновый приёмник входящих сообщений.
//!
//! ## Зачем нужен
//!
//! `PlexNode` — полноценное ядро с декриптованием, outbox, UI-методами.
//! `PlexReceiverNode` — минимальный вариант для **Android Foreground Service**:
//!
//! * Открывает ту же SQLCipher БД (WAL — поддерживает concurrent write из двух процессов).
//! * Поднимает iroh QUIC endpoint с тем же постоянным ключом (тот же NodeID).
//! * Запускает только `run_incoming_connection_loop` (без outbox, без mDNS).
//! * При получении новых событий через sync → вызывает `IncomingEventCallback`.
//!
//! ## Жизненный цикл Android
//!
//! ```text
//! App на заднем плане / смерть процесса:
//!   PlexReceiverService (foreground service, тихое persistent notification)
//!   └── PlexReceiverNode.init_receiver_node(db_key, relay_urls)
//!       └── on_sync_received(from, n) → NotificationManager.notify()
//!
//! Пользователь открывает приложение:
//!   1. receiverNode.shutdown()          // закрываем endpoint
//!   2. PlexNode.init_node_with_config() // открываем полный узел
//! ```
//!
//! ## Коллбэк
//!
//! `IncomingEventCallback.on_sync_received(from_peer_id, new_events_count)` —
//! это *сигнал*, а не расшифрованный контент.  
//! Показывай «Новое сообщение» без вскрытия plaintext.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use secrecy::SecretString;
use tracing::info;
use zeroize::Zeroize;

use crate::{network, storage, PlexError};

// ── Callback interface ────────────────────────────────────────────────────────

/// Callback для уведомления о входящих событиях.
///
/// Реализуется на стороне Kotlin/Swift; UniFFI генерирует JNI/Swift-прокси.
/// Вызывается из Tokio-треда — реализация должна быть thread-safe и не блокировать.
#[uniffi::export(callback_interface)]
pub trait IncomingEventCallback: Send + Sync {
    /// Вызывается после успешного incoming sync с новыми событиями.
    ///
    /// * `from_peer_id` — NodeID пира, от которого пришли события.
    /// * `new_events_count` — количество новых событий (≥1).
    ///
    /// **Не раскрывает содержимое**: только сигнал «есть что читать».
    fn on_sync_received(&self, from_peer_id: String, new_events_count: u64);
}

// ── PlexReceiverNode ──────────────────────────────────────────────────────────

/// Лёгкий фоновый приёмник.
///
/// Разделяет ту же SQLCipher БД с `PlexNode` (WAL-конкурентность),
/// но держит отдельный Tokio runtime и iroh endpoint.
///
/// **Важно:** перед созданием `PlexNode` вызови `shutdown()`,
/// так как два iroh endpoint с одним NodeID не могут работать одновременно
/// в одном процессе.
#[derive(uniffi::Object)]
pub struct PlexReceiverNode {
    rt: Arc<tokio::runtime::Runtime>,
    iroh: Arc<network::IrohNode>,
    /// Зарегистрированный callback; может быть обновлён после создания узла.
    callback: Mutex<Option<Arc<dyn IncomingEventCallback>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl PlexReceiverNode {
    /// Создаёт лёгкий фоновый приёмник.
    ///
    /// * `db_key`     — ключ SQLCipher (тот же, что у `PlexNode`).
    /// * `relay_urls` — список DERP/relay URL (пустой = community-серверы Iroh).
    ///   mDNS **не запускается** в receiver-режиме.
    #[uniffi::constructor]
    pub async fn init_receiver_node(
        data_dir: String,
        db_key: String,
        relay_urls: Vec<String>,
        relay_only: bool,
    ) -> Result<Arc<PlexReceiverNode>, PlexError> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "plex_core=info".into()),
            )
            .try_init();

        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("plex-receiver")
                .build()
                .context("Failed to build Tokio runtime for receiver")
                .map_err(|e| PlexError::Internal { msg: e.to_string() })?,
        );

        let mut db_key = db_key;
        let secret_key = SecretString::new(std::mem::take(&mut db_key));
        db_key.zeroize();

        // Открываем БД только чтобы загрузить постоянный identity-ключ.
        let db_path = if data_dir.is_empty() {
            "plex.db".to_string()
        } else {
            let path = std::path::Path::new(&data_dir).join("plex.db");
            path.to_string_lossy().to_string()
        };

        let db = storage::Db::open(&db_path, &secret_key)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let node_secret_key_bytes: zeroize::Zeroizing<[u8; 32]> = match db.load_node_secret_key()? {
            Some(existing) => {
                info!("[receiver] Loaded persistent node identity key");
                zeroize::Zeroizing::new(existing)
            }
            None => {
                // Без сохранённого ключа receiver не имеет смысла — узел ещё не инициализирован.
                return Err(PlexError::Storage {
                    msg: "No persistent node identity key found; run init_node_with_config first"
                        .into(),
                });
            }
        };

        let node_config = network::NodeConfig {
            secret_key_bytes: Some(*node_secret_key_bytes),
            relay_urls,
            disable_mdns: true, // receiver никогда не использует mDNS
            relay_only,
        };

        let iroh = rt
            .spawn(network::IrohNode::start_with_config(node_config))
            .await
            .context("iroh spawn failed for receiver")
            .map_err(|e| PlexError::Network { msg: e.to_string() })?
            .map_err(|e| PlexError::Network { msg: e.to_string() })?;

        let node = Arc::new(PlexReceiverNode {
            rt,
            iroh: Arc::new(iroh),
            callback: Mutex::new(None),
        });

        // Стартуем loop приёма входящих соединений.
        node.start_incoming_loop(db);

        info!(node_id = %node.iroh.node_id(), "[receiver] PlexReceiverNode ready");

        Ok(node)
    }

    /// Регистрирует callback для уведомлений. Можно вызывать в любой момент.
    ///
    /// Последующий вызов заменяет предыдущий callback.
    pub fn register_callback(&self, callback: Box<dyn IncomingEventCallback>) {
        if let Ok(mut guard) = self.callback.lock() {
            *guard = Some(Arc::from(callback));
        }
    }

    /// NodeID текущего узла (совпадает с NodeID полного PlexNode).
    pub fn node_id(&self) -> String {
        self.iroh.node_id().to_string()
    }

    /// Корректно завершает работу: закрывает QUIC endpoint.
    ///
    /// Обязательно вызвать перед `PlexNode.init_node_with_config()`.
    pub async fn shutdown(&self) -> Result<(), PlexError> {
        self.iroh.close_endpoint().await;
        info!("[receiver] PlexReceiverNode shut down");
        Ok(())
    }
}

impl PlexReceiverNode {
    /// Запускает `run_incoming_connection_loop` с callback-оберткой.
    fn start_incoming_loop(self: &Arc<Self>, db: storage::Db) {
        let iroh = Arc::clone(&self.iroh);
        let self_weak = Arc::downgrade(self);
        let on_sync: network::SyncEventCallback =
            std::sync::Arc::new(move |peer_id: String, count: u64| {
                if let Some(node) = self_weak.upgrade() {
                    if let Ok(guard) = node.callback.lock() {
                        if let Some(ref cb) = *guard {
                            cb.on_sync_received(peer_id, count);
                        }
                    }
                }
            });

        let db = Arc::new(db);
        let metrics = Arc::new(crate::metrics::CoreMetrics::new());

        self.rt.spawn(async move {
            network::run_incoming_connection_loop(iroh, db, metrics, Some(on_sync)).await;
        });
    }
}
