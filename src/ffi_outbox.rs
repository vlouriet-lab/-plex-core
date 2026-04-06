//! `ffi_outbox.rs` — FFI-модуль управления исходящей очередью и доставкой.
//!
//! Содержит:
//! * Типы: [`OutboxMessageRecord`], [`DeliveryMaintenanceReport`].
//! * Методы PlexNode для управления outbox-очередью и семантикой доставки.
//! * Внутренний фоновый loop диспетчеризации исходящих сообщений.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::time::{sleep, Duration};
use tracing::warn;

use crate::{storage, PlexError, PlexNode};

// ── Константы ─────────────────────────────────────────────────────────────────

const OUTBOX_BACKOFF_BASE_SECS: u64 = 2;
const OUTBOX_BACKOFF_MAX_SECS: u64 = 10 * 60;
const OUTBOX_MAX_ATTEMPTS: u64 = 8;
pub(crate) const OUTBOX_WORKER_BATCH_LIMIT: usize = 64;
pub(crate) const OUTBOX_WORKER_TICK_SECS: u64 = 2;
const DELIVERY_PRUNE_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

// ── Типы ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Record)]
pub struct OutboxMessageRecord {
    pub message_id: String,
    pub peer_id: String,
    pub ciphertext: Vec<u8>,
    pub status: String,
    pub attempt_count: u64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub next_attempt_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeliveryMaintenanceReport {
    pub pruned_dedup: u64,
    pub pruned_receipts: u64,
}

// ── FFI-методы PlexNode ───────────────────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    /// Шифрует сообщение и кладет его в устойчивую outbox-очередь.
    pub fn queue_encrypted_message_for_peer(
        &self,
        peer_id: String,
        plaintext: Vec<u8>,
    ) -> Result<String, PlexError> {
        let ciphertext = self.encrypt_for_peer(peer_id.clone(), plaintext)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        self.db.enqueue_outbox_message(&peer_id, &ciphertext, now)
    }

    /// Возвращает следующую пачку outbox сообщений к отправке.
    pub fn outbox_next_batch(&self, limit: u64) -> Result<Vec<OutboxMessageRecord>, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let messages = self.db.pending_outbox_messages(now, limit as usize)?;
        Ok(messages.into_iter().map(to_outbox_record).collect())
    }

    /// Помечает outbox сообщение как отправленное.
    pub fn outbox_mark_sent(&self, message_id: String) -> Result<bool, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let updated = self.db.mark_outbox_sent(&message_id, now)?;
        if updated {
            let _ = self
                .db
                .mark_chat_message_sent_by_transport_id(&message_id, now);
            self.metrics.inc(&self.metrics.outbox_sent_total);
        }
        Ok(updated)
    }

    /// Помечает outbox сообщение как failed и ставит повтор через retry_after_secs.
    pub fn outbox_mark_failed(
        &self,
        message_id: String,
        error_text: String,
        retry_after_secs: u64,
    ) -> Result<bool, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        let retry_at = now.saturating_add(retry_after_secs as i64);

        self.db
            .mark_outbox_failed(&message_id, &error_text, retry_at, now)
    }

    /// Помечает outbox сообщение как failed и рассчитывает retry по exponential backoff.
    /// Возвращает рассчитанную задержку в секундах.
    pub fn outbox_mark_failed_backoff(
        &self,
        message_id: String,
        error_text: String,
    ) -> Result<Option<u64>, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        self.db.mark_outbox_failed_with_backoff_jitter(
            &message_id,
            &error_text,
            OUTBOX_BACKOFF_BASE_SECS,
            OUTBOX_BACKOFF_MAX_SECS,
            OUTBOX_MAX_ATTEMPTS,
            now,
        )
    }

    /// Подтверждает доставку outbox сообщения (delivery ack).
    pub fn outbox_ack_delivered(
        &self,
        peer_id: String,
        message_id: String,
    ) -> Result<bool, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let updated = self.db.ack_outbox_delivery(&peer_id, &message_id, now)?;
        if updated {
            let _ = self
                .db
                .mark_chat_message_delivered_by_transport_id(&message_id, now);
            self.metrics.inc(&self.metrics.outbox_delivered_total);
        }
        Ok(updated)
    }

    /// Идемпотентно регистрирует входящее сообщение. true = первое получение, false = дубликат.
    pub fn register_inbound_message_once(
        &self,
        peer_id: String,
        message_id: String,
    ) -> Result<bool, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        self.db
            .register_inbound_message_once(&peer_id, &message_id, now)
    }

    /// Очистка старых dedup/receipt записей по retention policy.
    pub fn delivery_maintenance_tick(&self) -> Result<DeliveryMaintenanceReport, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        let older_than = now.saturating_sub(DELIVERY_PRUNE_RETENTION_SECS);

        let pruned_dedup = self.db.prune_inbound_dedup_older_than(older_than)?;
        let pruned_receipts = self.db.prune_delivery_receipts_older_than(older_than)?;

        Ok(DeliveryMaintenanceReport {
            pruned_dedup,
            pruned_receipts,
        })
    }
}

// ── Фоновый dispatch loop ────────────────────────────────────────────────────

impl PlexNode {
    pub(crate) async fn run_outbox_dispatch_loop(
        node: Arc<crate::network::IrohNode>,
        db: Arc<storage::Db>,
        local_secret: iroh::SecretKey,
        metrics: Arc<crate::metrics::CoreMetrics>,
        on_sync: Option<crate::network::SyncEventCallback>,
    ) {
        loop {
            let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs() as i64,
                Err(error) => {
                    warn!("Outbox worker clock error: {}", error);
                    sleep(Duration::from_secs(OUTBOX_WORKER_TICK_SECS)).await;
                    continue;
                }
            };

            let pending = match db.pending_outbox_messages(now, OUTBOX_WORKER_BATCH_LIMIT) {
                Ok(messages) => messages,
                Err(error) => {
                    warn!("Outbox worker cannot load pending messages: {}", error);
                    sleep(Duration::from_secs(OUTBOX_WORKER_TICK_SECS)).await;
                    continue;
                }
            };

            for message in pending {
                match db.append_local_event(&local_secret, &message.ciphertext) {
                    Ok(_) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|duration| duration.as_secs() as i64)
                            .unwrap_or(0);
                        if let Err(error) = db.mark_outbox_sent(&message.message_id, now) {
                            warn!("Outbox worker failed to mark sent: {}", error);
                        } else {
                            let _ =
                                db.mark_chat_message_sent_by_transport_id(&message.message_id, now);
                            metrics.inc(&metrics.outbox_sent_total);

                            // Push sync! Уведомляем целевого пользователя о новом сообщении
                            let peer_id_str = message.peer_id.clone();
                            let node_clone = node.clone();
                            let db_clone = db.clone();
                            let metrics_clone = metrics.clone();
                            let on_sync_clone = on_sync.clone();

                            tokio::spawn(async move {
                                let _ = crate::network::trigger_sync_with_peer(
                                    node_clone,
                                    db_clone,
                                    metrics_clone,
                                    peer_id_str,
                                    on_sync_clone,
                                )
                                .await;
                            });
                        }
                    }
                    Err(error) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|duration| duration.as_secs() as i64)
                            .unwrap_or(0);
                        let _ = db.mark_outbox_failed_with_backoff_jitter(
                            &message.message_id,
                            &error.to_string(),
                            OUTBOX_BACKOFF_BASE_SECS,
                            OUTBOX_BACKOFF_MAX_SECS,
                            OUTBOX_MAX_ATTEMPTS,
                            now,
                        );
                        metrics.inc(&metrics.outbox_failures_total);
                    }
                }
            }

            sleep(Duration::from_secs(OUTBOX_WORKER_TICK_SECS)).await;
        }
    }
}

// ── Конвертеры ────────────────────────────────────────────────────────────────

fn to_outbox_record(message: storage::OutboxMessage) -> OutboxMessageRecord {
    OutboxMessageRecord {
        message_id: message.message_id,
        peer_id: message.peer_id,
        ciphertext: message.ciphertext,
        status: message.status,
        attempt_count: message.attempt_count,
        last_error: message.last_error,
        created_at: message.created_at,
        updated_at: message.updated_at,
        next_attempt_at: message.next_attempt_at,
    }
}
