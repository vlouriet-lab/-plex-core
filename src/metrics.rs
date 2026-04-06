//! `metrics.rs` — атомарные счётчики и gauge-метрики производительности ядра.
//!
//! Основные поля используют `AtomicU64` и накапливаются за lifetime процесса.
//! Отдельные runtime-gauge поля (например, активные соединения пула) отражают
//! текущее состояние на момент снятия снапшота.
//! Значения доступны через [`CoreMetrics::snapshot`] → [`CoreMetricsSnapshot`].

use std::sync::atomic::{AtomicU64, Ordering};

/// Глобальные счётчики ядра, хранятся в `PlexNode.metrics`.
pub struct CoreMetrics {
    // ── Runtime gauges ───────────────────────────────────────────────────────
    /// Текущее число живых соединений в persistent connection pool.
    pub pool_active_connections: AtomicU64,

    // ── Chat / Сообщения ──────────────────────────────────────────────────────
    /// Исходящих сообщений передано в outbox (send_*_message).
    pub chat_messages_queued: AtomicU64,
    /// Входящих сообщений успешно принято (ingest_incoming_chat_ciphertext).
    pub chat_messages_received: AtomicU64,
    /// Входящих дубликатов отвергнуто (dedup-фильтр).
    pub chat_messages_duplicate: AtomicU64,
    /// Read receipt-ов отправлено локально.
    pub chat_read_receipts_sent: AtomicU64,
    /// Read receipt-ов получено от пиров.
    pub chat_read_receipts_received: AtomicU64,

    // ── Outbox / Доставка ─────────────────────────────────────────────────────
    /// Сообщений успешно доставлено (mark_outbox_sent).
    pub outbox_sent_total: AtomicU64,
    /// Сообщений получило delivery ack (outbox_ack_delivered).
    pub outbox_delivered_total: AtomicU64,
    /// Отказов отправки (mark_outbox_failed*).
    pub outbox_failures_total: AtomicU64,

    // ── Sync / Синхронизация ──────────────────────────────────────────────────
    /// Событий вставлено из sync-bundle (apply_sync_bundle).
    pub sync_events_inserted_total: AtomicU64,
    /// Sync-раундов успешно завершено.
    pub sync_rounds_completed: AtomicU64,
    /// Раундов, в которых был обнаружен реорг.
    pub sync_reorgs_detected: AtomicU64,

    // ── Calls / Звонки ────────────────────────────────────────────────────────
    /// Звонков инициировано (send_call_signal Ring).
    pub calls_initiated_total: AtomicU64,
    /// Звонков принято (apply_incoming_call_signal Ring).
    pub calls_received_total: AtomicU64,
    /// Звонков завершено нормально (End).
    pub calls_ended_total: AtomicU64,
    /// Звонков со сбоем (Failed).
    pub calls_failed_total: AtomicU64,

    // ── Crypto ────────────────────────────────────────────────────────────────
    /// Успешных операций шифрования ratchet.
    pub ratchet_encrypt_total: AtomicU64,
    /// Успешных операций расшифрования ratchet.
    pub ratchet_decrypt_total: AtomicU64,
    /// Ошибок расшифрования (неверный ключ, повреждён пакет).
    pub ratchet_decrypt_errors: AtomicU64,
}

impl CoreMetrics {
    pub fn new() -> Self {
        Self {
            pool_active_connections: AtomicU64::new(0),
            chat_messages_queued: AtomicU64::new(0),
            chat_messages_received: AtomicU64::new(0),
            chat_messages_duplicate: AtomicU64::new(0),
            chat_read_receipts_sent: AtomicU64::new(0),
            chat_read_receipts_received: AtomicU64::new(0),
            outbox_sent_total: AtomicU64::new(0),
            outbox_delivered_total: AtomicU64::new(0),
            outbox_failures_total: AtomicU64::new(0),
            sync_events_inserted_total: AtomicU64::new(0),
            sync_rounds_completed: AtomicU64::new(0),
            sync_reorgs_detected: AtomicU64::new(0),
            calls_initiated_total: AtomicU64::new(0),
            calls_received_total: AtomicU64::new(0),
            calls_ended_total: AtomicU64::new(0),
            calls_failed_total: AtomicU64::new(0),
            ratchet_encrypt_total: AtomicU64::new(0),
            ratchet_decrypt_total: AtomicU64::new(0),
            ratchet_decrypt_errors: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> CoreMetricsSnapshot {
        CoreMetricsSnapshot {
            pool_active_connections: self.pool_active_connections.load(Ordering::Relaxed),
            chat_messages_queued: self.chat_messages_queued.load(Ordering::Relaxed),
            chat_messages_received: self.chat_messages_received.load(Ordering::Relaxed),
            chat_messages_duplicate: self.chat_messages_duplicate.load(Ordering::Relaxed),
            chat_read_receipts_sent: self.chat_read_receipts_sent.load(Ordering::Relaxed),
            chat_read_receipts_received: self.chat_read_receipts_received.load(Ordering::Relaxed),
            outbox_sent_total: self.outbox_sent_total.load(Ordering::Relaxed),
            outbox_delivered_total: self.outbox_delivered_total.load(Ordering::Relaxed),
            outbox_failures_total: self.outbox_failures_total.load(Ordering::Relaxed),
            sync_events_inserted_total: self.sync_events_inserted_total.load(Ordering::Relaxed),
            sync_rounds_completed: self.sync_rounds_completed.load(Ordering::Relaxed),
            sync_reorgs_detected: self.sync_reorgs_detected.load(Ordering::Relaxed),
            calls_initiated_total: self.calls_initiated_total.load(Ordering::Relaxed),
            calls_received_total: self.calls_received_total.load(Ordering::Relaxed),
            calls_ended_total: self.calls_ended_total.load(Ordering::Relaxed),
            calls_failed_total: self.calls_failed_total.load(Ordering::Relaxed),
            ratchet_encrypt_total: self.ratchet_encrypt_total.load(Ordering::Relaxed),
            ratchet_decrypt_total: self.ratchet_decrypt_total.load(Ordering::Relaxed),
            ratchet_decrypt_errors: self.ratchet_decrypt_errors.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot значений метрик (все поля — u64, monotonically increasing).
/// Android-слой вычисляет дельту между двумя снапшотами для rate-метрик.
#[derive(Debug, Clone)]
pub struct CoreMetricsSnapshot {
    pub pool_active_connections: u64,
    pub chat_messages_queued: u64,
    pub chat_messages_received: u64,
    pub chat_messages_duplicate: u64,
    pub chat_read_receipts_sent: u64,
    pub chat_read_receipts_received: u64,
    pub outbox_sent_total: u64,
    pub outbox_delivered_total: u64,
    pub outbox_failures_total: u64,
    pub sync_events_inserted_total: u64,
    pub sync_rounds_completed: u64,
    pub sync_reorgs_detected: u64,
    pub calls_initiated_total: u64,
    pub calls_received_total: u64,
    pub calls_ended_total: u64,
    pub calls_failed_total: u64,
    pub ratchet_encrypt_total: u64,
    pub ratchet_decrypt_total: u64,
    pub ratchet_decrypt_errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn snapshot_includes_pool_active_connections_gauge() {
        let metrics = CoreMetrics::new();
        metrics.pool_active_connections.store(3, Ordering::Relaxed);
        metrics.inc(&metrics.chat_messages_queued);

        let snap = metrics.snapshot();
        assert_eq!(snap.pool_active_connections, 3);
        assert_eq!(snap.chat_messages_queued, 1);
    }
}
