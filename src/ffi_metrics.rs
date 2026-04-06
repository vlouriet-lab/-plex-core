//! `ffi_metrics.rs` — FFI-метод чтения снапшота метрик ядра.
//!
//! Android-слой вызывает [`PlexNode::core_metrics_snapshot`] периодически
//! (например, раз в 30 с) и вычисляет дельту для отображения диагностики
//! или отправки телеметрии.

use crate::{metrics, PlexError, PlexNode};

/// Снапшот всех монотонных счётчиков ядра.
/// Все значения накапливаются с момента запуска процесса и никогда не сбрасываются.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CoreMetricsRecord {
    // Runtime gauges
    pub pool_active_connections: u64,
    // Chat
    pub chat_messages_queued: u64,
    pub chat_messages_received: u64,
    pub chat_messages_duplicate: u64,
    pub chat_read_receipts_sent: u64,
    pub chat_read_receipts_received: u64,
    // Outbox
    pub outbox_sent_total: u64,
    pub outbox_delivered_total: u64,
    pub outbox_failures_total: u64,
    // Sync
    pub sync_events_inserted_total: u64,
    pub sync_rounds_completed: u64,
    pub sync_reorgs_detected: u64,
    // Calls
    pub calls_initiated_total: u64,
    pub calls_received_total: u64,
    pub calls_ended_total: u64,
    pub calls_failed_total: u64,
    // Crypto
    pub ratchet_encrypt_total: u64,
    pub ratchet_decrypt_total: u64,
    pub ratchet_decrypt_errors: u64,
}

#[uniffi::export]
impl PlexNode {
    /// Возвращает снапшот всех накопленных метрик ядра.
    ///
    /// Вызывайте периодически и вычисляйте разницу между двумя снапшотами,
    /// чтобы получить rate-значения (сообщений/с, событий/с и т.д.).
    pub fn core_metrics_snapshot(&self) -> Result<CoreMetricsRecord, PlexError> {
        let snap = self.metrics.snapshot();
        Ok(from_snapshot(&snap))
    }
}

pub(crate) fn from_snapshot(snap: &metrics::CoreMetricsSnapshot) -> CoreMetricsRecord {
    CoreMetricsRecord {
        pool_active_connections: snap.pool_active_connections,
        chat_messages_queued: snap.chat_messages_queued,
        chat_messages_received: snap.chat_messages_received,
        chat_messages_duplicate: snap.chat_messages_duplicate,
        chat_read_receipts_sent: snap.chat_read_receipts_sent,
        chat_read_receipts_received: snap.chat_read_receipts_received,
        outbox_sent_total: snap.outbox_sent_total,
        outbox_delivered_total: snap.outbox_delivered_total,
        outbox_failures_total: snap.outbox_failures_total,
        sync_events_inserted_total: snap.sync_events_inserted_total,
        sync_rounds_completed: snap.sync_rounds_completed,
        sync_reorgs_detected: snap.sync_reorgs_detected,
        calls_initiated_total: snap.calls_initiated_total,
        calls_received_total: snap.calls_received_total,
        calls_ended_total: snap.calls_ended_total,
        calls_failed_total: snap.calls_failed_total,
        ratchet_encrypt_total: snap.ratchet_encrypt_total,
        ratchet_decrypt_total: snap.ratchet_decrypt_total,
        ratchet_decrypt_errors: snap.ratchet_decrypt_errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_metrics_record_preserves_pool_active_connections() {
        let snap = metrics::CoreMetricsSnapshot {
            pool_active_connections: 7,
            chat_messages_queued: 1,
            chat_messages_received: 2,
            chat_messages_duplicate: 3,
            chat_read_receipts_sent: 4,
            chat_read_receipts_received: 5,
            outbox_sent_total: 6,
            outbox_delivered_total: 7,
            outbox_failures_total: 8,
            sync_events_inserted_total: 9,
            sync_rounds_completed: 10,
            sync_reorgs_detected: 11,
            calls_initiated_total: 12,
            calls_received_total: 13,
            calls_ended_total: 14,
            calls_failed_total: 15,
            ratchet_encrypt_total: 16,
            ratchet_decrypt_total: 17,
            ratchet_decrypt_errors: 18,
        };

        let record = from_snapshot(&snap);
        assert_eq!(record.pool_active_connections, 7);
        assert_eq!(record.sync_rounds_completed, 10);
        assert_eq!(record.ratchet_decrypt_errors, 18);
    }
}
