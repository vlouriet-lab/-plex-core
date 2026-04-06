//! `ffi_sync.rs` — FFI-методы статуса синхронизации event log.
//!
//! Позволяет Android-слою запросить текущее состояние синхронизации:
//! - сколько событий в локальном log
//! - число orphan-событий (ссылаются на неизвестных предков — признак неполного backfill)
//! - глубина очереди outbox
//! - hash последнего события (для сравнения с пиром)

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{PlexError, PlexNode};

/// Снапшот состояния sync-подсистемы, возвращаемый Android-слою.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncHealthRecord {
    /// Число событий в локальном event log.
    pub total_events: u64,
    /// Number of events that reference unknown ancestors (incomplete backfill).
    pub orphan_events: u64,
    /// Number of outbox messages pending delivery.
    pub pending_outbox: u64,
    /// SHA-256 hash последнего известного события (None = лог пуст).
    pub latest_event_hash: Option<String>,
    /// Число frontier-хэшей (кончиков активных ветвей event log).
    pub frontier_size: u64,
    /// Unix-секунды на момент создания снапшота.
    pub snapshot_at: i64,
}

#[uniffi::export]
impl PlexNode {
    /// Возвращает текущее состояние синхронизации.
    ///
    /// Безопасно вызывать из Android в любой момент для обновления индикатора
    /// "синхронизировано / идёт синхронизация".
    pub fn sync_health_snapshot(&self) -> Result<SyncHealthRecord, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let total_events = self.db.all_events().map(|v| v.len() as u64).unwrap_or(0);
        let orphan_events = self
            .db
            .orphan_prev_hashes(1024)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let pending_outbox = self
            .db
            .pending_outbox_messages(now, 4096)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let latest_event_hash = self.db.latest_event_hash().unwrap_or(None);
        let frontier_size = self
            .db
            .frontier_hashes()
            .map(|v| v.len() as u64)
            .unwrap_or(0);

        Ok(SyncHealthRecord {
            total_events,
            orphan_events,
            pending_outbox,
            latest_event_hash,
            frontier_size,
            snapshot_at: now,
        })
    }

    /// Принудительно начинает исходящую push-синхронизацию с указанным пиром (по NodeID).
    /// Полезно для мгновенного обновления сообщений или UI-свайпов.
    pub async fn force_sync_with_peer(&self, peer_id: String) -> Result<(), PlexError> {
        let cb = self.make_sync_callback();

        // Запускаем через метод network.rs
        crate::network::trigger_sync_with_peer(
            self.iroh.clone(),
            self.db.clone(),
            self.metrics.clone(),
            peer_id,
            cb,
        )
        .await
    }
}
