//! `storage/call_signals.rs` — персистентный журнал call signaling сообщений.
//!
//! Хранит все отправленные и принятые call-сигналы (Ring / Offer / Answer / IceCandidate / End…).
//! Цель: при реконнекте Android-слой может считать историю сигналов и воспроизвести
//! ICE-обмен без нового Ring. Таблица очищается при завершении звонка
//! через [`Db::prune_call_signals_for_call`].

use rusqlite::params;

use super::*;

/// Направление сигнала относительно локального узла.
const DIR_OUTGOING: &str = "outgoing";
const DIR_INCOMING: &str = "incoming";

/// Сохранённый call-сигнал.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedCallSignal {
    pub signal_id: String,
    pub call_id: String,
    pub peer_id: String,
    pub direction: String,
    pub kind: String,
    pub payload: String,
    pub created_at: i64,
}

impl Db {
    /// Сохраняет исходящий call-сигнал в журнал.
    pub fn save_outgoing_call_signal(
        &self,
        call_id: &str,
        peer_id: &str,
        kind: &str,
        payload: &str,
        created_at: i64,
    ) -> Result<String, PlexError> {
        self.save_call_signal(call_id, peer_id, DIR_OUTGOING, kind, payload, created_at)
    }

    /// Сохраняет входящий call-сигнал в журнал.
    pub fn save_incoming_call_signal(
        &self,
        call_id: &str,
        peer_id: &str,
        kind: &str,
        payload: &str,
        created_at: i64,
    ) -> Result<String, PlexError> {
        self.save_call_signal(call_id, peer_id, DIR_INCOMING, kind, payload, created_at)
    }

    fn save_call_signal(
        &self,
        call_id: &str,
        peer_id: &str,
        direction: &str,
        kind: &str,
        payload: &str,
        created_at: i64,
    ) -> Result<String, PlexError> {
        let signal_id = generate_signal_id(call_id, peer_id, direction, kind, created_at);
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO call_signal_log
             (signal_id, call_id, peer_id, direction, kind, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![signal_id, call_id, peer_id, direction, kind, payload, created_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save call signal: {e}"),
            })?;
        Ok(signal_id)
    }

    /// Возвращает все сохранённые сигналы для `call_id`, отсортированные по времени.
    pub fn load_call_signals_for_call(
        &self,
        call_id: &str,
    ) -> Result<Vec<SavedCallSignal>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT signal_id, call_id, peer_id, direction, kind, payload, created_at
                 FROM call_signal_log
                 WHERE call_id = ?1
                 ORDER BY created_at ASC, signal_id ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([call_id], |row| {
                Ok(SavedCallSignal {
                    signal_id: row.get(0)?,
                    call_id: row.get(1)?,
                    peer_id: row.get(2)?,
                    direction: row.get(3)?,
                    kind: row.get(4)?,
                    payload: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Удаляет все сигналы для завершённого звонка (вызывать при End/Reject/Busy).
    pub fn prune_call_signals_for_call(&self, call_id: &str) -> Result<u64, PlexError> {
        let affected = self
            .conn()?
            .execute("DELETE FROM call_signal_log WHERE call_id = ?1", [call_id])
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to prune call signals: {e}"),
            })?;
        Ok(affected as u64)
    }

    /// Очистка старых сигналов по retention (не старше retention_secs).
    #[allow(dead_code)]
    pub fn prune_call_signals_older_than(&self, older_than: i64) -> Result<u64, PlexError> {
        let affected = self
            .conn()?
            .execute(
                "DELETE FROM call_signal_log WHERE created_at < ?1",
                [older_than],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to prune old call signals: {e}"),
            })?;
        Ok(affected as u64)
    }
}

fn generate_signal_id(
    call_id: &str,
    peer_id: &str,
    direction: &str,
    kind: &str,
    created_at: i64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(call_id.as_bytes());
    hasher.update(b"|");
    hasher.update(peer_id.as_bytes());
    hasher.update(b"|");
    hasher.update(direction.as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(created_at.to_le_bytes());
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in hash.iter() {
        use std::fmt::Write;
        write!(hex, "{:02x}", b).unwrap();
    }
    format!("csig:{}", hex)
}

pub(crate) const MIGRATION_V10: &str = "
CREATE TABLE IF NOT EXISTS call_signal_log (
    signal_id  TEXT PRIMARY KEY,
    call_id    TEXT NOT NULL,
    peer_id    TEXT NOT NULL,
    direction  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_call_signal_call_id ON call_signal_log(call_id, created_at ASC);

UPDATE schema_version SET version = 10
WHERE version < 10;
";

#[cfg(test)]
mod tests {
    use crate::storage::Db;
    use secrecy::SecretString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_db() -> Db {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("plex-call-signals-{nanos}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        Db::open(&db_path_str, &SecretString::new("test".into())).unwrap()
    }

    #[test]
    fn save_and_load_call_signals() {
        let db = test_db();

        db.save_outgoing_call_signal("call-1", "peer-b", "ring", "", 100)
            .unwrap();
        db.save_outgoing_call_signal("call-1", "peer-b", "offer", "v=0...", 101)
            .unwrap();
        db.save_incoming_call_signal("call-1", "peer-b", "answer", "v=0...", 102)
            .unwrap();

        let signals = db.load_call_signals_for_call("call-1").unwrap();
        assert_eq!(signals.len(), 3);
        assert_eq!(signals[0].kind, "ring");
        assert_eq!(signals[0].direction, "outgoing");
        assert_eq!(signals[2].kind, "answer");
        assert_eq!(signals[2].direction, "incoming");
    }

    #[test]
    fn prune_removes_only_target_call() {
        let db = test_db();

        db.save_outgoing_call_signal("call-1", "peer-b", "ring", "", 100)
            .unwrap();
        db.save_outgoing_call_signal("call-2", "peer-c", "ring", "", 101)
            .unwrap();

        let pruned = db.prune_call_signals_for_call("call-1").unwrap();
        assert_eq!(pruned, 1);

        assert!(db.load_call_signals_for_call("call-1").unwrap().is_empty());
        assert_eq!(db.load_call_signals_for_call("call-2").unwrap().len(), 1);
    }
}
