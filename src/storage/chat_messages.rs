use super::*;

const INLINE_MEDIA_MAX_BYTES: usize = 256 * 1024;
const MEDIA_CHUNK_BYTES: usize = 64 * 1024;

impl Db {
    pub fn upsert_chat_message(&self, message: &ChatMessage) -> Result<(), PlexError> {
        if message.message_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "chat message_id must not be empty".into(),
            });
        }
        if message.peer_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "chat peer_id must not be empty".into(),
            });
        }
        if message.kind.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "chat kind must not be empty".into(),
            });
        }

        let inline_media = message
            .media_blob
            .as_ref()
            .filter(|blob| blob.len() <= INLINE_MEDIA_MAX_BYTES)
            .cloned();
        let chunked_media = message
            .media_blob
            .as_ref()
            .filter(|blob| blob.len() > INLINE_MEDIA_MAX_BYTES)
            .cloned();

        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        tx.execute(
                "INSERT INTO chat_messages
                 (message_id, peer_id, transport_message_id, is_outgoing, kind, body_text, media_name, media_mime,
                  media_width, media_height, media_duration_ms, media_size, media_blob, status,
                  created_at, sent_at, delivered_at, read_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
                 ON CONFLICT(message_id) DO UPDATE SET
                    peer_id = excluded.peer_id,
                    transport_message_id = COALESCE(excluded.transport_message_id, chat_messages.transport_message_id),
                    is_outgoing = excluded.is_outgoing,
                    kind = excluded.kind,
                    body_text = excluded.body_text,
                    media_name = excluded.media_name,
                    media_mime = excluded.media_mime,
                    media_width = COALESCE(excluded.media_width, chat_messages.media_width),
                    media_height = COALESCE(excluded.media_height, chat_messages.media_height),
                    media_duration_ms = COALESCE(excluded.media_duration_ms, chat_messages.media_duration_ms),
                    media_size = excluded.media_size,
                    media_blob = excluded.media_blob,
                    status = CASE
                        WHEN chat_messages.status = 'read'                                       THEN chat_messages.status
                        WHEN chat_messages.status = 'delivered' AND excluded.status IN ('queued','sent') THEN chat_messages.status
                        WHEN chat_messages.status = 'sent'      AND excluded.status = 'queued'   THEN chat_messages.status
                        ELSE excluded.status
                    END,
                    sent_at = COALESCE(excluded.sent_at, chat_messages.sent_at),
                    delivered_at = COALESCE(excluded.delivered_at, chat_messages.delivered_at),
                    read_at = COALESCE(excluded.read_at, chat_messages.read_at),
                    updated_at = excluded.updated_at",
                params![
                    &message.message_id,
                    &message.peer_id,
                    &message.transport_message_id,
                    if message.is_outgoing { 1 } else { 0 },
                    &message.kind,
                    &message.body_text,
                    &message.media_name,
                    &message.media_mime,
                    message.media_width,
                    message.media_height,
                    message.media_duration_ms,
                    message.media_size,
                    &inline_media,
                    &message.status,
                    message.created_at,
                    message.sent_at,
                    message.delivered_at,
                    message.read_at,
                    message.updated_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to upsert chat message: {e}"),
            })?;

        tx.execute(
            "DELETE FROM chat_media_chunks WHERE message_id = ?1",
            [&message.message_id],
        )
        .map_err(|e| PlexError::Storage {
            msg: format!("Failed to clear previous chat media chunks: {e}"),
        })?;

        if let Some(blob) = chunked_media {
            for (chunk_index, chunk) in blob.chunks(MEDIA_CHUNK_BYTES).enumerate() {
                tx.execute(
                    "INSERT INTO chat_media_chunks (message_id, chunk_index, chunk_blob)
                     VALUES (?1, ?2, ?3)",
                    params![&message.message_id, chunk_index as i64, chunk],
                )
                .map_err(|e| PlexError::Storage {
                    msg: format!("Failed to insert chat media chunk: {e}"),
                })?;
            }
        }

        tx.commit().map_err(|e| PlexError::Storage {
            msg: format!("Failed to commit chat message upsert transaction: {e}"),
        })?;

        Ok(())
    }

    pub fn load_chat_message(&self, message_id: &str) -> Result<Option<ChatMessage>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT message_id, peer_id, transport_message_id, is_outgoing, kind, body_text, media_name, media_mime,
                    media_width, media_height, media_duration_ms, media_size, media_blob,
                    status, created_at, sent_at, delivered_at, read_at, updated_at
             FROM chat_messages WHERE message_id = ?1",
            [message_id],
            |row| {
                Ok(ChatMessage {
                    message_id: row.get(0)?,
                    peer_id: row.get(1)?,
                    transport_message_id: row.get(2)?,
                    is_outgoing: row.get::<_, i64>(3)? != 0,
                    kind: row.get(4)?,
                    body_text: row.get(5)?,
                    media_name: row.get(6)?,
                    media_mime: row.get(7)?,
                    media_width: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
                    media_height: row.get::<_, Option<i64>>(9)?.map(|v| v as u32),
                    media_duration_ms: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
                    media_size: row.get(11)?,
                    media_blob: row.get(12)?,
                    status: row.get(13)?,
                    created_at: row.get(14)?,
                    sent_at: row.get(15)?,
                    delivered_at: row.get(16)?,
                    read_at: row.get(17)?,
                    updated_at: row.get(18)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    pub fn list_chat_messages(
        &self,
        peer_id: &str,
        limit: usize,
        before_ts: Option<i64>,
    ) -> Result<Vec<ChatMessage>, PlexError> {
        let conn = self.conn()?;
        let cap = (limit.min(512)) as i64;

        let sql = if before_ts.is_some() {
            "SELECT message_id, peer_id, transport_message_id, is_outgoing, kind, body_text, media_name, media_mime,
                    media_width, media_height, media_duration_ms, media_size, media_blob,
                    status, created_at, sent_at, delivered_at, read_at, updated_at
             FROM chat_messages
             WHERE peer_id = ?1 AND created_at < ?2
             ORDER BY created_at DESC, message_id DESC
             LIMIT ?3"
        } else {
            "SELECT message_id, peer_id, transport_message_id, is_outgoing, kind, body_text, media_name, media_mime,
                    media_width, media_height, media_duration_ms, media_size, media_blob,
                    status, created_at, sent_at, delivered_at, read_at, updated_at
             FROM chat_messages
             WHERE peer_id = ?1
             ORDER BY created_at DESC, message_id DESC
             LIMIT ?2"
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ChatMessage> {
            Ok(ChatMessage {
                message_id: row.get(0)?,
                peer_id: row.get(1)?,
                transport_message_id: row.get(2)?,
                is_outgoing: row.get::<_, i64>(3)? != 0,
                kind: row.get(4)?,
                body_text: row.get(5)?,
                media_name: row.get(6)?,
                media_mime: row.get(7)?,
                media_width: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
                media_height: row.get::<_, Option<i64>>(9)?.map(|v| v as u32),
                media_duration_ms: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
                media_size: row.get(11)?,
                media_blob: row.get(12)?,
                status: row.get(13)?,
                created_at: row.get(14)?,
                sent_at: row.get(15)?,
                delivered_at: row.get(16)?,
                read_at: row.get(17)?,
                updated_at: row.get(18)?,
            })
        };

        let rows = if let Some(ts) = before_ts {
            stmt.query_map(params![peer_id, ts, cap], map_row)
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
        } else {
            stmt.query_map(params![peer_id, cap], map_row)
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
        };

        Ok(rows)
    }

    pub fn list_chat_dialogs(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ChatDialogSummary>, PlexError> {
        let conn = self.conn()?;
        let cap = (limit.min(256)) as i64;
        let skip = offset as i64;

        let mut stmt = conn
            .prepare(
                "SELECT m.peer_id,
                        m.message_id,
                        m.kind,
                        m.body_text,
                        m.status,
                        m.created_at,
                        (
                            SELECT COUNT(1)
                            FROM chat_messages u
                            WHERE u.peer_id = m.peer_id
                              AND u.is_outgoing = 0
                              AND u.read_at IS NULL
                        ) AS unread_count
                 FROM chat_messages m
                 WHERE m.message_id = (
                     SELECT m2.message_id
                     FROM chat_messages m2
                     WHERE m2.peer_id = m.peer_id
                     ORDER BY m2.created_at DESC, m2.message_id DESC
                     LIMIT 1
                 )
                 ORDER BY m.created_at DESC, m.message_id DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map(params![cap, skip], |row| {
                let text: Option<String> = row.get(3)?;
                let preview = text
                    .as_ref()
                    .map(|t| t.chars().take(80).collect::<String>());

                Ok(ChatDialogSummary {
                    peer_id: row.get(0)?,
                    last_message_id: row.get(1)?,
                    last_kind: row.get(2)?,
                    last_text_preview: preview,
                    last_status: row.get(4)?,
                    last_created_at: row.get(5)?,
                    unread_count: row.get::<_, i64>(6)?.max(0) as u64,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    pub fn load_chat_media_blob(&self, message_id: &str) -> Result<Option<Vec<u8>>, PlexError> {
        let conn = self.conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT media_blob, media_size
                 FROM chat_messages
                 WHERE message_id = ?1",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let row = stmt
            .query_row([message_id], |row| {
                let blob: Option<Vec<u8>> = row.get(0)?;
                let size: Option<i64> = row.get(1)?;
                Ok((blob, size))
            })
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let Some((inline_blob, media_size)) = row else {
            return Ok(None);
        };

        if let Some(blob) = inline_blob {
            return Ok(Some(blob));
        }

        if media_size.unwrap_or(0) <= 0 {
            return Ok(None);
        }

        let mut chunk_stmt = conn
            .prepare(
                "SELECT chunk_blob
                 FROM chat_media_chunks
                 WHERE message_id = ?1
                 ORDER BY chunk_index ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let chunks = chunk_stmt
            .query_map([message_id], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        if chunks.is_empty() {
            return Ok(None);
        }

        let total_size = chunks.iter().map(std::vec::Vec::len).sum();
        let mut out = Vec::with_capacity(total_size);
        for chunk in chunks {
            out.extend_from_slice(&chunk);
        }

        Ok(Some(out))
    }

    pub fn count_unread_chat_messages(&self, peer_id: &str) -> Result<u64, PlexError> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1)
                 FROM chat_messages
                 WHERE peer_id = ?1
                   AND is_outgoing = 0
                   AND read_at IS NULL",
                [peer_id],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(count.max(0) as u64)
    }

    pub fn mark_chat_message_sent_by_transport_id(
        &self,
        transport_message_id: &str,
        sent_at: i64,
    ) -> Result<bool, PlexError> {
        // Only advance queued → sent. Never regress delivered/read back to sent.
        let affected = self
            .conn()?
            .execute(
                "UPDATE chat_messages
                 SET status = 'sent',
                     sent_at = COALESCE(sent_at, ?2),
                     updated_at = ?2
                 WHERE transport_message_id = ?1
                   AND status = 'queued'",
                params![transport_message_id, sent_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark chat message sent by transport id: {e}"),
            })?;

        Ok(affected > 0)
    }

    pub fn mark_chat_message_delivered_by_transport_id(
        &self,
        transport_message_id: &str,
        delivered_at: i64,
    ) -> Result<bool, PlexError> {
        // Only advance queued/sent → delivered. Never regress read back to delivered.
        let affected = self
            .conn()?
            .execute(
                "UPDATE chat_messages
                 SET status = 'delivered',
                     delivered_at = COALESCE(delivered_at, ?2),
                     updated_at = ?2
                 WHERE transport_message_id = ?1
                   AND status != 'read'",
                params![transport_message_id, delivered_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark chat message delivered by transport id: {e}"),
            })?;

        Ok(affected > 0)
    }

    pub fn mark_chat_message_read(
        &self,
        message_id: &str,
        read_at: i64,
    ) -> Result<bool, PlexError> {
        // Guard: only advance to 'read' if not already read. Prevents duplicate receipt sends.
        let affected = self
            .conn()?
            .execute(
                "UPDATE chat_messages
                 SET status = 'read',
                     read_at = COALESCE(read_at, ?2),
                     updated_at = ?2
                 WHERE message_id = ?1
                   AND read_at IS NULL",
                params![message_id, read_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark chat message read: {e}"),
            })?;

        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use secrecy::SecretString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_db() -> Db {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("plex-chat-status-{nanos}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        Db::open(&db_path_str, &SecretString::new("test".into())).unwrap()
    }

    fn base_message(msg_id: &str, transport_id: &str) -> ChatMessage {
        ChatMessage {
            message_id: msg_id.to_string(),
            peer_id: "peer-a".into(),
            transport_message_id: Some(transport_id.to_string()),
            is_outgoing: true,
            kind: "text".into(),
            body_text: Some("hello".into()),
            media_name: None,
            media_mime: None,
            media_width: None,
            media_height: None,
            media_duration_ms: None,
            media_size: None,
            media_blob: None,
            status: "queued".into(),
            created_at: 100,
            sent_at: None,
            delivered_at: None,
            read_at: None,
            updated_at: 100,
        }
    }

    // ── Тест 1: forward-only upsert — re-upsert 'queued' не перезаписывает 'delivered' ──
    #[test]
    fn upsert_does_not_regress_status_from_delivered_to_queued() {
        let db = test_db();
        let msg = base_message("msg-1", "tr-1");
        db.upsert_chat_message(&msg).unwrap();

        // Advance to delivered
        db.mark_chat_message_delivered_by_transport_id("tr-1", 200)
            .unwrap();
        let loaded = db.load_chat_message("msg-1").unwrap().unwrap();
        assert_eq!(loaded.status, "delivered");

        // Re-upsert with 'queued' status — must not regress
        db.upsert_chat_message(&msg).unwrap();
        let loaded2 = db.load_chat_message("msg-1").unwrap().unwrap();
        assert_eq!(
            loaded2.status, "delivered",
            "status must not regress from delivered to queued on re-upsert"
        );
    }

    // ── Тест 2: mark_sent guard — нельзя вернуть delivered → sent ─────────────────────
    #[test]
    fn mark_sent_does_not_regress_from_delivered() {
        let db = test_db();
        let msg = base_message("msg-2", "tr-2");
        db.upsert_chat_message(&msg).unwrap();

        db.mark_chat_message_delivered_by_transport_id("tr-2", 200)
            .unwrap();
        // Attempt to regress to sent
        let advanced = db
            .mark_chat_message_sent_by_transport_id("tr-2", 300)
            .unwrap();
        assert!(
            !advanced,
            "mark_sent must not update a message already at delivered"
        );

        let loaded = db.load_chat_message("msg-2").unwrap().unwrap();
        assert_eq!(loaded.status, "delivered");
    }

    // ── Тест 3: mark_delivered guard — нельзя вернуть read → delivered ────────────────
    #[test]
    fn mark_delivered_does_not_regress_from_read() {
        let db = test_db();
        let mut msg = base_message("msg-3", "tr-3");
        msg.is_outgoing = false;
        db.upsert_chat_message(&msg).unwrap();

        db.mark_chat_message_read("msg-3", 200).unwrap();
        let loaded = db.load_chat_message("msg-3").unwrap().unwrap();
        assert_eq!(loaded.status, "read");

        // Attempt to regress to delivered
        let regressed = db
            .mark_chat_message_delivered_by_transport_id("tr-3", 300)
            .unwrap();
        assert!(
            !regressed,
            "mark_delivered must not update a message already at read"
        );

        let loaded2 = db.load_chat_message("msg-3").unwrap().unwrap();
        assert_eq!(loaded2.status, "read");
    }

    // ── Тест 4: mark_read идемпотентен — повторный вызов возвращает false ─────────────
    #[test]
    fn mark_read_is_idempotent() {
        let db = test_db();
        let mut msg = base_message("msg-4", "tr-4");
        msg.is_outgoing = false;
        db.upsert_chat_message(&msg).unwrap();

        let first = db.mark_chat_message_read("msg-4", 200).unwrap();
        assert!(first, "first read must return true");

        let second = db.mark_chat_message_read("msg-4", 300).unwrap();
        assert!(!second, "second read must return false (already read)");

        // Timestamp must not change
        let loaded = db.load_chat_message("msg-4").unwrap().unwrap();
        assert_eq!(
            loaded.read_at,
            Some(200),
            "read_at must not change on second mark_read"
        );
    }

    // ── Тест 5: happy path — full queued → sent → delivered → read flow ───────────────
    #[test]
    fn status_advances_forward_through_full_lifecycle() {
        let db = test_db();
        let msg = base_message("msg-5", "tr-5");
        db.upsert_chat_message(&msg).unwrap();

        assert!(db
            .mark_chat_message_sent_by_transport_id("tr-5", 110)
            .unwrap());
        let l1 = db.load_chat_message("msg-5").unwrap().unwrap();
        assert_eq!(l1.status, "sent");

        assert!(db
            .mark_chat_message_delivered_by_transport_id("tr-5", 120)
            .unwrap());
        let l2 = db.load_chat_message("msg-5").unwrap().unwrap();
        assert_eq!(l2.status, "delivered");

        assert!(db.mark_chat_message_read("msg-5", 130).unwrap());
        let l3 = db.load_chat_message("msg-5").unwrap().unwrap();
        assert_eq!(l3.status, "read");
        assert_eq!(l3.sent_at, Some(110));
        assert_eq!(l3.delivered_at, Some(120));
        assert_eq!(l3.read_at, Some(130));
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatDialogSummary {
    pub peer_id: String,
    pub last_message_id: String,
    pub last_kind: String,
    pub last_text_preview: Option<String>,
    pub last_status: String,
    pub last_created_at: i64,
    pub unread_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatMessage {
    pub message_id: String,
    pub peer_id: String,
    pub transport_message_id: Option<String>,
    pub is_outgoing: bool,
    pub kind: String,
    pub body_text: Option<String>,
    pub media_name: Option<String>,
    pub media_mime: Option<String>,
    pub media_width: Option<u32>,
    pub media_height: Option<u32>,
    pub media_duration_ms: Option<u64>,
    pub media_size: Option<i64>,
    pub media_blob: Option<Vec<u8>>,
    pub status: String,
    pub created_at: i64,
    pub sent_at: Option<i64>,
    pub delivered_at: Option<i64>,
    pub read_at: Option<i64>,
    pub updated_at: i64,
}

pub(crate) const MIGRATION_V8: &str = "
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id            TEXT PRIMARY KEY,
    peer_id               TEXT NOT NULL,
    transport_message_id  TEXT,
    is_outgoing           INTEGER NOT NULL,
    kind                  TEXT NOT NULL,
    body_text             TEXT,
    media_name            TEXT,
    media_mime            TEXT,
    media_size            INTEGER,
    media_blob            BLOB,
    status                TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    sent_at               INTEGER,
    delivered_at          INTEGER,
    read_at               INTEGER,
    updated_at            INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_chat_peer_time ON chat_messages(peer_id, created_at DESC, message_id DESC);
CREATE INDEX IF NOT EXISTS idx_chat_unread ON chat_messages(peer_id, is_outgoing, read_at);
CREATE INDEX IF NOT EXISTS idx_chat_transport_id ON chat_messages(transport_message_id);

UPDATE schema_version SET version = 8
WHERE version < 8;
";

pub(crate) const MIGRATION_V14: &str = "
ALTER TABLE chat_messages ADD COLUMN media_width       INTEGER;
ALTER TABLE chat_messages ADD COLUMN media_height      INTEGER;
ALTER TABLE chat_messages ADD COLUMN media_duration_ms INTEGER;

UPDATE schema_version SET version = 14
WHERE version < 14;
";

pub(crate) const MIGRATION_V9: &str = "
CREATE TABLE IF NOT EXISTS chat_media_chunks (
    message_id   TEXT NOT NULL,
    chunk_index  INTEGER NOT NULL,
    chunk_blob   BLOB NOT NULL,
    PRIMARY KEY(message_id, chunk_index)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_chat_media_chunks_message ON chat_media_chunks(message_id, chunk_index);

UPDATE schema_version SET version = 9
WHERE version < 9;
";
