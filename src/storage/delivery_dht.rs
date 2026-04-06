use super::*;
use rand::Rng;

impl Db {
    /// Возвращает активные DHT-ключи (по которым TTL еще не истек).
    pub fn all_active_dht_keys(&self, now: i64) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT dht_key FROM dht_records
                 WHERE expires_at > ?1
                 ORDER BY dht_key ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let keys = stmt
            .query_map([now], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(keys)
    }

    /// Возвращает активные DHT-записи, которых нет у удаленного пира.
    pub fn dht_records_excluding(
        &self,
        known_keys: &[String],
        limit: usize,
        now: i64,
    ) -> Result<Vec<DhtRecord>, PlexError> {
        let known = known_keys.iter().cloned().collect::<HashSet<_>>();
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT dht_key, value_blob, updated_at, expires_at
                 FROM dht_records
                 WHERE expires_at > ?1
                 ORDER BY updated_at DESC, dht_key ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let mut rows = stmt
            .query_map([now], |row| {
                Ok(DhtRecord {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    updated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        rows.retain(|record| !known.contains(&record.key));
        if rows.len() > limit {
            rows.truncate(limit);
        }

        Ok(rows)
    }

    /// Импортирует DHT-запись с anti-downgrade по `updated_at`.
    /// Возвращает `true`, если запись была вставлена/обновлена.
    pub fn import_dht_record(&self, record: &DhtRecord, now: i64) -> Result<bool, PlexError> {
        if record.key.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "DHT key must not be empty".into(),
            });
        }

        if record.expires_at <= now {
            return Ok(false);
        }

        let updated = self
            .conn()?
            .execute(
                "INSERT INTO dht_records (dht_key, value_blob, updated_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(dht_key) DO UPDATE SET
                    value_blob = excluded.value_blob,
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at
                 WHERE excluded.updated_at >= dht_records.updated_at",
                params![
                    &record.key,
                    &record.value,
                    record.updated_at,
                    record.expires_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to import DHT record: {e}"),
            })?;

        Ok(updated > 0)
    }

    /// Удаляет все DHT-записи с истекшим TTL.
    pub fn prune_expired_dht_records(&self, now: i64) -> Result<u64, PlexError> {
        let deleted = self
            .conn()?
            .execute("DELETE FROM dht_records WHERE expires_at <= ?1", [now])
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to prune expired DHT records: {e}"),
            })?;

        Ok(deleted as u64)
    }

    /// Возвращает ключи записей, которые истекут до дедлайна (включительно).
    pub fn dht_keys_expiring_before(
        &self,
        deadline: i64,
        limit: usize,
    ) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT dht_key FROM dht_records
                 WHERE expires_at <= ?1
                 ORDER BY expires_at ASC, dht_key ASC
                 LIMIT ?2",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let keys = stmt
            .query_map(params![deadline, limit as i64], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(keys)
    }

    /// Продлевает TTL существующей DHT-записи.
    pub fn refresh_dht_record_ttl(
        &self,
        key: &str,
        ttl_secs: i64,
        now: i64,
    ) -> Result<bool, PlexError> {
        let expires_at = now.saturating_add(ttl_secs.max(1));
        let affected = self
            .conn()?
            .execute(
                "UPDATE dht_records
                 SET updated_at = ?2,
                     expires_at = ?3
                 WHERE dht_key = ?1",
                params![key, now, expires_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to refresh DHT record TTL: {e}"),
            })?;

        Ok(affected > 0)
    }

    /// Возвращает `(total_records, total_bytes)` для активных (не истекших) DHT-записей.
    ///
    /// Используется для проверки превышения лимита кэша.
    pub fn dht_cache_usage(&self, now: i64) -> Result<(u64, u64), PlexError> {
        let conn = self.conn()?;
        let (records, bytes): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(value_blob)), 0)
                 FROM dht_records
                 WHERE expires_at > ?1",
                [now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok((records as u64, bytes.max(0) as u64))
    }

    /// Возвращает кандидатов на вытеснение: самые старые (по `updated_at`) активные записи.
    ///
    /// Порядок: oldest-first — чтобы вытеснять наименее актуальные данные первыми.
    pub fn dht_eviction_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<DhtCacheEvictionCandidate>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT dht_key, LENGTH(value_blob), updated_at, expires_at
                 FROM dht_records
                 WHERE expires_at > ?1
                 ORDER BY updated_at ASC, expires_at ASC
                 LIMIT ?2",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let candidates = stmt
            .query_map(params![now, limit as i64], |row| {
                Ok(DhtCacheEvictionCandidate {
                    key: row.get(0)?,
                    size_bytes: {
                        let v: i64 = row.get(1)?;
                        v.max(0) as u64
                    },
                    updated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(candidates)
    }

    /// Удаляет DHT-записи по явно переданному списку ключей.
    ///
    /// Ключи, которых не существует, игнорируются без ошибки.
    /// Возвращает число фактически удалённых записей.
    pub fn dht_delete_by_keys(&self, keys: &[String]) -> Result<u64, PlexError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let conn = self.conn()?;
        let mut total = 0u64;
        for key in keys {
            let deleted = conn
                .execute("DELETE FROM dht_records WHERE dht_key = ?1", [key])
                .map_err(|e| PlexError::Storage {
                    msg: format!("Failed to delete DHT record '{key}': {e}"),
                })?;
            total += deleted as u64;
        }
        Ok(total)
    }

    /// Добавляет сообщение в надежную outbox-очередь.
    pub fn enqueue_outbox_message(
        &self,
        peer_id: &str,
        ciphertext: &[u8],
        now: i64,
    ) -> Result<String, PlexError> {
        if peer_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "outbox peer_id must not be empty".into(),
            });
        }

        if ciphertext.is_empty() {
            return Err(PlexError::Storage {
                msg: "outbox ciphertext must not be empty".into(),
            });
        }

        let message_id = compute_outbox_message_id(peer_id, ciphertext, now);
        self.conn()?
            .execute(
                "INSERT INTO outbox_messages
                 (message_id, peer_id, ciphertext, status, attempt_count, last_error, created_at, updated_at, next_attempt_at)
                 VALUES (?1, ?2, ?3, 'queued', 0, NULL, ?4, ?4, ?4)
                 ON CONFLICT(message_id) DO NOTHING",
                params![message_id, peer_id, ciphertext, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to enqueue outbox message: {e}"),
            })?;

        Ok(message_id)
    }

    /// Возвращает pending сообщения (queued/failed) с наступившим next_attempt_at.
    pub fn pending_outbox_messages(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<OutboxMessage>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT message_id, peer_id, ciphertext, status, attempt_count, last_error, created_at, updated_at, next_attempt_at
                 FROM outbox_messages
                 WHERE status IN ('queued', 'failed')
                   AND next_attempt_at <= ?1
                 ORDER BY created_at ASC, message_id ASC
                 LIMIT ?2",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map(params![now, limit as i64], |row| {
                Ok(OutboxMessage {
                    message_id: row.get(0)?,
                    peer_id: row.get(1)?,
                    ciphertext: row.get(2)?,
                    status: row.get(3)?,
                    attempt_count: row.get::<_, i64>(4)?.max(0) as u64,
                    last_error: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    next_attempt_at: row.get(8)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Помечает сообщение как отправленное (пока без delivery ack).
    pub fn mark_outbox_sent(&self, message_id: &str, now: i64) -> Result<bool, PlexError> {
        let affected = self
            .conn()?
            .execute(
                "UPDATE outbox_messages
                 SET status = 'sent',
                     attempt_count = attempt_count + 1,
                     updated_at = ?2,
                     next_attempt_at = ?2,
                     last_error = NULL
                 WHERE message_id = ?1
                   AND status IN ('queued', 'failed', 'sent')",
                params![message_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark outbox sent: {e}"),
            })?;

        Ok(affected > 0)
    }

    /// Помечает сообщение как failed и планирует повтор.
    pub fn mark_outbox_failed(
        &self,
        message_id: &str,
        error_text: &str,
        retry_at: i64,
        now: i64,
    ) -> Result<bool, PlexError> {
        let affected = self
            .conn()?
            .execute(
                "UPDATE outbox_messages
                 SET status = 'failed',
                     attempt_count = attempt_count + 1,
                     updated_at = ?4,
                     next_attempt_at = ?3,
                     last_error = ?2
                 WHERE message_id = ?1
                   AND status IN ('queued', 'failed', 'sent')",
                params![message_id, error_text, retry_at, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark outbox failed: {e}"),
            })?;

        Ok(affected > 0)
    }

    /// Помечает сообщение как failed и рассчитывает retry по backoff с jitter.
    /// При достижении лимита попыток переводит сообщение в terminal status `dead`.
    /// Возвращает delay (сек), 0 = сообщение помечено dead.
    pub fn mark_outbox_failed_with_backoff_jitter(
        &self,
        message_id: &str,
        error_text: &str,
        base_delay_secs: u64,
        max_delay_secs: u64,
        max_attempts: u64,
        now: i64,
    ) -> Result<Option<u64>, PlexError> {
        self.mark_outbox_failed_with_backoff_internal(
            message_id,
            error_text,
            base_delay_secs,
            max_delay_secs,
            max_attempts,
            true,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_outbox_failed_with_backoff_internal(
        &self,
        message_id: &str,
        error_text: &str,
        base_delay_secs: u64,
        max_delay_secs: u64,
        max_attempts: u64,
        with_jitter: bool,
        now: i64,
    ) -> Result<Option<u64>, PlexError> {
        let attempt_count: Option<i64> = {
            let conn = self.conn()?;
            conn.query_row(
                "SELECT attempt_count FROM outbox_messages WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
        };

        let Some(current_attempts) = attempt_count else {
            return Ok(None);
        };

        let next_attempt = current_attempts.max(0) as u64 + 1;
        if next_attempt >= max_attempts.max(1) {
            let affected = self
                .conn()?
                .execute(
                    "UPDATE outbox_messages
                     SET status = 'dead',
                         attempt_count = attempt_count + 1,
                         updated_at = ?2,
                         next_attempt_at = ?2,
                         last_error = ?3
                     WHERE message_id = ?1
                       AND status IN ('queued', 'failed', 'sent')",
                    params![message_id, now, error_text],
                )
                .map_err(|e| PlexError::Storage {
                    msg: format!("Failed to mark outbox dead: {e}"),
                })?;

            if affected > 0 {
                return Ok(Some(0));
            }
            return Ok(None);
        }

        let exp = next_attempt.saturating_sub(1).min(20);
        let multiplier = 1u64 << exp;
        let mut delay = base_delay_secs
            .max(1)
            .saturating_mul(multiplier)
            .min(max_delay_secs.max(1));

        if with_jitter && delay > 1 {
            let jitter_range = (delay / 5).max(1);
            let jitter = rand::thread_rng().gen_range(0..=jitter_range);
            delay = delay.saturating_add(jitter).min(max_delay_secs.max(1));
        }

        let retry_at = now.saturating_add(delay as i64);

        if self.mark_outbox_failed(message_id, error_text, retry_at, now)? {
            Ok(Some(delay))
        } else {
            Ok(None)
        }
    }

    /// Регистрирует delivery-ack и помечает сообщение как delivered.
    pub fn ack_outbox_delivery(
        &self,
        peer_id: &str,
        message_id: &str,
        now: i64,
    ) -> Result<bool, PlexError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        tx.execute(
            "INSERT OR IGNORE INTO delivery_receipts (message_id, peer_id, delivered_at)
             VALUES (?1, ?2, ?3)",
            params![message_id, peer_id, now],
        )
        .map_err(|e| PlexError::Storage {
            msg: format!("Failed to insert delivery receipt: {e}"),
        })?;

        let updated = tx
            .execute(
                "UPDATE outbox_messages
                 SET status = 'delivered',
                     updated_at = ?2,
                     next_attempt_at = ?2,
                     last_error = NULL
                 WHERE message_id = ?1
                   AND peer_id = ?3",
                params![message_id, now, peer_id],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to update outbox delivery status: {e}"),
            })?;

        tx.commit()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(updated > 0)
    }

    /// Возвращает message_id известных delivery receipts.
    pub fn all_delivery_receipt_ids(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT message_id FROM delivery_receipts ORDER BY message_id ASC")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает delivery receipts, которых нет у удаленного пира.
    pub fn delivery_receipts_excluding(
        &self,
        known_ids: &[String],
        limit: usize,
    ) -> Result<Vec<DeliveryReceipt>, PlexError> {
        let known = known_ids.iter().cloned().collect::<HashSet<_>>();
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT message_id, peer_id, delivered_at
                 FROM delivery_receipts
                 ORDER BY delivered_at DESC, message_id ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(DeliveryReceipt {
                    message_id: row.get(0)?,
                    peer_id: row.get(1)?,
                    delivered_at: row.get(2)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        rows.retain(|r| !known.contains(&r.message_id));
        if rows.len() > limit {
            rows.truncate(limit);
        }

        Ok(rows)
    }

    /// Импортирует delivery receipt и продвигает локальный outbox до delivered.
    pub fn import_delivery_receipt(&self, receipt: &DeliveryReceipt) -> Result<bool, PlexError> {
        if receipt.message_id.trim().is_empty() || receipt.peer_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "delivery receipt fields must not be empty".into(),
            });
        }

        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO delivery_receipts (message_id, peer_id, delivered_at)
                 VALUES (?1, ?2, ?3)",
                params![receipt.message_id, receipt.peer_id, receipt.delivered_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to import delivery receipt: {e}"),
            })?;

        tx.execute(
            "UPDATE outbox_messages
             SET status = 'delivered',
                 updated_at = MAX(updated_at, ?2),
                 next_attempt_at = MAX(next_attempt_at, ?2),
                 last_error = NULL
             WHERE message_id = ?1
               AND peer_id = ?3",
            params![receipt.message_id, receipt.delivered_at, receipt.peer_id],
        )
        .map_err(|e| PlexError::Storage {
            msg: format!("Failed to apply imported delivery receipt: {e}"),
        })?;

        tx.commit()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(inserted > 0)
    }

    /// Проверяет, зарегистрировано ли уже входящее сообщение (read-only peek).
    ///
    /// Использовать перед `decrypt`, чтобы не блокировать dedup при ошибке расшифровки.
    pub fn is_inbound_message_registered(
        &self,
        peer_id: &str,
        message_id: &str,
    ) -> Result<bool, PlexError> {
        if peer_id.trim().is_empty() || message_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "peer_id and message_id must not be empty".into(),
            });
        }

        let count: i64 = self
            .conn()?
            .query_row(
                "SELECT COUNT(1) FROM inbound_message_dedup WHERE message_id = ?1 AND peer_id = ?2",
                params![message_id, peer_id],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to check inbound dedup: {e}"),
            })?;

        Ok(count > 0)
    }

    /// Регистрирует входящее сообщение как обработанное (INSERT OR IGNORE).
    /// Возвращает true при первой регистрации, false если уже было.
    pub fn register_inbound_message_once(
        &self,
        peer_id: &str,
        message_id: &str,
        now: i64,
    ) -> Result<bool, PlexError> {
        if peer_id.trim().is_empty() || message_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "peer_id and message_id must not be empty".into(),
            });
        }

        let inserted = self
            .conn()?
            .execute(
                "INSERT OR IGNORE INTO inbound_message_dedup
                 (message_id, peer_id, first_seen_at)
                 VALUES (?1, ?2, ?3)",
                params![message_id, peer_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to register inbound dedup message: {e}"),
            })?;

        Ok(inserted > 0)
    }

    /// Удаляет старые inbound dedup-записи по времени first_seen_at.
    pub fn prune_inbound_dedup_older_than(&self, older_than: i64) -> Result<u64, PlexError> {
        let deleted = self
            .conn()?
            .execute(
                "DELETE FROM inbound_message_dedup WHERE first_seen_at < ?1",
                [older_than],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to prune inbound dedup: {e}"),
            })?;

        Ok(deleted as u64)
    }

    /// Удаляет старые delivery receipts по delivered_at.
    pub fn prune_delivery_receipts_older_than(&self, older_than: i64) -> Result<u64, PlexError> {
        let deleted = self
            .conn()?
            .execute(
                "DELETE FROM delivery_receipts WHERE delivered_at < ?1",
                [older_than],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to prune delivery receipts: {e}"),
            })?;

        Ok(deleted as u64)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub updated_at: i64,
    pub expires_at: i64,
}

/// Кандидат на вытеснение из DHT-кэша при превышении лимита.
///
/// Содержит метаданные записи, достаточные для отображения пользователю
/// в диалоге подтверждения очистки.
#[derive(Debug, Clone)]
pub struct DhtCacheEvictionCandidate {
    /// DHT-ключ (идентификатор записи).
    pub key: String,
    /// Размер `value_blob` в байтах.
    pub size_bytes: u64,
    /// Unix-timestamp последнего обновления.
    pub updated_at: i64,
    /// Unix-timestamp истечения TTL.
    pub expires_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutboxMessage {
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryReceipt {
    pub message_id: String,
    pub peer_id: String,
    pub delivered_at: i64,
}

fn compute_outbox_message_id(peer_id: &str, ciphertext: &[u8], ts: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"plex.outbox.v1");
    hasher.update(peer_id.as_bytes());
    hasher.update(ciphertext);
    hasher.update(ts.to_le_bytes());
    encode_hex(&hasher.finalize())
}

pub(crate) const MIGRATION_V6: &str = "
CREATE TABLE IF NOT EXISTS dht_records (
    dht_key    TEXT PRIMARY KEY,
    value_blob BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dht_expires ON dht_records(expires_at);

UPDATE schema_version SET version = 6
WHERE version < 6;
";

pub(crate) const MIGRATION_V7: &str = "
CREATE TABLE IF NOT EXISTS outbox_messages (
    message_id      TEXT PRIMARY KEY,
    peer_id         TEXT NOT NULL,
    ciphertext      BLOB NOT NULL,
    status          TEXT NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    next_attempt_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS delivery_receipts (
    message_id   TEXT PRIMARY KEY,
    peer_id      TEXT NOT NULL,
    delivered_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS inbound_message_dedup (
    message_id    TEXT PRIMARY KEY,
    peer_id       TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_outbox_retry ON outbox_messages(status, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS idx_delivery_peer ON delivery_receipts(peer_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_dedup_peer ON inbound_message_dedup(peer_id, first_seen_at DESC);

UPDATE schema_version SET version = 7
WHERE version < 7;
";
