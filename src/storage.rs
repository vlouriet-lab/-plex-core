//! `storage.rs` — зашифрованная БД (SQLite + SQLCipher AES-256).
//!
//! * Открывает/создаёт файл `plex.db` в директории приложения.
//! * Применяет прагму `key` для AES-256 шифрования через SQLCipher.
//! * Выполняет миграции для двух слоев данных:
//!   1) Immutable `event_log` как криптографический журнал событий.
//!   2) Projection-таблицы (`users`, `contacts`, `relay_nodes`, `identity_registrations` и т.д.)
//!      для быстрых чтений FFI/API.
//!
//! Важно: projection-таблицы считаются производным состоянием и могут мутировать,
//! тогда как source-of-truth для репликации событий остается в `event_log`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use iroh_base::{PublicKey, SecretKey, Signature};
use rusqlite::{params, Connection, OptionalExtension};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::PlexError;

mod call_signals;
mod chat_messages;
mod delivery_dht;
mod events;
mod projection_events;
mod ratchet;

use self::call_signals::MIGRATION_V10;
pub use self::chat_messages::{ChatDialogSummary, ChatMessage};
use self::chat_messages::{MIGRATION_V14, MIGRATION_V8, MIGRATION_V9};
pub use self::delivery_dht::{DeliveryReceipt, DhtRecord, OutboxMessage};
use self::delivery_dht::{MIGRATION_V6, MIGRATION_V7};
pub use self::events::Event;
use self::events::MIGRATION_V1;
#[cfg(test)]
use self::events::{compute_event_id, sign_event_id, validate_event};
pub use self::projection_events::ProjectionEvent;

/// Обёртка над `rusqlite::Connection` с зашифрованным хранилищем.
///
/// Содержит два соединения:
/// * `writer` — для всех мутирующих операций (INSERT/UPDATE/DELETE).
/// * `reader` — для SELECT-запросов из фоновых задач (sync, export).
///   Оба находятся под `Mutex`, но разные блокировки позволяют фоновым
///   reads не блокировать foreground writes в WAL-режиме SQLite.
pub struct Db {
    /// Соединение для записи. Должно держаться как можно короче.
    writer: Mutex<Connection>,
    /// Отдельное соединение для чтения фоновыми задачами.
    reader: Mutex<Connection>,
    /// Ключ шифрования снапшотов Double Ratchet (HKDF от passphrase).
    /// Defense-in-depth поверх SQLCipher.
    pub(crate) ratchet_enc_key: Zeroizing<[u8; 32]>,
}

impl Db {
    pub fn open(db_path: &str, key: &SecretString) -> Result<Self, PlexError> {
        Self::open_at_path(db_path, key)
    }

    pub fn open_at_path(db_path: &str, key: &SecretString) -> Result<Self, PlexError> {
        if let Some(parent) = Path::new(db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| PlexError::Storage {
                    msg: format!("Cannot create DB dir {}: {e}", parent.display()),
                })?;
            }
        }

        // Хелпер: открывает одно соединение и применяет SQLCipher-ключ.
        let open_conn = |path: &str| -> Result<Connection, PlexError> {
            let conn = Connection::open(path).map_err(|e| PlexError::Storage {
                msg: format!("Cannot open DB: {e}"),
            })?;
            // Zeroizing<String> обнулит буфер при выходе из блока.
            {
                let pragma_val = Zeroizing::new(format!("\"{}\"", key.expose_secret()));
                conn.execute_batch(&format!("PRAGMA key = {};", &*pragma_val))
                    .map_err(|e| PlexError::Storage {
                        msg: format!("SQLCipher key error: {e}"),
                    })?;
            }
            conn.execute_batch("PRAGMA journal_mode = WAL;")
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
            Ok(conn)
        };

        let writer_conn = open_conn(db_path)?;
        let reader_conn = open_conn(db_path)?;

        // ── Derivation application-layer ratchet encryption key ──────────────
        // Отдельный ключ (не равный SQLCipher passphrase), полученный через
        // HKDF-SHA256. Defense-in-depth: даже если DB вытечет с passphrase —
        // снапшоты ratchet-сессий остаются зашифрованными этим ключом.
        let ratchet_enc_key = {
            let hk = Hkdf::<Sha256>::new(None, key.expose_secret().as_bytes());
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(b"plex/ratchet-enc/v1", out.as_mut())
                .map_err(|_| PlexError::Crypto {
                    msg: "HKDF expand failed for ratchet enc key".into(),
                })?;
            out
        };

        let db = Db {
            writer: Mutex::new(writer_conn),
            reader: Mutex::new(reader_conn),
            ratchet_enc_key,
        };
        db.migrate()?;
        Ok(db)
    }

    // Убрано: автоматическое определение пути (Android/Generic).
    // Теперь путь передаётся явно при открытии.

    /// Применяет все миграции в правильном порядке.
    fn migrate(&self) -> Result<(), PlexError> {
        self.conn()?
            .execute_batch(MIGRATION_V1)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V1 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V2)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V2 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V3)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V3 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V4)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V4 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V5)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V5 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V6)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V6 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V7)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V7 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V8)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V8 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V9)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V9 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V10)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V10 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V11)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V11 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V12)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V12 failed: {e}"),
            })?;

        self.conn()?
            .execute_batch(MIGRATION_V13)
            .map_err(|e| PlexError::Storage {
                msg: format!("Migration V13 failed: {e}"),
            })?;

        // MIGRATION_V14 содержит ALTER TABLE ADD COLUMN, которые не идемпотентны
        // в SQLite (нет поддержки IF NOT EXISTS). Запускаем только если БД ещё
        // не мигрирована до версии 14.
        let current_version: i64 = self
            .conn()?
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        if current_version < 14 {
            self.conn()?
                .execute_batch(MIGRATION_V14)
                .map_err(|e| PlexError::Storage {
                    msg: format!("Migration V14 failed: {e}"),
                })?;
        }

        if current_version < 15 {
            self.conn()?
                .execute_batch(MIGRATION_V15)
                .map_err(|e| PlexError::Storage {
                    msg: format!("Migration V15 failed: {e}"),
                })?;
        }

        if current_version < 16 {
            self.conn()?
                .execute_batch(MIGRATION_V16)
                .map_err(|e| PlexError::Storage {
                    msg: format!("Migration V16 failed: {e}"),
                })?;
        }

        Ok(())
    }

    // ── Публичный API хранилища ────────────────────────────────────────────

    /// Сохраняет или обновляет регистрацию личности пира.
    pub fn save_identity_registration(
        &self,
        record: &IdentityRegistration,
    ) -> Result<(), PlexError> {
        validate_identity_registration(record)?;

        self.conn()?
            .execute(
                "INSERT INTO identity_registrations
                 (peer_id, identity_commitment, registrar_node_id, registrar_signature, registered_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(peer_id) DO UPDATE SET
                    identity_commitment = excluded.identity_commitment,
                    registrar_node_id = excluded.registrar_node_id,
                    registrar_signature = excluded.registrar_signature,
                    registered_at = excluded.registered_at,
                    updated_at = excluded.updated_at
                 WHERE excluded.updated_at >= identity_registrations.updated_at",
                params![
                    &record.peer_id,
                    &record.identity_commitment,
                    &record.registrar_node_id,
                    &record.registrar_signature,
                    record.registered_at,
                    record.updated_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save identity registration: {e}"),
            })?;

        Ok(())
    }

    /// Загружает регистрацию личности пира.
    pub fn load_identity_registration(
        &self,
        peer_id: &str,
    ) -> Result<Option<IdentityRegistration>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT peer_id, identity_commitment, registrar_node_id, registrar_signature, registered_at, updated_at
             FROM identity_registrations
             WHERE peer_id = ?1",
            [peer_id],
            |row| {
                Ok(IdentityRegistration {
                    peer_id: row.get(0)?,
                    identity_commitment: row.get(1)?,
                    registrar_node_id: row.get(2)?,
                    registrar_signature: row.get(3)?,
                    registered_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Сохраняет запись об on-chain anchor верификации.
    pub fn save_verification_anchor(&self, anchor: &VerificationAnchor) -> Result<(), PlexError> {
        if anchor.peer_id.trim().is_empty()
            || anchor.chain.trim().is_empty()
            || anchor.tx_id.trim().is_empty()
        {
            return Err(PlexError::Storage {
                msg: "peer_id, chain and tx_id must not be empty".into(),
            });
        }

        self.conn()?
            .execute(
                "INSERT INTO verification_anchors
                 (peer_id, event_hash, chain, tx_id, confirmations, anchored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(chain, tx_id) DO UPDATE SET
                    peer_id = CASE
                        WHEN excluded.anchored_at >= verification_anchors.anchored_at THEN excluded.peer_id
                        ELSE verification_anchors.peer_id
                    END,
                    event_hash = CASE
                        WHEN excluded.anchored_at >= verification_anchors.anchored_at THEN excluded.event_hash
                        ELSE verification_anchors.event_hash
                    END,
                    confirmations = MAX(verification_anchors.confirmations, excluded.confirmations),
                    anchored_at = MAX(verification_anchors.anchored_at, excluded.anchored_at)",
                params![
                    &anchor.peer_id,
                    &anchor.event_hash,
                    &anchor.chain,
                    &anchor.tx_id,
                    anchor.confirmations,
                    anchor.anchored_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save verification anchor: {e}"),
            })?;

        Ok(())
    }

    /// Возвращает последнюю anchor-запись для пира.
    pub fn latest_verification_anchor(
        &self,
        peer_id: &str,
    ) -> Result<Option<VerificationAnchor>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT peer_id, event_hash, chain, tx_id, confirmations, anchored_at
             FROM verification_anchors
             WHERE peer_id = ?1
             ORDER BY anchored_at DESC, id DESC
             LIMIT 1",
            [peer_id],
            |row| {
                Ok(VerificationAnchor {
                    peer_id: row.get(0)?,
                    event_hash: row.get(1)?,
                    chain: row.get(2)?,
                    tx_id: row.get(3)?,
                    confirmations: row.get(4)?,
                    anchored_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Возвращает количество anchor-записей по пирy.
    pub fn verification_anchor_count(&self, peer_id: &str) -> Result<u64, PlexError> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM verification_anchors WHERE peer_id = ?1",
                [peer_id],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(count.max(0) as u64)
    }

    /// Возвращает число anchor-обновлений для пира начиная с указанного времени.
    pub fn verification_anchor_count_since(
        &self,
        peer_id: &str,
        since_ts: i64,
    ) -> Result<u64, PlexError> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM verification_anchors WHERE peer_id = ?1 AND anchored_at >= ?2",
                params![peer_id, since_ts],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(count.max(0) as u64)
    }

    /// Возвращает число identity-записей, обновлённых начиная с указанного времени.
    pub fn identity_registration_count_since(&self, since_ts: i64) -> Result<u64, PlexError> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM identity_registrations WHERE updated_at >= ?1",
                [since_ts],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(count.max(0) as u64)
    }

    /// Возвращает peer_id всех известных identity registration записей.
    pub fn all_identity_peer_ids(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT peer_id FROM identity_registrations ORDER BY peer_id ASC")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает identity registration записи, которых нет у удалённого пира.
    pub fn identity_registrations_excluding(
        &self,
        known_peer_ids: &[String],
        limit: usize,
    ) -> Result<Vec<IdentityRegistration>, PlexError> {
        let known = known_peer_ids.iter().cloned().collect::<HashSet<_>>();
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT peer_id, identity_commitment, registrar_node_id, registrar_signature, registered_at, updated_at
                 FROM identity_registrations
                 ORDER BY updated_at DESC, peer_id ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(IdentityRegistration {
                    peer_id: row.get(0)?,
                    identity_commitment: row.get(1)?,
                    registrar_node_id: row.get(2)?,
                    registrar_signature: row.get(3)?,
                    registered_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        rows.retain(|record| !known.contains(&record.peer_id));
        if rows.len() > limit {
            rows.truncate(limit);
        }

        Ok(rows)
    }

    /// Возвращает ключи вида "chain:tx_id" для всех anchor-записей.
    pub fn all_verification_anchor_keys(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT chain || ':' || tx_id AS anchor_key FROM verification_anchors ORDER BY anchored_at DESC, id DESC")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает anchor-записи, которых нет у удалённого пира.
    pub fn verification_anchors_excluding(
        &self,
        known_anchor_keys: &[String],
        limit: usize,
    ) -> Result<Vec<VerificationAnchor>, PlexError> {
        let known = known_anchor_keys.iter().cloned().collect::<HashSet<_>>();
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT peer_id, event_hash, chain, tx_id, confirmations, anchored_at
                 FROM verification_anchors
                 ORDER BY anchored_at DESC, id DESC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(VerificationAnchor {
                    peer_id: row.get(0)?,
                    event_hash: row.get(1)?,
                    chain: row.get(2)?,
                    tx_id: row.get(3)?,
                    confirmations: row.get(4)?,
                    anchored_at: row.get(5)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        rows.retain(|record| {
            let key = format!("{}:{}", record.chain, record.tx_id);
            !known.contains(&key)
        });
        if rows.len() > limit {
            rows.truncate(limit);
        }

        Ok(rows)
    }

    /// Сохраняет публичный профиль пользователя (с anti-downgrade по updated_at).
    pub fn save_public_profile(&self, profile: &PublicProfile) -> Result<(), PlexError> {
        if profile.user_id.trim().is_empty()
            || profile.username.trim().is_empty()
            || profile.display_name.trim().is_empty()
            || profile.public_key.trim().is_empty()
        {
            return Err(PlexError::Storage {
                msg: "user_id, username, display_name, public_key must not be empty".into(),
            });
        }

        self.conn()?
            .execute(
                "INSERT INTO users
                 (user_id, username, display_name, avatar_blob, bio, public_key, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(user_id) DO UPDATE SET
                    username = excluded.username,
                    display_name = excluded.display_name,
                    avatar_blob = excluded.avatar_blob,
                    bio = excluded.bio,
                    public_key = excluded.public_key,
                    updated_at = excluded.updated_at
                 WHERE excluded.updated_at >= users.updated_at",
                params![
                    &profile.user_id,
                    &profile.username,
                    &profile.display_name,
                    &profile.avatar_blob,
                    &profile.bio,
                    &profile.public_key,
                    profile.created_at,
                    profile.updated_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save public profile: {e}"),
            })?;

        Ok(())
    }

    /// Загружает профиль по user_id.
    pub fn load_public_profile(&self, user_id: &str) -> Result<Option<PublicProfile>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT user_id, username, display_name, avatar_blob, bio, public_key, created_at, updated_at
             FROM users WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(PublicProfile {
                    user_id: row.get(0)?,
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                    avatar_blob: row.get(3)?,
                    bio: row.get(4)?,
                    public_key: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Загружает профиль по username.
    pub fn load_public_profile_by_username(
        &self,
        username: &str,
    ) -> Result<Option<PublicProfile>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT user_id, username, display_name, avatar_blob, bio, public_key, created_at, updated_at
             FROM users WHERE username = ?1",
            [username],
            |row| {
                Ok(PublicProfile {
                    user_id: row.get(0)?,
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                    avatar_blob: row.get(3)?,
                    bio: row.get(4)?,
                    public_key: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Возвращает user_id всех известных профилей.
    pub fn all_public_profile_user_ids(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT user_id FROM users ORDER BY user_id ASC")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает публичные профили, которых нет у удалённого пира.
    pub fn public_profiles_excluding(
        &self,
        known_user_ids: &[String],
        limit: usize,
    ) -> Result<Vec<PublicProfile>, PlexError> {
        let known = known_user_ids.iter().cloned().collect::<HashSet<_>>();
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT user_id, username, display_name, avatar_blob, bio, public_key, created_at, updated_at
                 FROM users ORDER BY updated_at DESC, user_id ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(PublicProfile {
                    user_id: row.get(0)?,
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                    avatar_blob: row.get(3)?,
                    bio: row.get(4)?,
                    public_key: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        rows.retain(|profile| !known.contains(&profile.user_id));
        if rows.len() > limit {
            rows.truncate(limit);
        }

        Ok(rows)
    }

    /// Добавляет или обновляет контакт локального пользователя.
    pub fn upsert_contact(&self, contact: &Contact) -> Result<(), PlexError> {
        if contact.user_id.trim().is_empty() || contact.display_name.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "user_id and display_name must not be empty".into(),
            });
        }

        self.conn()?
            .execute(
                "INSERT INTO contacts
                 (user_id, username, display_name, custom_avatar_blob, trust_level, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id) DO UPDATE SET
                    username = excluded.username,
                    display_name = excluded.display_name,
                    custom_avatar_blob = excluded.custom_avatar_blob,
                    trust_level = excluded.trust_level",
                params![
                    &contact.user_id,
                    &contact.username,
                    &contact.display_name,
                    &contact.custom_avatar_blob,
                    &contact.trust_level,
                    contact.added_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to upsert contact: {e}"),
            })?;

        Ok(())
    }

    /// Список локальных контактов.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT user_id, username, display_name, custom_avatar_blob, trust_level, added_at
                 FROM contacts ORDER BY added_at DESC, user_id ASC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Contact {
                    user_id: row.get(0)?,
                    username: row.get::<_, String>(1)?,
                    display_name: row.get(2)?,
                    custom_avatar_blob: row.get(3)?,
                    trust_level: row.get(4)?,
                    added_at: row.get(5)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Ищет контакты по username (точное совпадение или prefix-match).
    pub fn search_contacts_by_username(&self, query: &str) -> Result<Vec<Contact>, PlexError> {
        let conn = self.conn()?;
        let pattern = format!("%{}%", query.to_lowercase());
        let mut stmt = conn
            .prepare(
                "SELECT user_id, username, display_name, custom_avatar_blob, trust_level, added_at
                 FROM contacts WHERE lower(username) LIKE ?1
                 ORDER BY username ASC LIMIT 50",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([pattern], |row| {
                Ok(Contact {
                    user_id: row.get(0)?,
                    username: row.get::<_, String>(1)?,
                    display_name: row.get(2)?,
                    custom_avatar_blob: row.get(3)?,
                    trust_level: row.get(4)?,
                    added_at: row.get(5)?,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Сохраняет или обновляет route hints пира отдельно от identity-контакта.
    pub fn upsert_peer_route_hint(&self, hint: &PeerRouteHint) -> Result<(), PlexError> {
        if hint.peer_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "peer_id must not be empty".into(),
            });
        }
        if hint.source.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "route hint source must not be empty".into(),
            });
        }

        let direct_addresses_json =
            serde_json::to_string(&hint.direct_addresses).map_err(|e| PlexError::Storage {
                msg: format!("Failed to serialize route hint direct addresses: {e}"),
            })?;

        self.conn()?
            .execute(
                "INSERT INTO peer_route_hints
                 (peer_id, relay_url, direct_addresses_json, source, last_success_at, last_failure_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(peer_id) DO UPDATE SET
                    relay_url = CASE
                        WHEN excluded.relay_url IS NOT NULL THEN excluded.relay_url
                        ELSE peer_route_hints.relay_url
                    END,
                    direct_addresses_json = excluded.direct_addresses_json,
                    source = excluded.source,
                    updated_at = MAX(peer_route_hints.updated_at, excluded.updated_at)",
                params![
                    &hint.peer_id,
                    &hint.relay_url,
                    &direct_addresses_json,
                    &hint.source,
                    hint.last_success_at,
                    hint.last_failure_at,
                    hint.updated_at,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to upsert peer route hint: {e}"),
            })?;

        Ok(())
    }

    pub fn load_peer_route_hint(&self, peer_id: &str) -> Result<Option<PeerRouteHint>, PlexError> {
        let conn = self.reader()?;
        conn.query_row(
            "SELECT peer_id, relay_url, direct_addresses_json, source, last_success_at, last_failure_at, updated_at
             FROM peer_route_hints
             WHERE peer_id = ?1",
            [peer_id],
            |row| {
                let direct_addresses_json: String = row.get(2)?;
                let direct_addresses = serde_json::from_str::<Vec<String>>(&direct_addresses_json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

                Ok(PeerRouteHint {
                    peer_id: row.get(0)?,
                    relay_url: row.get(1)?,
                    direct_addresses,
                    source: row.get(3)?,
                    last_success_at: row.get(4)?,
                    last_failure_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    pub fn mark_peer_route_hint_success(&self, peer_id: &str, now: i64) -> Result<(), PlexError> {
        self.conn()?
            .execute(
                "UPDATE peer_route_hints
                 SET last_success_at = ?2,
                     updated_at = MAX(updated_at, ?2)
                 WHERE peer_id = ?1",
                params![peer_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark peer route hint success: {e}"),
            })?;
        Ok(())
    }

    pub fn mark_peer_route_hint_failure(&self, peer_id: &str, now: i64) -> Result<(), PlexError> {
        self.conn()?
            .execute(
                "UPDATE peer_route_hints
                 SET last_failure_at = ?2,
                     updated_at = MAX(updated_at, ?2)
                 WHERE peer_id = ?1",
                params![peer_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark peer route hint failure: {e}"),
            })?;
        Ok(())
    }

    /// Возвращает `true` если `peer_id` уже известен (есть в contacts или
    /// в identity_registrations) **и не заблокирован**. Используется sync-слоем как auth gate.
    pub fn is_known_peer(&self, peer_id: &str) -> Result<bool, PlexError> {
        let conn = self.reader()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM (
                    SELECT 1 FROM contacts WHERE user_id = ?1
                    UNION ALL
                    SELECT 1 FROM identity_registrations WHERE peer_id = ?1
                ) LIMIT 1",
                [peer_id],
                |r| r.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        if count == 0 {
            return Ok(false);
        }
        // Заблокированные пиры не получают доступ к event log даже если они известны.
        Ok(!self.is_peer_blocked(peer_id)?)
    }

    /// Добавляет пира в blocklist. С этого момента он:
    /// * не получает event log при sync,
    /// * его входящая сессия закрывается немедленно.
    pub fn block_peer(&self, peer_id: &str, now: i64) -> Result<(), PlexError> {
        if peer_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "peer_id must not be empty".into(),
            });
        }
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO blocked_peers (peer_id, blocked_at) VALUES (?1, ?2)",
                params![peer_id, now],
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(())
    }

    /// Удаляет пира из blocklist.
    pub fn unblock_peer(&self, peer_id: &str) -> Result<(), PlexError> {
        self.conn()?
            .execute("DELETE FROM blocked_peers WHERE peer_id = ?1", [peer_id])
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(())
    }

    /// Возвращает `true` если пир заблокирован.
    pub fn is_peer_blocked(&self, peer_id: &str) -> Result<bool, PlexError> {
        let conn = self.reader()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM blocked_peers WHERE peer_id = ?1",
                [peer_id],
                |r| r.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(count > 0)
    }

    /// Возвращает список заблокированных (пара peer_id, blocked_at).
    pub fn list_blocked_peers(&self) -> Result<Vec<(String, i64)>, PlexError> {
        let conn = self.reader()?;
        let mut stmt = conn
            .prepare("SELECT peer_id, blocked_at FROM blocked_peers ORDER BY blocked_at DESC")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    // ── X3DH storage ──────────────────────────────────────────────────────────

    /// Загружает X25519 identity DH ключ из БД, или генерирует и сохраняет новый.
    ///
    /// Возвращает `(StaticSecret, pub_bytes)`.
    /// IK_dh постоянен — никогда не ротируется (как в Signal).
    pub fn x3dh_load_or_create_identity_key(
        &self,
    ) -> Result<(x25519_dalek::StaticSecret, [u8; 32]), PlexError> {
        use rand::rngs::OsRng;
        use x25519_dalek::PublicKey as X25519Pub;

        // Пробуем загрузить существующий ключ.
        let existing = {
            let conn = self.reader()?;
            conn.query_row(
                "SELECT ik_secret, ik_pub FROM x3dh_identity_key WHERE id = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
        };

        if let Some((secret_bytes, pub_bytes)) = existing {
            let secret_arr: [u8; 32] = secret_bytes.try_into().map_err(|_| PlexError::Storage {
                msg: "x3dh_identity_key: ik_secret blob has wrong length".into(),
            })?;
            let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|_| PlexError::Storage {
                msg: "x3dh_identity_key: ik_pub blob has wrong length".into(),
            })?;
            return Ok((x25519_dalek::StaticSecret::from(secret_arr), pub_arr));
        }

        // Генерируем и сохраняем.
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pub_key = X25519Pub::from(&secret).to_bytes();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .as_secs() as i64;

        self.conn()?
            .execute(
                "INSERT INTO x3dh_identity_key (id, ik_secret, ik_pub, created_at)
             VALUES (1, ?1, ?2, ?3)",
                params![secret.to_bytes().as_ref(), pub_key.as_ref(), now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save x3dh identity key: {e}"),
            })?;

        Ok((secret, pub_key))
    }

    /// Возвращает активный Signed Prekey: `(spk_id, secret, pub, sig, created_at)`.
    /// Возвращает `None` если активного SPK ещё нет.
    #[allow(clippy::type_complexity)]
    pub fn x3dh_get_active_spk(
        &self,
    ) -> Result<Option<(u32, [u8; 32], [u8; 32], Vec<u8>, i64)>, PlexError> {
        let conn = self.reader()?;
        let result = conn
            .query_row(
                "SELECT spk_id, spk_secret, spk_pub, spk_sig, created_at
             FROM x3dh_signed_prekeys
             WHERE superseded = 0
             ORDER BY spk_id DESC
             LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u32,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        match result {
            None => Ok(None),
            Some((spk_id, secret_bytes, pub_bytes, sig, created_at)) => {
                let secret: [u8; 32] = secret_bytes.try_into().map_err(|_| PlexError::Storage {
                    msg: "x3dh_signed_prekeys: spk_secret blob has wrong length".into(),
                })?;
                let pub_key: [u8; 32] = pub_bytes.try_into().map_err(|_| PlexError::Storage {
                    msg: "x3dh_signed_prekeys: spk_pub blob has wrong length".into(),
                })?;
                Ok(Some((spk_id, secret, pub_key, sig, created_at)))
            }
        }
    }

    /// Возвращает следующий незанятый spk_id (MAX + 1, минимум 1).
    pub fn x3dh_next_spk_id(&self) -> Result<u32, PlexError> {
        let conn = self.reader()?;
        let max_id: i64 = conn
            .query_row(
                "SELECT IFNULL(MAX(spk_id), 0) FROM x3dh_signed_prekeys",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok((max_id + 1) as u32)
    }

    /// Сохраняет новый SPK с явным `spk_id`, помечая прежний активный как `superseded`.
    ///
    /// Возвращает `spk_id`.
    pub fn x3dh_save_spk(
        &self,
        spk_id: u32,
        spk_secret: [u8; 32],
        spk_pub: [u8; 32],
        spk_sig: Vec<u8>,
        now: i64,
    ) -> Result<u32, PlexError> {
        let conn = self.conn()?;
        // Помечаем прежние активные SPK как superseded.
        conn.execute(
            "UPDATE x3dh_signed_prekeys SET superseded = 1 WHERE superseded = 0",
            [],
        )
        .map_err(|e| PlexError::Storage {
            msg: format!("Failed to supersede old SPKs: {e}"),
        })?;
        // Вставляем новый SPK.
        conn.execute(
            "INSERT INTO x3dh_signed_prekeys (spk_id, spk_secret, spk_pub, spk_sig, created_at, superseded)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![spk_id as i64, spk_secret.as_ref(), spk_pub.as_ref(), spk_sig.as_slice(), now],
        ).map_err(|e| PlexError::Storage {
            msg: format!("Failed to insert new SPK: {e}"),
        })?;
        Ok(spk_id)
    }

    /// Загружает SPK по ID (включая superseded — нужно Bob при accept_session).
    ///
    /// Возвращает `(spk_secret, spk_pub)` или `None` если SPK не найден.
    pub fn x3dh_get_spk_by_id(
        &self,
        spk_id: u32,
    ) -> Result<Option<(x25519_dalek::StaticSecret, [u8; 32])>, PlexError> {
        let conn = self.reader()?;
        let result = conn
            .query_row(
                "SELECT spk_secret, spk_pub FROM x3dh_signed_prekeys WHERE spk_id = ?1",
                [spk_id as i64],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        match result {
            None => Ok(None),
            Some((secret_bytes, pub_bytes)) => {
                let secret: [u8; 32] = secret_bytes.try_into().map_err(|_| PlexError::Storage {
                    msg: "x3dh_get_spk_by_id: spk_secret blob has wrong length".into(),
                })?;
                let pub_key: [u8; 32] = pub_bytes.try_into().map_err(|_| PlexError::Storage {
                    msg: "x3dh_get_spk_by_id: spk_pub blob has wrong length".into(),
                })?;
                Ok(Some((x25519_dalek::StaticSecret::from(secret), pub_key)))
            }
        }
    }

    /// Добавляет партию одноразовых prekeys в пул.
    ///
    /// Принимает вектор пар `(opk_secret[32], opk_pub[32])`.
    /// Возвращает вектор назначенных `opk_id`.
    pub fn x3dh_add_opks(&self, items: Vec<([u8; 32], [u8; 32])>) -> Result<Vec<u32>, PlexError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .as_secs() as i64;

        let mut ids = Vec::with_capacity(items.len());
        let conn = self.conn()?;
        for (secret, pub_key) in items {
            conn.execute(
                "INSERT INTO x3dh_one_time_prekeys (opk_secret, opk_pub, used, created_at)
                 VALUES (?1, ?2, 0, ?3)",
                params![secret.as_ref(), pub_key.as_ref(), now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to insert OPK: {e}"),
            })?;
            ids.push(conn.last_insert_rowid() as u32);
        }
        Ok(ids)
    }

    /// Помечает OPK как использованный и возвращает его секрет.
    ///
    /// Возвращает `None` если OPK не найден или уже использован.
    pub fn x3dh_consume_opk(&self, opk_id: u32) -> Result<Option<[u8; 32]>, PlexError> {
        let conn = self.conn()?;
        let updated = conn
            .execute(
                "UPDATE x3dh_one_time_prekeys SET used = 1 WHERE opk_id = ?1 AND used = 0",
                [opk_id as i64],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to mark OPK as used: {e}"),
            })?;

        if updated == 0 {
            return Ok(None);
        }

        let secret_bytes: Vec<u8> = conn
            .query_row(
                "SELECT opk_secret FROM x3dh_one_time_prekeys WHERE opk_id = ?1",
                [opk_id as i64],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to load consumed OPK secret: {e}"),
            })?;

        let secret: [u8; 32] = secret_bytes.try_into().map_err(|_| PlexError::Storage {
            msg: "x3dh_consume_opk: opk_secret blob has wrong length".into(),
        })?;
        Ok(Some(secret))
    }

    /// Возвращает `(opk_id, opk_pub)` самого старого неиспользованного OPK.
    ///
    /// Используется при построении prekey bundle — один OPK за раз.
    pub fn x3dh_get_oldest_unused_opk(&self) -> Result<Option<(u32, [u8; 32])>, PlexError> {
        let conn = self.reader()?;
        let result = conn
            .query_row(
                "SELECT opk_id, opk_pub FROM x3dh_one_time_prekeys
             WHERE used = 0
             ORDER BY opk_id ASC
             LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        match result {
            None => Ok(None),
            Some((opk_id, pub_bytes)) => {
                let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|_| PlexError::Storage {
                    msg: "x3dh_get_oldest_unused_opk: opk_pub blob has wrong length".into(),
                })?;
                Ok(Some((opk_id, pub_arr)))
            }
        }
    }

    /// Возвращает количество неиспользованных OPK в пуле.
    pub fn x3dh_remaining_opk_count(&self) -> Result<u64, PlexError> {
        let conn = self.reader()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM x3dh_one_time_prekeys WHERE used = 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(count as u64)
    }

    /// Удаляет контакт по user_id.
    pub fn remove_contact(&self, user_id: &str) -> Result<(), PlexError> {
        self.conn()?
            .execute("DELETE FROM contacts WHERE user_id = ?1", [user_id])
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to remove contact: {e}"),
            })?;

        Ok(())
    }

    /// Регистрирует relay-узел в локальном реестре.
    pub fn register_relay_node(&self, node_id: &str, now: i64) -> Result<(), PlexError> {
        if node_id.trim().is_empty() {
            return Err(PlexError::Storage {
                msg: "relay node_id must not be empty".into(),
            });
        }

        self.conn()?
            .execute(
                "INSERT INTO relay_nodes
                 (node_id, reputation, messages_relayed, success_count, failure_count, uptime_percent, last_heartbeat, registered_at, updated_at, is_active)
                 VALUES (?1, ?2, 0, 0, 0, 0.0, ?3, ?3, ?3, 1)
                 ON CONFLICT(node_id) DO UPDATE SET
                    is_active = 1,
                    updated_at = excluded.updated_at",
                params![node_id, crate::relay_reputation::DEFAULT_REPUTATION, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to register relay node: {e}"),
            })?;

        Ok(())
    }

    /// Обновляет heartbeat relay-узла.
    pub fn update_relay_heartbeat(&self, node_id: &str, now: i64) -> Result<(), PlexError> {
        self.conn()?
            .execute(
                "UPDATE relay_nodes
                 SET last_heartbeat = ?2,
                     updated_at = ?2,
                     is_active = 1
                 WHERE node_id = ?1",
                params![node_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to update relay heartbeat: {e}"),
            })?;

        Ok(())
    }

    /// Обновляет репутацию relay по факту успеха/ошибки.
    pub fn update_relay_reputation(
        &self,
        node_id: &str,
        success: bool,
        now: i64,
    ) -> Result<(), PlexError> {
        let mut relay = self
            .load_relay_node(node_id)?
            .ok_or_else(|| PlexError::Storage {
                msg: format!("Relay node not found: {node_id}"),
            })?;

        let elapsed = now.saturating_sub(relay.updated_at);
        let decayed = crate::relay_reputation::apply_decay(relay.reputation, elapsed);
        relay.reputation = crate::relay_reputation::score_after_event(decayed, success);
        relay.messages_relayed += 1;
        if success {
            relay.success_count += 1;
        } else {
            relay.failure_count += 1;
        }
        relay.uptime_percent =
            crate::relay_reputation::uptime_percent(relay.success_count, relay.messages_relayed);
        relay.updated_at = now;
        relay.last_heartbeat = now;

        self.conn()?
            .execute(
                "UPDATE relay_nodes
                 SET reputation = ?2,
                     messages_relayed = ?3,
                     success_count = ?4,
                     failure_count = ?5,
                     uptime_percent = ?6,
                     last_heartbeat = ?7,
                     updated_at = ?7
                 WHERE node_id = ?1",
                params![
                    node_id,
                    relay.reputation,
                    relay.messages_relayed,
                    relay.success_count,
                    relay.failure_count,
                    relay.uptime_percent,
                    now,
                ],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to update relay reputation: {e}"),
            })?;

        Ok(())
    }

    /// Деактивирует relay-узел.
    pub fn deactivate_relay_node(&self, node_id: &str, now: i64) -> Result<(), PlexError> {
        self.conn()?
            .execute(
                "UPDATE relay_nodes
                 SET is_active = 0,
                     updated_at = ?2
                 WHERE node_id = ?1",
                params![node_id, now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to deactivate relay node: {e}"),
            })?;

        Ok(())
    }

    /// Загружает relay-узел по node_id.
    pub fn load_relay_node(&self, node_id: &str) -> Result<Option<RelayNode>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT node_id, reputation, messages_relayed, success_count, failure_count, uptime_percent,
                    last_heartbeat, registered_at, updated_at, is_active
             FROM relay_nodes
             WHERE node_id = ?1",
            [node_id],
            |row| {
                Ok(RelayNode {
                    node_id: row.get(0)?,
                    reputation: row.get(1)?,
                    messages_relayed: row.get(2)?,
                    success_count: row.get(3)?,
                    failure_count: row.get(4)?,
                    uptime_percent: row.get(5)?,
                    last_heartbeat: row.get(6)?,
                    registered_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    is_active: row.get::<_, i64>(9)? != 0,
                })
            },
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Возвращает все relay-узлы.
    pub fn list_relay_nodes(&self) -> Result<Vec<RelayNode>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT node_id, reputation, messages_relayed, success_count, failure_count, uptime_percent,
                        last_heartbeat, registered_at, updated_at, is_active
                 FROM relay_nodes
                 ORDER BY reputation DESC, uptime_percent DESC, updated_at DESC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| {
                Ok(RelayNode {
                    node_id: row.get(0)?,
                    reputation: row.get(1)?,
                    messages_relayed: row.get(2)?,
                    success_count: row.get(3)?,
                    failure_count: row.get(4)?,
                    uptime_percent: row.get(5)?,
                    last_heartbeat: row.get(6)?,
                    registered_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    is_active: row.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Выбирает лучший relay по репутации, аптайму и свежести heartbeat.
    pub fn select_best_relay(
        &self,
        now: i64,
        min_reputation: i64,
        max_stale_secs: i64,
    ) -> Result<Option<RelayNode>, PlexError> {
        let relays = self.list_relay_nodes()?;

        let mut ranked = relays
            .into_iter()
            .filter(|r| r.is_active)
            .filter(|r| r.reputation >= min_reputation)
            .filter_map(|relay| {
                let age = now.saturating_sub(relay.last_heartbeat);
                if age > max_stale_secs {
                    return None;
                }
                let freshness = 1.0 - (age as f64 / max_stale_secs as f64);
                let rank = (relay.reputation as f64) * 0.65
                    + relay.uptime_percent * 0.25
                    + freshness.clamp(0.0, 1.0) * 10.0;
                Some((rank, relay))
            })
            .collect::<Vec<_>>();

        ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        Ok(ranked.into_iter().next().map(|(_, relay)| relay))
    }

    /// Публикует DHT-запись с TTL.
    pub fn publish_dht_record(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: i64,
        now: i64,
    ) -> Result<(), PlexError> {
        let expires_at = now.saturating_add(ttl_secs.max(1));

        self.conn()?
            .execute(
                "INSERT INTO dht_records (dht_key, value_blob, updated_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(dht_key) DO UPDATE SET
                    value_blob = excluded.value_blob,
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at",
                params![key, value, now, expires_at],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to publish DHT record: {e}"),
            })?;

        Ok(())
    }

    /// Ищет DHT-запись, если TTL не истек.
    pub fn lookup_dht_record(&self, key: &str, now: i64) -> Result<Option<Vec<u8>>, PlexError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT value_blob FROM dht_records
             WHERE dht_key = ?1 AND expires_at > ?2",
            params![key, now],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Возвращает guard на соединение для записи.
    /// Используй только для INSERT/UPDATE/DELETE и миграций.
    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, PlexError> {
        self.writer.lock().map_err(|e| PlexError::Storage {
            msg: format!("DB writer mutex poisoned: {e}"),
        })
    }

    /// Alias — явно указывает на write-соединение.
    #[allow(dead_code)]
    fn writer(&self) -> Result<std::sync::MutexGuard<'_, Connection>, PlexError> {
        self.conn()
    }

    /// Возвращает guard на соединение для чтения.
    /// Используй в фоновых SELECT-запросах (sync export, snapshot'ы).
    fn reader(&self) -> Result<std::sync::MutexGuard<'_, Connection>, PlexError> {
        self.reader.lock().map_err(|e| PlexError::Storage {
            msg: format!("DB reader mutex poisoned: {e}"),
        })
    }

    /// Сохраняет bytes постоянного identity-ключа iroh-узла.
    /// Ключ защищён SQLCipher (AES-256). Перезаписывается при каждом вызове.
    pub fn save_node_secret_key(&self, key_bytes: &[u8; 32]) -> Result<(), PlexError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .as_secs() as i64;

        self.conn()?
            .execute(
                "INSERT INTO node_identity (id, secret_key_bytes, created_at)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    secret_key_bytes = excluded.secret_key_bytes",
                params![&key_bytes[..], now],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save node secret key: {e}"),
            })?;
        Ok(())
    }

    /// Загружает bytes постоянного identity-ключа, если они были сохранены ранее.
    pub fn load_node_secret_key(&self) -> Result<Option<[u8; 32]>, PlexError> {
        let conn = self.reader()?;
        let result = conn
            .query_row(
                "SELECT secret_key_bytes FROM node_identity WHERE id = 1",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(bytes)
                },
            )
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        match result {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(PlexError::Storage {
                        msg: format!(
                            "Stored node secret key has wrong length: {} (expected 32)",
                            bytes.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }
}

// ── Модель данных ─────────────────────────────────────────────────────────────

/// Запись регистрации личности пира (подписывается регистратором).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityRegistration {
    pub peer_id: String,
    pub identity_commitment: Vec<u8>,
    pub registrar_node_id: String,
    pub registrar_signature: Vec<u8>,
    pub registered_at: i64,
    pub updated_at: i64,
}

/// Запись anchor в блокчейне для подтверждения состояния.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationAnchor {
    pub peer_id: String,
    pub event_hash: String,
    pub chain: String,
    pub tx_id: String,
    pub confirmations: i64,
    pub anchored_at: i64,
}

/// Публичный профиль пользователя.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicProfile {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub avatar_blob: Option<Vec<u8>>,
    pub bio: Option<String>,
    pub public_key: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Локальный контакт пользователя.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub user_id: String,
    /// Никнейм контакта (может быть пустой для старых записей).
    pub username: String,
    pub display_name: String,
    pub custom_avatar_blob: Option<Vec<u8>>,
    pub trust_level: String,
    pub added_at: i64,
}

/// Временные route hints для peer identity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRouteHint {
    pub peer_id: String,
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<String>,
    pub source: String,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub updated_at: i64,
}

/// Репутационный профиль relay-узла.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayNode {
    pub node_id: String,
    pub reputation: i64,
    pub messages_relayed: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub uptime_percent: f64,
    pub last_heartbeat: i64,
    pub registered_at: i64,
    pub updated_at: i64,
    pub is_active: bool,
}

fn current_unix_micros() -> Result<i64, PlexError> {
    let duration =
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Storage {
                msg: format!("System clock error: {e}"),
            })?;

    Ok(duration.as_micros() as i64)
}

pub(crate) fn identity_registration_signing_payload(
    peer_id: &str,
    identity_commitment: &[u8],
    registered_at: i64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        b"plex.identity.v1".len() + peer_id.len() + identity_commitment.len() + 16,
    );
    payload.extend_from_slice(b"plex.identity.v1");
    payload.extend_from_slice(peer_id.as_bytes());
    payload.extend_from_slice(identity_commitment);
    payload.extend_from_slice(&registered_at.to_le_bytes());
    payload
}

fn validate_identity_registration(record: &IdentityRegistration) -> Result<(), PlexError> {
    if record.peer_id.trim().is_empty() {
        return Err(PlexError::Storage {
            msg: "Identity registration peer_id must not be empty".into(),
        });
    }

    if record.identity_commitment.is_empty() {
        return Err(PlexError::Storage {
            msg: "Identity commitment must not be empty".into(),
        });
    }

    let registrar_key: PublicKey =
        record
            .registrar_node_id
            .parse()
            .map_err(|e| PlexError::Storage {
                msg: format!(
                    "Invalid registrar public key '{}': {e}",
                    record.registrar_node_id
                ),
            })?;

    let signature =
        Signature::from_slice(&record.registrar_signature).map_err(|e| PlexError::Storage {
            msg: format!("Invalid registrar signature bytes: {e}"),
        })?;

    let payload = identity_registration_signing_payload(
        &record.peer_id,
        &record.identity_commitment,
        record.registered_at,
    );

    registrar_key
        .verify(&payload, &signature)
        .map_err(|e| PlexError::Storage {
            msg: format!("Identity registration signature verification failed: {e}"),
        })?;

    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }

    out
}

// ── SQL миграции ──────────────────────────────────────────────────────────────

/// Миграция V2: создание `ratchet_sessions` для persistence Double Ratchet state.
const MIGRATION_V2: &str = "
CREATE TABLE IF NOT EXISTS ratchet_sessions (
    peer_id                 TEXT NOT NULL PRIMARY KEY,
    root_key_bytes          BLOB NOT NULL,
    dh_sending_secret_bytes BLOB NOT NULL,
    dh_sending_public       BLOB NOT NULL,
    dh_remote_public        BLOB,
    sending_chain_key_bytes BLOB,
    receiving_chain_key_bytes BLOB,
    ns                      INTEGER NOT NULL DEFAULT 0,
    nr                      INTEGER NOT NULL DEFAULT 0,
    pn                      INTEGER NOT NULL DEFAULT 0,
    pending_dh_ratchet      INTEGER NOT NULL DEFAULT 0,
    skipped_message_keys    BLOB NOT NULL,
    updated_at              INTEGER NOT NULL,
    created_at              INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ratchet_updated ON ratchet_sessions (updated_at);

UPDATE schema_version SET version = 2
WHERE version < 2;
";

/// Миграция V3: регистрация личности и blockchain anchor-верификации.
const MIGRATION_V3: &str = "
CREATE TABLE IF NOT EXISTS identity_registrations (
    peer_id              TEXT NOT NULL PRIMARY KEY,
    identity_commitment  BLOB NOT NULL,
    registrar_node_id    TEXT NOT NULL,
    registrar_signature  BLOB NOT NULL,
    registered_at        INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS verification_anchors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id       TEXT NOT NULL,
    event_hash    TEXT NOT NULL,
    chain         TEXT NOT NULL,
    tx_id         TEXT NOT NULL,
    confirmations INTEGER NOT NULL DEFAULT 0,
    anchored_at   INTEGER NOT NULL,
    UNIQUE(chain, tx_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_identity_updated ON identity_registrations (updated_at);
CREATE INDEX IF NOT EXISTS idx_anchor_peer_time ON verification_anchors (peer_id, anchored_at DESC);

UPDATE schema_version SET version = 3
WHERE version < 3;
";

/// Миграция V4: таблицы профилей и локальных контактов.
const MIGRATION_V4: &str = "
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_blob  BLOB,
    bio          TEXT,
    public_key   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS contacts (
    user_id            TEXT PRIMARY KEY,
    display_name       TEXT NOT NULL,
    custom_avatar_blob BLOB,
    trust_level        TEXT NOT NULL,
    added_at           INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_updated ON users(updated_at);
CREATE INDEX IF NOT EXISTS idx_contacts_added ON contacts(added_at);

UPDATE schema_version SET version = 4
WHERE version < 4;
";

/// Миграция V5: таблица репутации relay-узлов.
const MIGRATION_V5: &str = "
CREATE TABLE IF NOT EXISTS relay_nodes (
    node_id          TEXT PRIMARY KEY,
    reputation       INTEGER NOT NULL,
    messages_relayed INTEGER NOT NULL,
    success_count    INTEGER NOT NULL,
    failure_count    INTEGER NOT NULL,
    uptime_percent   REAL NOT NULL,
    last_heartbeat   INTEGER NOT NULL,
    registered_at    INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    is_active        INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE INDEX IF NOT EXISTS idx_relay_reputation ON relay_nodes(reputation DESC, uptime_percent DESC);
CREATE INDEX IF NOT EXISTS idx_relay_heartbeat ON relay_nodes(last_heartbeat DESC);

UPDATE schema_version SET version = 5
WHERE version < 5;
";

/// Миграция V11: постоянный identity-ключ iroh-узла и зашифрованные ratchet-снапшоты.
///
/// `node_identity` — одна строка (id=1), хранит 32-байтовый Ed25519 секретный ключ.
/// `ratchet_sessions_enc` — зашифрованные ChaCha20-Poly1305 снапшоты Double Ratchet.
/// Старая таблица `ratchet_sessions` остаётся для read-fallback (legacy-данные).
const MIGRATION_V11: &str = "
CREATE TABLE IF NOT EXISTS node_identity (
    id                INTEGER PRIMARY KEY DEFAULT 1 CHECK(id = 1),
    secret_key_bytes  BLOB NOT NULL,
    created_at        INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS ratchet_sessions_enc (
    peer_id             TEXT NOT NULL PRIMARY KEY,
    nonce               BLOB NOT NULL,
    snapshot_encrypted  BLOB NOT NULL,
    updated_at          INTEGER NOT NULL,
    created_at          INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ratchet_enc_updated ON ratchet_sessions_enc(updated_at DESC);

UPDATE schema_version SET version = 11
WHERE version < 11;
";

const MIGRATION_V12: &str = "
CREATE TABLE IF NOT EXISTS blocked_peers (
    peer_id    TEXT NOT NULL PRIMARY KEY,
    blocked_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_blocked_peers_at ON blocked_peers(blocked_at DESC);

UPDATE schema_version SET version = 12
WHERE version < 12;
";

/// Миграция V13: X3DH identity key, signed prekeys, one-time prekeys.
const MIGRATION_V13: &str = "
CREATE TABLE IF NOT EXISTS x3dh_identity_key (
    id         INTEGER PRIMARY KEY DEFAULT 1 CHECK(id = 1),
    ik_secret  BLOB NOT NULL,
    ik_pub     BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS x3dh_signed_prekeys (
    spk_id     INTEGER PRIMARY KEY,
    spk_secret BLOB NOT NULL,
    spk_pub    BLOB NOT NULL,
    spk_sig    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    superseded INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS x3dh_one_time_prekeys (
    opk_id     INTEGER PRIMARY KEY,
    opk_secret BLOB NOT NULL,
    opk_pub    BLOB NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_x3dh_opks_unused ON x3dh_one_time_prekeys(used, opk_id ASC);

UPDATE schema_version SET version = 13
WHERE version < 13;
";

const MIGRATION_V15: &str = "
CREATE TABLE IF NOT EXISTS peer_route_hints (
    peer_id               TEXT NOT NULL PRIMARY KEY,
    relay_url             TEXT,
    direct_addresses_json TEXT NOT NULL,
    source                TEXT NOT NULL,
    last_success_at       INTEGER,
    last_failure_at       INTEGER,
    updated_at            INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_peer_route_hints_updated ON peer_route_hints(updated_at DESC);

UPDATE schema_version SET version = 15
WHERE version < 15;
";

/// Миграция V16: добавляет username в contacts для username-first модели.
const MIGRATION_V16: &str = "
ALTER TABLE contacts ADD COLUMN username TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);

UPDATE schema_version SET version = 16
WHERE version < 16;
";

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn open_test_db() -> Db {
        use std::fs;

        let key = SecretString::new("test-key".to_string());
        let nonce = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_path = format!("plex-test-{nonce}.db");
        let _ = fs::remove_file(&db_path);

        Db::open_at_path(&db_path, &key).expect("open test db")
    }

    fn make_event(secret: &SecretKey, payload: &[u8], prev_hash: Option<String>, ts: i64) -> Event {
        let author = secret.public().to_string();
        let id = compute_event_id(&author, payload, prev_hash.as_deref(), ts);
        Event {
            id: id.clone(),
            author,
            payload: payload.to_vec(),
            signature: sign_event_id(secret, &id),
            prev_hash,
            ts,
        }
    }

    fn sample_secret_key() -> SecretKey {
        SecretKey::from_bytes(&[7u8; 32])
    }

    fn sample_event() -> Event {
        let author_secret = sample_secret_key();
        let author = author_secret.public().to_string();
        let payload = b"hello".to_vec();
        let prev_hash = Some("prev-hash".to_string());
        let ts = 123456;
        let id = compute_event_id(&author, &payload, prev_hash.as_deref(), ts);

        Event {
            id: id.clone(),
            author,
            payload,
            signature: sign_event_id(&author_secret, &id),
            prev_hash,
            ts,
        }
    }

    fn sample_registration(secret: &SecretKey, peer_id: &str) -> IdentityRegistration {
        let registrar_node_id = secret.public().to_string();
        let identity_commitment = b"peer-identity-commitment".to_vec();
        let registered_at = 1_700_000_000_i64;
        let payload =
            identity_registration_signing_payload(peer_id, &identity_commitment, registered_at);
        let registrar_signature = secret.sign(&payload).to_bytes().to_vec();

        IdentityRegistration {
            peer_id: peer_id.to_string(),
            identity_commitment,
            registrar_node_id,
            registrar_signature,
            registered_at,
            updated_at: registered_at,
        }
    }

    #[test]
    fn validate_event_accepts_consistent_hash() {
        let event = sample_event();
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn validate_event_rejects_tampered_id() {
        let mut event = sample_event();
        event.id = "tampered".into();

        let err = validate_event(&event).unwrap_err();
        assert!(matches!(err, PlexError::Storage { .. }));
    }

    #[test]
    fn validate_event_rejects_empty_author() {
        let mut event = sample_event();
        event.author.clear();
        event.id = compute_event_id(
            &event.author,
            &event.payload,
            event.prev_hash.as_deref(),
            event.ts,
        );
        event.signature.clear();

        let err = validate_event(&event).unwrap_err();
        assert!(matches!(err, PlexError::Storage { .. }));
    }

    #[test]
    fn validate_event_rejects_tampered_signature() {
        let mut event = sample_event();
        event.signature[0] ^= 0xFF;

        let err = validate_event(&event).unwrap_err();
        assert!(matches!(err, PlexError::Storage { .. }));
    }

    #[test]
    fn identity_registration_save_and_load() {
        let db = open_test_db();
        let secret = sample_secret_key();
        let record = sample_registration(&secret, "peer-alpha");

        db.save_identity_registration(&record).unwrap();
        let loaded = db
            .load_identity_registration("peer-alpha")
            .unwrap()
            .expect("record exists");

        assert_eq!(loaded.peer_id, record.peer_id);
        assert_eq!(loaded.identity_commitment, record.identity_commitment);
        assert_eq!(loaded.registrar_node_id, record.registrar_node_id);
    }

    #[test]
    fn identity_registration_rejects_tampered_signature() {
        let db = open_test_db();
        let secret = sample_secret_key();
        let mut record = sample_registration(&secret, "peer-beta");
        record.registrar_signature[0] ^= 0x01;

        let err = db.save_identity_registration(&record).unwrap_err();
        assert!(matches!(err, PlexError::Storage { .. }));
    }

    #[test]
    fn verification_anchor_save_latest_and_count() {
        let db = open_test_db();
        let peer = "peer-gamma";

        let first = VerificationAnchor {
            peer_id: peer.to_string(),
            event_hash: "h1".to_string(),
            chain: "eth-sepolia".to_string(),
            tx_id: "0xtx1".to_string(),
            confirmations: 2,
            anchored_at: 100,
        };
        let second = VerificationAnchor {
            peer_id: peer.to_string(),
            event_hash: "h2".to_string(),
            chain: "eth-sepolia".to_string(),
            tx_id: "0xtx2".to_string(),
            confirmations: 7,
            anchored_at: 200,
        };

        db.save_verification_anchor(&first).unwrap();
        db.save_verification_anchor(&second).unwrap();

        let latest = db
            .latest_verification_anchor(peer)
            .unwrap()
            .expect("latest anchor exists");
        assert_eq!(latest.tx_id, "0xtx2");
        assert_eq!(latest.event_hash, "h2");

        let count = db.verification_anchor_count(peer).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn identity_registrations_excluding_filters_known_records() {
        let db = open_test_db();
        let secret = sample_secret_key();

        let rec1 = sample_registration(&secret, "peer-1");
        let rec2 = sample_registration(&secret, "peer-2");
        let rec3 = sample_registration(&secret, "peer-3");

        db.save_identity_registration(&rec1).unwrap();
        db.save_identity_registration(&rec2).unwrap();
        db.save_identity_registration(&rec3).unwrap();

        let known = vec!["peer-2".to_string()];
        let got = db.identity_registrations_excluding(&known, 16).unwrap();
        let ids = got.into_iter().map(|r| r.peer_id).collect::<HashSet<_>>();

        assert!(ids.contains("peer-1"));
        assert!(ids.contains("peer-3"));
        assert!(!ids.contains("peer-2"));
    }

    #[test]
    fn verification_anchors_excluding_filters_known_records() {
        let db = open_test_db();

        db.save_verification_anchor(&VerificationAnchor {
            peer_id: "peer-1".into(),
            event_hash: "h1".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-1".into(),
            confirmations: 1,
            anchored_at: 11,
        })
        .unwrap();
        db.save_verification_anchor(&VerificationAnchor {
            peer_id: "peer-2".into(),
            event_hash: "h2".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-2".into(),
            confirmations: 3,
            anchored_at: 12,
        })
        .unwrap();

        let known = vec!["eth-sepolia:tx-2".to_string()];
        let got = db.verification_anchors_excluding(&known, 16).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].tx_id, "tx-1");
    }

    #[test]
    fn identity_registration_does_not_downgrade_to_older_update() {
        let db = open_test_db();
        let secret = sample_secret_key();

        let mut newer = sample_registration(&secret, "peer-delta");
        newer.identity_commitment = b"newer-commitment".to_vec();
        newer.registered_at = 200;
        newer.updated_at = 200;

        let mut older = sample_registration(&secret, "peer-delta");
        older.identity_commitment = b"older-commitment".to_vec();
        older.registered_at = 100;
        older.updated_at = 100;

        let payload_new = identity_registration_signing_payload(
            &newer.peer_id,
            &newer.identity_commitment,
            newer.registered_at,
        );
        newer.registrar_signature = secret.sign(&payload_new).to_bytes().to_vec();

        let payload_old = identity_registration_signing_payload(
            &older.peer_id,
            &older.identity_commitment,
            older.registered_at,
        );
        older.registrar_signature = secret.sign(&payload_old).to_bytes().to_vec();

        db.save_identity_registration(&newer).unwrap();
        db.save_identity_registration(&older).unwrap();

        let loaded = db
            .load_identity_registration("peer-delta")
            .unwrap()
            .expect("registration exists");
        assert_eq!(loaded.updated_at, 200);
        assert_eq!(loaded.identity_commitment, b"newer-commitment".to_vec());
    }

    #[test]
    fn verification_anchor_preserves_max_confirmations_and_newer_payload() {
        let db = open_test_db();

        let newer = VerificationAnchor {
            peer_id: "peer-epsilon".into(),
            event_hash: "h-new".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-stable".into(),
            confirmations: 12,
            anchored_at: 300,
        };
        let older_replay = VerificationAnchor {
            peer_id: "peer-epsilon".into(),
            event_hash: "h-old".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-stable".into(),
            confirmations: 3,
            anchored_at: 100,
        };

        db.save_verification_anchor(&newer).unwrap();
        db.save_verification_anchor(&older_replay).unwrap();

        let latest = db
            .latest_verification_anchor("peer-epsilon")
            .unwrap()
            .expect("anchor exists");
        assert_eq!(latest.event_hash, "h-new");
        assert_eq!(latest.confirmations, 12);
        assert_eq!(latest.anchored_at, 300);
    }

    #[test]
    fn verification_anchor_count_since_counts_recent_records() {
        let db = open_test_db();
        db.save_verification_anchor(&VerificationAnchor {
            peer_id: "peer-zeta".into(),
            event_hash: "hz1".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-z1".into(),
            confirmations: 1,
            anchored_at: 10,
        })
        .unwrap();
        db.save_verification_anchor(&VerificationAnchor {
            peer_id: "peer-zeta".into(),
            event_hash: "hz2".into(),
            chain: "eth-sepolia".into(),
            tx_id: "tx-z2".into(),
            confirmations: 1,
            anchored_at: 20,
        })
        .unwrap();

        let count_recent = db.verification_anchor_count_since("peer-zeta", 15).unwrap();
        assert_eq!(count_recent, 1);
    }

    #[test]
    fn public_profile_save_load_and_downgrade_protection() {
        let db = open_test_db();
        let newer = PublicProfile {
            user_id: "user-1".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            avatar_blob: Some(vec![1, 2, 3]),
            bio: Some("hi".into()),
            public_key: sample_secret_key().public().to_string(),
            created_at: 10,
            updated_at: 20,
        };
        let older = PublicProfile {
            user_id: "user-1".into(),
            username: "alice_old".into(),
            display_name: "Old Alice".into(),
            avatar_blob: None,
            bio: Some("old".into()),
            public_key: sample_secret_key().public().to_string(),
            created_at: 10,
            updated_at: 5,
        };

        db.save_public_profile(&newer).unwrap();
        db.save_public_profile(&older).unwrap();

        let loaded = db
            .load_public_profile("user-1")
            .unwrap()
            .expect("profile exists");
        assert_eq!(loaded.display_name, "Alice");
        assert_eq!(loaded.username, "alice");
        assert_eq!(loaded.updated_at, 20);
    }

    #[test]
    fn public_profiles_excluding_filters_known_profiles() {
        let db = open_test_db();
        let pk = sample_secret_key().public().to_string();

        db.save_public_profile(&PublicProfile {
            user_id: "u1".into(),
            username: "u1_name".into(),
            display_name: "U1".into(),
            avatar_blob: None,
            bio: None,
            public_key: pk.clone(),
            created_at: 1,
            updated_at: 1,
        })
        .unwrap();
        db.save_public_profile(&PublicProfile {
            user_id: "u2".into(),
            username: "u2_name".into(),
            display_name: "U2".into(),
            avatar_blob: None,
            bio: None,
            public_key: pk,
            created_at: 2,
            updated_at: 2,
        })
        .unwrap();

        let got = db
            .public_profiles_excluding(&["u2".to_string()], 10)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].user_id, "u1");
    }

    #[test]
    fn contacts_upsert_list_remove_roundtrip() {
        let db = open_test_db();

        db.upsert_contact(&Contact {
            user_id: "peer-1".into(),
            username: "peerone".into(),
            display_name: "Peer One".into(),
            custom_avatar_blob: Some(vec![9, 9]),
            trust_level: "Unverified".into(),
            added_at: 100,
        })
        .unwrap();

        let contacts = db.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].user_id, "peer-1");

        db.remove_contact("peer-1").unwrap();
        assert!(db.list_contacts().unwrap().is_empty());
    }

    #[test]
    fn peer_route_hint_roundtrip_and_status_updates() {
        let db = open_test_db();

        db.upsert_peer_route_hint(&PeerRouteHint {
            peer_id: "peer-1".into(),
            relay_url: Some("https://relay.example".into()),
            direct_addresses: vec!["10.0.0.5:7777".into()],
            source: "qr_import".into(),
            last_success_at: None,
            last_failure_at: None,
            updated_at: 100,
        })
        .unwrap();

        let loaded = db
            .load_peer_route_hint("peer-1")
            .unwrap()
            .expect("route hint exists");
        assert_eq!(loaded.peer_id, "peer-1");
        assert_eq!(loaded.relay_url.as_deref(), Some("https://relay.example"));
        assert_eq!(loaded.direct_addresses, vec!["10.0.0.5:7777"]);
        assert_eq!(loaded.source, "qr_import");

        db.mark_peer_route_hint_success("peer-1", 150).unwrap();
        db.mark_peer_route_hint_failure("peer-1", 175).unwrap();

        let updated = db
            .load_peer_route_hint("peer-1")
            .unwrap()
            .expect("updated route hint exists");
        assert_eq!(updated.last_success_at, Some(150));
        assert_eq!(updated.last_failure_at, Some(175));

        db.upsert_peer_route_hint(&PeerRouteHint {
            peer_id: "peer-1".into(),
            relay_url: None,
            direct_addresses: vec![],
            source: "reconnect".into(),
            last_success_at: updated.last_success_at,
            last_failure_at: updated.last_failure_at,
            updated_at: 200,
        })
        .unwrap();

        let replaced = db
            .load_peer_route_hint("peer-1")
            .unwrap()
            .expect("replaced route hint exists");
        assert_eq!(replaced.relay_url.as_deref(), Some("https://relay.example"));
        assert!(replaced.direct_addresses.is_empty());
        assert_eq!(replaced.source, "reconnect");
    }

    #[test]
    fn relay_registration_and_reputation_update() {
        let db = open_test_db();

        db.register_relay_node("relay-1", 100).unwrap();
        db.update_relay_reputation("relay-1", true, 110).unwrap();
        db.update_relay_reputation("relay-1", false, 120).unwrap();

        let relay = db
            .load_relay_node("relay-1")
            .unwrap()
            .expect("relay exists");
        assert_eq!(relay.messages_relayed, 2);
        assert_eq!(relay.success_count, 1);
        assert_eq!(relay.failure_count, 1);
        assert!(relay.reputation >= crate::relay_reputation::MIN_REPUTATION);
        assert!(relay.reputation <= crate::relay_reputation::MAX_REPUTATION);
    }

    #[test]
    fn relay_select_best_prefers_healthier_node() {
        let db = open_test_db();

        db.register_relay_node("relay-a", 100).unwrap();
        db.register_relay_node("relay-b", 100).unwrap();

        // relay-a: преимущественно успешный
        for i in 0..6 {
            db.update_relay_reputation("relay-a", true, 110 + i)
                .unwrap();
        }

        // relay-b: плохие результаты
        for i in 0..4 {
            db.update_relay_reputation("relay-b", false, 210 + i)
                .unwrap();
        }

        let best = db
            .select_best_relay(400, 0, 1_000)
            .unwrap()
            .expect("best relay selected");
        assert_eq!(best.node_id, "relay-a");
    }

    #[test]
    fn relay_deactivate_excludes_from_selection() {
        let db = open_test_db();
        db.register_relay_node("relay-x", 100).unwrap();
        db.register_relay_node("relay-y", 100).unwrap();

        db.update_relay_reputation("relay-x", true, 110).unwrap();
        db.update_relay_reputation("relay-y", true, 110).unwrap();
        db.deactivate_relay_node("relay-x", 120).unwrap();

        let best = db
            .select_best_relay(130, 0, 1_000)
            .unwrap()
            .expect("best relay selected");
        assert_eq!(best.node_id, "relay-y");
    }

    #[test]
    fn dht_publish_and_lookup_respects_ttl() {
        let db = open_test_db();
        db.publish_dht_record("username:alice", b"node-1", 10, 100)
            .unwrap();

        let hit = db.lookup_dht_record("username:alice", 105).unwrap();
        assert_eq!(hit, Some(b"node-1".to_vec()));

        let miss = db.lookup_dht_record("username:alice", 111).unwrap();
        assert!(miss.is_none());
    }

    #[test]
    fn dht_prune_and_refresh_ttl_work() {
        let db = open_test_db();
        db.publish_dht_record("k:fresh", b"v1", 30, 100).unwrap();
        db.publish_dht_record("k:old", b"v2", 5, 100).unwrap();

        let deleted = db.prune_expired_dht_records(106).unwrap();
        assert_eq!(deleted, 1);

        assert!(db.lookup_dht_record("k:old", 106).unwrap().is_none());
        assert_eq!(
            db.lookup_dht_record("k:fresh", 106).unwrap(),
            Some(b"v1".to_vec())
        );

        let refreshed = db.refresh_dht_record_ttl("k:fresh", 20, 120).unwrap();
        assert!(refreshed);

        assert_eq!(
            db.lookup_dht_record("k:fresh", 135).unwrap(),
            Some(b"v1".to_vec())
        );
        assert!(db.lookup_dht_record("k:fresh", 141).unwrap().is_none());
    }

    #[test]
    fn dht_keys_expiring_before_returns_nearest_keys() {
        let db = open_test_db();
        db.publish_dht_record("k:one", b"1", 5, 10).unwrap();
        db.publish_dht_record("k:two", b"2", 10, 10).unwrap();
        db.publish_dht_record("k:three", b"3", 20, 10).unwrap();

        let keys = db.dht_keys_expiring_before(21, 10).unwrap();
        assert_eq!(keys, vec!["k:one".to_string(), "k:two".to_string()]);
    }

    #[test]
    fn dht_records_excluding_and_import_work() {
        let db = open_test_db();
        db.publish_dht_record("k:one", b"1", 50, 100).unwrap();
        db.publish_dht_record("k:two", b"2", 50, 100).unwrap();

        let known = vec!["k:two".to_string()];
        let records = db.dht_records_excluding(&known, 10, 110).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "k:one");

        let imported = DhtRecord {
            key: "k:three".into(),
            value: b"3".to_vec(),
            updated_at: 120,
            expires_at: 170,
        };
        assert!(db.import_dht_record(&imported, 121).unwrap());
        assert_eq!(
            db.lookup_dht_record("k:three", 121).unwrap(),
            Some(b"3".to_vec())
        );
    }

    #[test]
    fn dht_import_ignores_older_update() {
        let db = open_test_db();
        db.publish_dht_record("k:stable", b"new", 50, 200).unwrap();

        let older = DhtRecord {
            key: "k:stable".into(),
            value: b"old".to_vec(),
            updated_at: 100,
            expires_at: 140,
        };

        let updated = db.import_dht_record(&older, 110).unwrap();
        assert!(!updated);
        assert_eq!(
            db.lookup_dht_record("k:stable", 120).unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn dht_cache_usage_and_eviction_candidates() {
        let db = open_test_db();
        // Публикуем три записи с разным временем
        db.publish_dht_record("k:a", b"aaa", 100, 10).unwrap(); // updated_at=10
        db.publish_dht_record("k:b", b"bb", 100, 20).unwrap(); // updated_at=20
        db.publish_dht_record("k:c", b"c", 100, 30).unwrap(); // updated_at=30

        let now = 50i64; // все три активны

        // Проверяем суммарный размер (3 + 2 + 1 = 6 байт)
        let (records, bytes) = db.dht_cache_usage(now).unwrap();
        assert_eq!(records, 3);
        assert_eq!(bytes, 6);

        // Кандидаты отсортированы oldest-first (по updated_at)
        let candidates = db.dht_eviction_candidates(now, 2).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].key, "k:a");
        assert_eq!(candidates[0].size_bytes, 3);
        assert_eq!(candidates[1].key, "k:b");

        // Подтверждаем удаление первых двух
        let deleted = db
            .dht_delete_by_keys(&["k:a".to_string(), "k:b".to_string()])
            .unwrap();
        assert_eq!(deleted, 2);

        // Осталась только k:c
        let (records2, bytes2) = db.dht_cache_usage(now).unwrap();
        assert_eq!(records2, 1);
        assert_eq!(bytes2, 1);
        assert!(db.lookup_dht_record("k:c", now).unwrap().is_some());
        assert!(db.lookup_dht_record("k:a", now).unwrap().is_none());
    }

    #[test]
    fn dht_delete_by_keys_ignores_missing() {
        let db = open_test_db();
        db.publish_dht_record("k:exists", b"v", 100, 10).unwrap();

        // Ключа "k:ghost" нет — ошибки быть не должно
        let deleted = db
            .dht_delete_by_keys(&["k:exists".to_string(), "k:ghost".to_string()])
            .unwrap();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn outbox_retry_and_ack_flow() {
        let db = open_test_db();
        let message_id = db.enqueue_outbox_message("peer-1", b"cipher", 100).unwrap();

        let pending = db.pending_outbox_messages(100, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_id, message_id);
        assert_eq!(pending[0].status, "queued");

        assert!(db
            .mark_outbox_failed(&message_id, "timeout", 140, 110)
            .unwrap());
        assert!(db.pending_outbox_messages(130, 10).unwrap().is_empty());
        assert_eq!(db.pending_outbox_messages(140, 10).unwrap().len(), 1);

        assert!(db.mark_outbox_sent(&message_id, 141).unwrap());
        assert!(db.ack_outbox_delivery("peer-1", &message_id, 150).unwrap());
        assert!(db.pending_outbox_messages(200, 10).unwrap().is_empty());
    }

    #[test]
    fn inbound_message_dedup_is_idempotent() {
        let db = open_test_db();

        let first = db
            .register_inbound_message_once("peer-2", "msg-1", 100)
            .unwrap();
        let second = db
            .register_inbound_message_once("peer-2", "msg-1", 110)
            .unwrap();

        assert!(first);
        assert!(!second);
    }

    #[test]
    fn outbox_backoff_grows_and_is_capped() {
        let db = open_test_db();
        let message_id = db.enqueue_outbox_message("peer-3", b"cipher", 100).unwrap();

        let d1 = db
            .mark_outbox_failed_with_backoff_jitter(&message_id, "e1", 2, 10, 16, 101)
            .unwrap()
            .expect("delay expected");
        let d2 = db
            .mark_outbox_failed_with_backoff_jitter(&message_id, "e2", 2, 10, 16, 102)
            .unwrap()
            .expect("delay expected");
        let d3 = db
            .mark_outbox_failed_with_backoff_jitter(&message_id, "e3", 2, 10, 16, 103)
            .unwrap()
            .expect("delay expected");
        let d4 = db
            .mark_outbox_failed_with_backoff_jitter(&message_id, "e4", 2, 10, 16, 104)
            .unwrap()
            .expect("delay expected");

        assert!((2..=3).contains(&d1));
        assert!((4..=5).contains(&d2));
        assert!((8..=9).contains(&d3));
        assert_eq!(d4, 10);
    }

    #[test]
    fn delivery_receipt_import_marks_outbox_delivered() {
        let db = open_test_db();
        let message_id = db.enqueue_outbox_message("peer-4", b"cipher", 200).unwrap();

        db.mark_outbox_failed(&message_id, "timeout", 260, 210)
            .unwrap();

        let imported = db
            .import_delivery_receipt(&DeliveryReceipt {
                message_id: message_id.clone(),
                peer_id: "peer-4".into(),
                delivered_at: 250,
            })
            .unwrap();
        assert!(imported);

        let pending = db.pending_outbox_messages(999, 10).unwrap();
        assert!(pending.iter().all(|m| m.message_id != message_id));
    }

    #[test]
    fn outbox_backoff_eventually_marks_dead() {
        let db = open_test_db();
        let message_id = db
            .enqueue_outbox_message("peer-dead", b"cipher", 10)
            .unwrap();

        for i in 0..4 {
            let _ = db
                .mark_outbox_failed_with_backoff_jitter(&message_id, "hard-fail", 1, 16, 4, 20 + i)
                .unwrap();
        }

        let pending = db.pending_outbox_messages(10_000, 10).unwrap();
        assert!(pending.iter().all(|m| m.message_id != message_id));
    }

    #[test]
    fn prune_delivery_and_dedup_removes_old_records() {
        let db = open_test_db();

        let _ = db
            .register_inbound_message_once("peer-x", "mid-1", 100)
            .unwrap();
        let message_id = db.enqueue_outbox_message("peer-x", b"cipher", 100).unwrap();
        db.ack_outbox_delivery("peer-x", &message_id, 100).unwrap();

        let pruned_dedup = db.prune_inbound_dedup_older_than(200).unwrap();
        let pruned_receipts = db.prune_delivery_receipts_older_than(200).unwrap();

        assert_eq!(pruned_dedup, 1);
        assert_eq!(pruned_receipts, 1);
    }

    #[test]
    fn frontier_prefers_longest_branch() {
        let db = open_test_db();
        let key = sample_secret_key();

        let root = make_event(&key, b"root", None, 1);
        let branch_a = make_event(&key, b"a", Some(root.id.clone()), 2);
        let branch_b = make_event(&key, b"b", Some(root.id.clone()), 3);
        let branch_a2 = make_event(&key, b"a2", Some(branch_a.id.clone()), 4);

        db.insert_events(&[
            root.clone(),
            branch_a.clone(),
            branch_b.clone(),
            branch_a2.clone(),
        ])
        .unwrap();

        let heads = db.frontier_hashes().unwrap();
        assert_eq!(heads.first().cloned(), Some(branch_a2.id));
    }

    #[test]
    fn events_with_ancestors_backfills_missing_chain() {
        let db = open_test_db();
        let key = sample_secret_key();

        let root = make_event(&key, b"root", None, 1);
        let mid = make_event(&key, b"mid", Some(root.id.clone()), 2);
        let leaf = make_event(&key, b"leaf", Some(mid.id.clone()), 3);

        db.insert_events(&[root.clone(), mid.clone(), leaf.clone()])
            .unwrap();

        let got = db
            .events_with_ancestors(std::slice::from_ref(&leaf.id), 16)
            .unwrap();
        let ids = got.into_iter().map(|e| e.id).collect::<Vec<_>>();
        assert_eq!(ids, vec![root.id, mid.id, leaf.id]);
    }

    #[test]
    fn orphan_prev_hashes_detects_gap() {
        let db = open_test_db();
        let key = sample_secret_key();
        let orphan_prev = "missing-parent".to_string();

        let event = make_event(&key, b"child", Some(orphan_prev.clone()), 42);
        db.insert_event(&event).unwrap();

        let missing = db.orphan_prev_hashes(8).unwrap();
        assert_eq!(missing, vec![orphan_prev]);
    }

    proptest! {
        #[test]
        fn prop_frontier_matches_branch_heads(
            parents in proptest::collection::vec(0u16..=511u16, 64..256),
            payload_seed in proptest::collection::vec(any::<u8>(), 64..256),
            ts_jitter in proptest::collection::vec(0u8..=9u8, 64..256),
        ) {
            let len = parents.len().min(payload_seed.len()).min(ts_jitter.len());
            prop_assume!(len >= 32);

            let db = open_test_db();
            let secret = sample_secret_key();
            let mut events: Vec<Event> = Vec::with_capacity(len);
            let mut children_count = vec![0usize; len];

            for idx in 0..len {
                let parent_idx = (parents[idx] as usize) % (idx + 1);
                let prev_hash = if idx == 0 || parent_idx == idx {
                    None
                } else {
                    Some(events[parent_idx].id.clone())
                };

                if let Some(parent) = prev_hash.as_ref() {
                    for (j, event) in events.iter().enumerate() {
                        if &event.id == parent {
                            children_count[j] += 1;
                            break;
                        }
                    }
                }

                let payload = vec![payload_seed[idx], (idx & 0xFF) as u8, ((idx >> 8) & 0xFF) as u8];
                let ts = idx as i64 * 10 + ts_jitter[idx] as i64;
                events.push(make_event(&secret, &payload, prev_hash, ts));
            }

            db.insert_events(&events).unwrap();

            let frontier = db.frontier_hashes().unwrap();
            let expected_heads = events
                .iter()
                .enumerate()
                .filter(|(i, _)| children_count[*i] == 0)
                .map(|(_, e)| e.id.clone())
                .collect::<std::collections::HashSet<_>>();

            let got_heads = frontier.iter().cloned().collect::<std::collections::HashSet<_>>();
            prop_assert_eq!(got_heads.clone(), expected_heads);

            let latest = db.latest_event_hash().unwrap();
            prop_assert!(latest.is_some());
            prop_assert!(got_heads.contains(&latest.unwrap()));
        }

        #[test]
        fn prop_events_with_ancestors_always_contains_requested_chain(
            chain_len in 16usize..128usize,
            request_count in 1usize..16usize,
        ) {
            let db = open_test_db();
            let secret = sample_secret_key();

            let mut events = Vec::with_capacity(chain_len);
            let mut prev = None;
            for i in 0..chain_len {
                let payload = vec![(i & 0xFF) as u8, 0xAA, 0x55];
                let event = make_event(&secret, &payload, prev.clone(), i as i64);
                prev = Some(event.id.clone());
                events.push(event);
            }
            db.insert_events(&events).unwrap();

            let mut need_hashes = Vec::new();
            for i in 0..request_count.min(chain_len) {
                let idx = chain_len - 1 - i;
                need_hashes.push(events[idx].id.clone());
            }

            let result = db
                .events_with_ancestors(&need_hashes, chain_len * 2)
                .unwrap();
            let result_ids = result.into_iter().map(|e| e.id).collect::<std::collections::HashSet<_>>();

            for need in &need_hashes {
                prop_assert!(result_ids.contains(need));
            }
        }
    }

    #[test]
    fn ratchet_session_save_and_load() {
        use crate::crypto::{RatchetSessionSnapshot, SkippedKeyId};

        let db = open_test_db();

        // Создаем snapshot
        let snapshot = RatchetSessionSnapshot {
            root_key_bytes: [0x01u8; 32],
            dh_sending_secret_bytes: [0x02u8; 32],
            dh_sending_public: [0x03u8; 32],
            dh_remote_public: Some([0x04u8; 32]),
            sending_chain_key_bytes: Some([0x05u8; 32]),
            receiving_chain_key_bytes: Some([0x06u8; 32]),
            ns: 5,
            nr: 3,
            pn: 2,
            pending_dh_ratchet: true,
            skipped_message_keys: vec![
                (
                    SkippedKeyId {
                        dh_pub: [0x07u8; 32],
                        n: 1,
                    },
                    [0x08u8; 32],
                ),
                (
                    SkippedKeyId {
                        dh_pub: [0x09u8; 32],
                        n: 2,
                    },
                    [0x0Au8; 32],
                ),
            ],
            peer_id: "test-peer-123".to_string(),
        };

        // Сохраняем
        db.save_ratchet_session(&snapshot).unwrap();

        // Загружаем
        let loaded = db.load_ratchet_session("test-peer-123").unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.peer_id, "test-peer-123");
        assert_eq!(loaded.root_key_bytes, [0x01u8; 32]);
        assert_eq!(loaded.ns, 5);
        assert_eq!(loaded.nr, 3);
        assert_eq!(loaded.pn, 2);
        assert_eq!(loaded.pending_dh_ratchet, true);
        assert_eq!(loaded.skipped_message_keys.len(), 2);
    }

    #[test]
    fn load_nonexistent_ratchet_session_returns_none() {
        let db = open_test_db();

        let loaded = db.load_ratchet_session("nonexistent-peer").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_all_ratchet_sessions() {
        use crate::crypto::RatchetSessionSnapshot;

        let db = open_test_db();

        // Сохраняем несколько sessions
        for i in 0..3 {
            let snapshot = RatchetSessionSnapshot {
                root_key_bytes: [i as u8; 32],
                dh_sending_secret_bytes: [i as u8; 32],
                dh_sending_public: [i as u8; 32],
                dh_remote_public: Some([i as u8; 32]),
                sending_chain_key_bytes: None,
                receiving_chain_key_bytes: None,
                ns: i as u32,
                nr: 0,
                pn: 0,
                pending_dh_ratchet: false,
                skipped_message_keys: vec![],
                peer_id: format!("peer-{}", i),
            };
            db.save_ratchet_session(&snapshot).unwrap();
        }

        // Загружаем все
        let all = db.load_all_ratchet_sessions().unwrap();
        assert_eq!(all.len(), 3);

        // Проверяем что все загрузились
        let peer_ids: Vec<_> = all.iter().map(|s| &s.peer_id).collect();
        assert!(peer_ids.contains(&&"peer-0".to_string()));
        assert!(peer_ids.contains(&&"peer-1".to_string()));
        assert!(peer_ids.contains(&&"peer-2".to_string()));
    }

    #[test]
    fn delete_ratchet_session() {
        use crate::crypto::RatchetSessionSnapshot;

        let db = open_test_db();

        let snapshot = RatchetSessionSnapshot {
            root_key_bytes: [0x01u8; 32],
            dh_sending_secret_bytes: [0x02u8; 32],
            dh_sending_public: [0x03u8; 32],
            dh_remote_public: None,
            sending_chain_key_bytes: None,
            receiving_chain_key_bytes: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_dh_ratchet: false,
            skipped_message_keys: vec![],
            peer_id: "to-delete".to_string(),
        };

        db.save_ratchet_session(&snapshot).unwrap();
        assert!(db.load_ratchet_session("to-delete").unwrap().is_some());

        db.delete_ratchet_session("to-delete").unwrap();
        assert!(db.load_ratchet_session("to-delete").unwrap().is_none());
    }
}
