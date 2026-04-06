//! `storage/projection_events.rs` — типизированные projection-события для восстановления проекций.
//!
//! Projection-события позволяют восстановить состояние projection-таблиц
//! (`identity_registrations`, `verification_anchors`, `users`, `relay_nodes`)
//! прямо из immutable `event_log` без внешних источников данных.
//!
//! ## Формат payload
//!
//! ```text
//! PLEXPJ\x01  (7 байт: magic prefix + version)
//! ||
//! serde_json(ProjectionEvent)
//! ```
//!
//! ## Жизненный цикл
//!
//! 1. Приложение явно вызывает [`Db::append_projection_event`], когда меняет
//!    важную projection-строку локально (регистрация пира, обновление профиля и т.д.).
//! 2. При аварийном восстановлении (потеря БД без потери event_log) вызывается
//!    [`Db::rebuild_projections_from_event_log`].  Метод идемпотентен: его можно
//!    вызывать многократно без побочных эффектов.
//!
//! ## Область действия
//!
//! Репроекция покрывает только те таблицы, которые участвуют в P2P-репликации:
//! `identity_registrations`, `verification_anchors`, `users`, `relay_nodes` (регистрация).
//! Локальный список контактов (`contacts`) **не** записывается в event log —
//! он является личными данными пользователя и не реплицируется между нодами.

use super::*;
use serde::{Deserialize, Serialize};

// ── Magic prefix ──────────────────────────────────────────────────────────────

/// Магический префикс payload для projection-событий.
/// 6 ASCII-байт `PLEXPJ` + version byte `\x01`.
pub(crate) const PROJECTION_PREFIX: &[u8] = b"PLEXPJ\x01";

// ── Typed event enum ──────────────────────────────────────────────────────────

/// Содержимое projection-события.
///
/// Сериализуется в JSON с полем `"type"` в snake_case.
/// Хранится в `event_log.payload` следом за [`PROJECTION_PREFIX`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProjectionEvent {
    /// Регистрация/обновление криптографической личности пира.
    IdentityRegistration {
        peer_id: String,
        /// Ed25519 commitment (raw bytes, сохраняется as JSON array).
        identity_commitment: Vec<u8>,
        registrar_node_id: String,
        /// Ed25519 подпись регистратора.
        registrar_signature: Vec<u8>,
        registered_at: i64,
        updated_at: i64,
    },

    /// On-chain anchor-верификация (запись в блокчейне).
    VerificationAnchor {
        peer_id: String,
        event_hash: String,
        chain: String,
        tx_id: String,
        confirmations: i64,
        anchored_at: i64,
    },

    /// Публичный профиль пользователя.
    PublicProfile {
        user_id: String,
        username: String,
        display_name: String,
        avatar_blob: Option<Vec<u8>>,
        bio: Option<String>,
        public_key: String,
        created_at: i64,
        updated_at: i64,
    },

    /// Регистрация relay-узла (только факт появления + метка времени).
    /// Репутационные счётчики не восстанавливаются из событий — они эфемерны.
    RelayNodeRegistered { node_id: String, registered_at: i64 },
}

// ── Rebuild report ────────────────────────────────────────────────────────────

/// Результат [`Db::rebuild_projections_from_event_log`].
#[derive(Debug, Default, Clone)]
pub struct RebuildReport {
    /// Общее число событий в event_log, которые были просмотрены.
    pub events_processed: u64,
    /// Применено записей `identity_registrations`.
    pub identity_registrations_rebuilt: u64,
    /// Применено `verification_anchors`.
    pub verification_anchors_rebuilt: u64,
    /// Применено публичных профилей (`users`).
    pub profiles_rebuilt: u64,
    /// Зарегистрировано relay-узлов.
    pub relay_nodes_rebuilt: u64,
    /// Событий без магического префикса (обычные сообщения/операции).
    pub skipped_unrecognized: u64,
}

// ── Serialization helpers ─────────────────────────────────────────────────────

/// Кодирует projection event в `payload` для `event_log`.
pub(crate) fn serialize_projection_event(event: &ProjectionEvent) -> Result<Vec<u8>, PlexError> {
    let json = serde_json::to_vec(event).map_err(|e| PlexError::Internal {
        msg: format!("Failed to serialize ProjectionEvent: {e}"),
    })?;
    let mut payload = Vec::with_capacity(PROJECTION_PREFIX.len() + json.len());
    payload.extend_from_slice(PROJECTION_PREFIX);
    payload.extend_from_slice(&json);
    Ok(payload)
}

/// Пробует распарсить `payload` как projection event.
///
/// Возвращает `None`, если payload не начинается с [`PROJECTION_PREFIX`]
/// или JSON невалиден — ошибки молча игнорируются при rebuild.
pub(crate) fn parse_projection_event(payload: &[u8]) -> Option<ProjectionEvent> {
    if !payload.starts_with(PROJECTION_PREFIX) {
        return None;
    }
    let json_bytes = &payload[PROJECTION_PREFIX.len()..];
    serde_json::from_slice(json_bytes).ok()
}

// ── Db impls ──────────────────────────────────────────────────────────────────

impl Db {
    /// Записывает typed projection event в event log.
    ///
    /// Используется при локальных мутациях projection-данных, которые должны
    /// поддерживать аварийное восстановление (не вызывать при импорте из сети,
    /// чтобы избежать дублирования событий).
    pub fn append_projection_event(
        &self,
        author_secret: &SecretKey,
        event: &ProjectionEvent,
    ) -> Result<String, PlexError> {
        let payload = serialize_projection_event(event)?;
        self.append_local_event(author_secret, &payload)
            .map(|e| e.id)
    }

    /// Перестраивает projection-таблицы из данных event_log.
    ///
    /// Сканирует ВСЕ события в хронологическом порядке (`ts ASC`).
    /// Projection-события (с magic prefix [`PROJECTION_PREFIX`]) применяются
    /// через те же idempotent upsert-методы, что и при обычных recording-операциях.
    ///
    /// ## Гарантии
    ///
    /// * **Идемпотентность**: многократный вызов не изменяет итоговое состояние.
    /// * **Безопасность при конкурентной записи**: использует `ON CONFLICT … DO UPDATE …
    ///   WHERE excluded.updated_at >= …` — более новые данные выигрывают.
    /// * **Частичные сбои**: при невалидных данных отдельного события возвращается `Err`.
    ///   Успешно применённые события к этому моменту **не** откатываются.
    pub fn rebuild_projections_from_event_log(&self) -> Result<RebuildReport, PlexError> {
        let events = self.all_events()?;
        let mut report = RebuildReport::default();

        for event in &events {
            report.events_processed += 1;

            let Some(pe) = parse_projection_event(&event.payload) else {
                report.skipped_unrecognized += 1;
                continue;
            };

            match pe {
                ProjectionEvent::IdentityRegistration {
                    peer_id,
                    identity_commitment,
                    registrar_node_id,
                    registrar_signature,
                    registered_at,
                    updated_at,
                } => {
                    let record = IdentityRegistration {
                        peer_id,
                        identity_commitment,
                        registrar_node_id,
                        registrar_signature,
                        registered_at,
                        updated_at,
                    };
                    self.save_identity_registration(&record)?;
                    report.identity_registrations_rebuilt += 1;
                }

                ProjectionEvent::VerificationAnchor {
                    peer_id,
                    event_hash,
                    chain,
                    tx_id,
                    confirmations,
                    anchored_at,
                } => {
                    let anchor = VerificationAnchor {
                        peer_id,
                        event_hash,
                        chain,
                        tx_id,
                        confirmations,
                        anchored_at,
                    };
                    self.save_verification_anchor(&anchor)?;
                    report.verification_anchors_rebuilt += 1;
                }

                ProjectionEvent::PublicProfile {
                    user_id,
                    username,
                    display_name,
                    avatar_blob,
                    bio,
                    public_key,
                    created_at,
                    updated_at,
                } => {
                    let profile = PublicProfile {
                        user_id,
                        username,
                        display_name,
                        avatar_blob,
                        bio,
                        public_key,
                        created_at,
                        updated_at,
                    };
                    self.save_public_profile(&profile)?;
                    report.profiles_rebuilt += 1;
                }

                ProjectionEvent::RelayNodeRegistered {
                    node_id,
                    registered_at,
                } => {
                    self.register_relay_node(&node_id, registered_at)?;
                    report.relay_nodes_rebuilt += 1;
                }
            }
        }

        Ok(report)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    fn open_test_db() -> Db {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("plex-projection-test-{n}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&db_path_str);
        Db::open(&db_path_str, &SecretString::new("testkey".to_string())).unwrap()
    }

    fn test_secret() -> SecretKey {
        iroh_base::SecretKey::generate(&mut rand::rngs::OsRng)
    }

    /// Создаёт валидную IdentityRegistration с правильной Ed25519-подписью.
    fn make_identity_registration(peer_id: &str) -> (IdentityRegistration, SecretKey) {
        let registrar_sk = test_secret();
        let commitment = vec![1u8, 2, 3, 4, 5];
        let registered_at = 1000i64;
        let signing_payload =
            identity_registration_signing_payload(peer_id, &commitment, registered_at);
        let sig = registrar_sk.sign(&signing_payload);
        let record = IdentityRegistration {
            peer_id: peer_id.into(),
            identity_commitment: commitment,
            registrar_node_id: registrar_sk.public().to_string(),
            registrar_signature: sig.to_bytes().to_vec(),
            registered_at,
            updated_at: 2000,
        };
        (record, registrar_sk)
    }

    /// Создаёт ProjectionEvent::IdentityRegistration из готовой записи.
    fn identity_registration_event(record: &IdentityRegistration) -> ProjectionEvent {
        ProjectionEvent::IdentityRegistration {
            peer_id: record.peer_id.clone(),
            identity_commitment: record.identity_commitment.clone(),
            registrar_node_id: record.registrar_node_id.clone(),
            registrar_signature: record.registrar_signature.clone(),
            registered_at: record.registered_at,
            updated_at: record.updated_at,
        }
    }

    // ── serialize / parse roundtrip ───────────────────────────────────────

    #[test]
    fn identity_registration_roundtrip() {
        let (record, _) = make_identity_registration("peer-1");
        let ev = identity_registration_event(&record);
        let payload = serialize_projection_event(&ev).unwrap();
        assert!(payload.starts_with(PROJECTION_PREFIX));
        let parsed = parse_projection_event(&payload).unwrap();
        let ProjectionEvent::IdentityRegistration {
            peer_id,
            registered_at,
            ..
        } = parsed
        else {
            panic!("wrong variant");
        };
        assert_eq!(peer_id, "peer-1");
        assert_eq!(registered_at, 1000);
    }

    #[test]
    fn non_projection_payload_is_none() {
        assert!(parse_projection_event(b"some random bytes").is_none());
        assert!(parse_projection_event(b"").is_none());
        // wrong prefix version
        assert!(parse_projection_event(b"PLEXPJ\x02{}").is_none());
    }

    #[test]
    fn verification_anchor_roundtrip() {
        let ev = ProjectionEvent::VerificationAnchor {
            peer_id: "peer-2".into(),
            event_hash: "abc123".into(),
            chain: "ethereum".into(),
            tx_id: "0xdeadbeef".into(),
            confirmations: 12,
            anchored_at: 5000,
        };
        let payload = serialize_projection_event(&ev).unwrap();
        let parsed = parse_projection_event(&payload).unwrap();
        let ProjectionEvent::VerificationAnchor {
            chain,
            confirmations,
            ..
        } = parsed
        else {
            panic!("wrong variant");
        };
        assert_eq!(chain, "ethereum");
        assert_eq!(confirmations, 12);
    }

    // ── rebuild_projections_from_event_log ────────────────────────────────

    #[test]
    fn rebuild_empty_log_returns_zero_report() {
        let db = open_test_db();
        let report = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(report.events_processed, 0);
        assert_eq!(report.skipped_unrecognized, 0);
    }

    #[test]
    fn rebuild_skips_non_projection_events() {
        let db = open_test_db();
        let sk = test_secret();
        db.append_local_event(&sk, b"plain message payload")
            .unwrap();
        db.append_local_event(&sk, b"another payload").unwrap();

        let report = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(report.events_processed, 2);
        assert_eq!(report.skipped_unrecognized, 2);
        assert_eq!(report.identity_registrations_rebuilt, 0);
    }

    #[test]
    fn rebuild_restores_identity_registration() {
        let db = open_test_db();
        let sk = test_secret();
        let (record, _) = make_identity_registration("peer-rebuild");
        let ev = identity_registration_event(&record);
        db.append_projection_event(&sk, &ev).unwrap();

        // Simulate projection loss by deleting the row directly.
        db.conn()
            .unwrap()
            .execute("DELETE FROM identity_registrations", [])
            .unwrap();
        assert!(db
            .load_identity_registration("peer-rebuild")
            .unwrap()
            .is_none());

        let report = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(report.identity_registrations_rebuilt, 1);
        assert_eq!(report.skipped_unrecognized, 0);
        assert!(db
            .load_identity_registration("peer-rebuild")
            .unwrap()
            .is_some());
    }

    #[test]
    fn rebuild_restores_public_profile() {
        let db = open_test_db();
        let sk = test_secret();

        let ev = ProjectionEvent::PublicProfile {
            user_id: "uid-42".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            avatar_blob: None,
            bio: Some("hello".into()),
            public_key: "pk-abc".into(),
            created_at: 50,
            updated_at: 60,
        };
        db.append_projection_event(&sk, &ev).unwrap();
        db.conn().unwrap().execute("DELETE FROM users", []).unwrap();

        let report = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(report.profiles_rebuilt, 1);
        let profile = db.load_public_profile("uid-42").unwrap().unwrap();
        assert_eq!(profile.username, "alice");
    }

    #[test]
    fn rebuild_is_idempotent() {
        let db = open_test_db();
        let sk = test_secret();
        let (record, _) = make_identity_registration("peer-idem");
        let ev = identity_registration_event(&record);
        db.append_projection_event(&sk, &ev).unwrap();

        let r1 = db.rebuild_projections_from_event_log().unwrap();
        let r2 = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(
            r1.identity_registrations_rebuilt,
            r2.identity_registrations_rebuilt
        );
        // Same row in DB — no duplicates.
        assert_eq!(db.all_identity_peer_ids().unwrap().len(), 1);
    }

    #[test]
    fn rebuild_mixed_events() {
        let db = open_test_db();
        let sk = test_secret();
        db.append_local_event(&sk, b"raw-msg-1").unwrap();

        let (record, _) = make_identity_registration("mx-peer");
        let id_ev = identity_registration_event(&record);
        db.append_projection_event(&sk, &id_ev).unwrap();

        let anchor_ev = ProjectionEvent::VerificationAnchor {
            peer_id: "mx-peer".into(),
            event_hash: "h1".into(),
            chain: "sol".into(),
            tx_id: "tx1".into(),
            confirmations: 3,
            anchored_at: 5,
        };
        db.append_projection_event(&sk, &anchor_ev).unwrap();

        db.append_local_event(&sk, b"raw-msg-2").unwrap();

        let report = db.rebuild_projections_from_event_log().unwrap();
        assert_eq!(report.events_processed, 4);
        assert_eq!(report.skipped_unrecognized, 2);
        assert_eq!(report.identity_registrations_rebuilt, 1);
        assert_eq!(report.verification_anchors_rebuilt, 1);
        assert_eq!(report.profiles_rebuilt, 0);
        assert_eq!(report.relay_nodes_rebuilt, 0);
    }
}
