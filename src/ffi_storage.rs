//! `ffi_storage.rs` — FFI-методы управления projection-событиями и аварийного восстановления.
//!
//! Содержит:
//! * [`RebuildProjectionsReport`] — отчёт о перестройке проекций (передаётся в Kotlin/Swift).
//! * Методы `record_*_event` — явная запись typed projection-события в event log.
//! * `rebuild_projections_from_event_log` — аварийная репроекция из event log.
//!
//! ## Архитектура projection recovery
//!
//! ```text
//!  Локальная мутация               Аварийное восстановление
//!  ────────────────                ────────────────────────
//!  record_*_event()                rebuild_projections_from_event_log()
//!       │                                    │
//!       ▼                                    ▼
//!  append_projection_event()        all_events() → parse_projection_event()
//!       │                                    │
//!       ▼                                    ▼
//!   event_log   ──────── source of truth ──► projection tables
//! ```
//!
//! Методы `record_*_event` следует вызывать ТОЛЬКО при **локальных** мутациях
//! (не при импорте из синхронизации), чтобы избежать дублирования событий.

use crate::{storage::ProjectionEvent, PlexError, PlexNode};

// ── FFI record ────────────────────────────────────────────────────────────────

/// Результат вызова [`PlexNode::rebuild_projections_from_event_log`].
///
/// Содержит разбивку по типам восстановленных проекций.
#[derive(Debug, uniffi::Record)]
pub struct RebuildProjectionsReport {
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
    /// Событий без magic prefix (обычные сообщения / операции) — пропущены.
    pub skipped_unrecognized: u64,
}

// ── FFI methods ───────────────────────────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    // ── Record helpers ─────────────────────────────────────────────────────

    /// Записывает projection event регистрации пира (identity registration) в event log.
    ///
    /// Вызывать при локальной регистрации или обновлении криптографической личности пира.
    /// Не вызывать при импорте данных из сетевой синхронизации.
    pub fn record_identity_registration_event(
        &self,
        peer_id: String,
        identity_commitment: Vec<u8>,
        registrar_node_id: String,
        registrar_signature: Vec<u8>,
        registered_at: i64,
        updated_at: i64,
    ) -> Result<String, PlexError> {
        let ev = ProjectionEvent::IdentityRegistration {
            peer_id,
            identity_commitment,
            registrar_node_id,
            registrar_signature,
            registered_at,
            updated_at,
        };
        self.db
            .append_projection_event(self.iroh.secret_key(), &ev)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Записывает projection event on-chain anchor-верификации в event log.
    ///
    /// Вызывать при подтверждении blockchain-транзакции, привязанной к peer_id.
    pub fn record_verification_anchor_event(
        &self,
        peer_id: String,
        event_hash: String,
        chain: String,
        tx_id: String,
        confirmations: i64,
        anchored_at: i64,
    ) -> Result<String, PlexError> {
        let ev = ProjectionEvent::VerificationAnchor {
            peer_id,
            event_hash,
            chain,
            tx_id,
            confirmations,
            anchored_at,
        };
        self.db
            .append_projection_event(self.iroh.secret_key(), &ev)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Записывает projection event публичного профиля пользователя в event log.
    ///
    /// Вызывать при создании или обновлении собственного профиля.
    #[allow(clippy::too_many_arguments)]
    pub fn record_public_profile_event(
        &self,
        user_id: String,
        username: String,
        display_name: String,
        avatar_blob: Option<Vec<u8>>,
        bio: Option<String>,
        public_key: String,
        created_at: i64,
        updated_at: i64,
    ) -> Result<String, PlexError> {
        let ev = ProjectionEvent::PublicProfile {
            user_id,
            username,
            display_name,
            avatar_blob,
            bio,
            public_key,
            created_at,
            updated_at,
        };
        self.db
            .append_projection_event(self.iroh.secret_key(), &ev)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Записывает projection event регистрации relay-узла в event log.
    ///
    /// Репутационные счётчики relay-узла не восстанавливаются — они эфемерны.
    pub fn record_relay_node_event(
        &self,
        node_id: String,
        registered_at: i64,
    ) -> Result<String, PlexError> {
        let ev = ProjectionEvent::RelayNodeRegistered {
            node_id,
            registered_at,
        };
        self.db
            .append_projection_event(self.iroh.secret_key(), &ev)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    // ── Rebuild ────────────────────────────────────────────────────────────

    /// Перестраивает projection-таблицы из immutable event log.
    ///
    /// Предназначен для аварийного восстановления: когда projection-таблицы
    /// (`identity_registrations`, `verification_anchors`, `users`, `relay_nodes`)
    /// были утеряны или повреждены, но `event_log` в целости.
    ///
    /// **Идемпотентен** — безопасно вызывать многократно.
    /// Возвращает разбивку по типам восстановленных проекций.
    pub fn rebuild_projections_from_event_log(
        &self,
    ) -> Result<RebuildProjectionsReport, PlexError> {
        let r = self.db.rebuild_projections_from_event_log()?;
        Ok(RebuildProjectionsReport {
            events_processed: r.events_processed,
            identity_registrations_rebuilt: r.identity_registrations_rebuilt,
            verification_anchors_rebuilt: r.verification_anchors_rebuilt,
            profiles_rebuilt: r.profiles_rebuilt,
            relay_nodes_rebuilt: r.relay_nodes_rebuilt,
            skipped_unrecognized: r.skipped_unrecognized,
        })
    }
}
