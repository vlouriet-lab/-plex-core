//! `ffi_crypto.rs` — FFI-модуль криптографии, ratchet-сессий и event log.
//!
//! Содержит:
//! * Методы PlexNode для работы с Double Ratchet (init_initiator, init_responder,
//!   encrypt, decrypt, drop), append-only event log и KDF.
//! * Приватный хелпер `ensure_ratchet_session_loaded` (pub(crate) для ffi_outbox).

use tracing::warn;
use zeroize::Zeroize;

use crate::{crypto, PlexError, PlexNode};

// ── FFI-методы PlexNode ───────────────────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    /// Добавляет локальное событие в append-only event log.
    pub fn append_local_event(&self, payload: Vec<u8>) -> Result<String, PlexError> {
        self.db
            .append_local_event(self.iroh.secret_key(), &payload)
            .map(|event| event.id)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Шифрует payload через Double Ratchet для конкретного пира и пишет событие в лог.
    pub fn append_local_event_encrypted(
        &self,
        peer_id: String,
        plaintext: Vec<u8>,
    ) -> Result<String, PlexError> {
        let ciphertext = self.encrypt_for_peer(peer_id, plaintext)?;
        self.db
            .append_local_event(self.iroh.secret_key(), &ciphertext)
            .map(|event| event.id)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Шифрует сообщение для пира через уже инициализированную ratchet-сессию.
    pub fn encrypt_for_peer(
        &self,
        peer_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, PlexError> {
        self.ensure_ratchet_session_loaded(&peer_id)?;

        let mut sessions = self
            .ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?;

        let session = sessions
            .get_mut(&peer_id)
            .ok_or_else(|| PlexError::Crypto {
                msg: format!("Ratchet session for peer '{peer_id}' is not initialized"),
            })?;

        let ciphertext = session.encrypt(&plaintext)?;

        let snapshot = session.to_snapshot();
        drop(sessions);

        if let Err(e) = self.db.save_ratchet_session(&snapshot) {
            warn!("Failed to save ratchet session after encrypt: {}", e);
        }

        self.metrics.inc(&self.metrics.ratchet_encrypt_total);
        Ok(ciphertext)
    }

    /// Расшифровывает сообщение от пира через уже инициализированную ratchet-сессию.
    pub fn decrypt_from_peer(
        &self,
        peer_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, PlexError> {
        self.ensure_ratchet_session_loaded(&peer_id)?;

        let mut sessions = self
            .ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?;

        let session = sessions
            .get_mut(&peer_id)
            .ok_or_else(|| PlexError::Crypto {
                msg: format!("Ratchet session for peer '{peer_id}' is not initialized"),
            })?;

        let plaintext = session.decrypt(&ciphertext).map_err(|e| {
            self.metrics.inc(&self.metrics.ratchet_decrypt_errors);
            warn!(
                peer_id = %peer_id,
                "[security] ratchet decrypt failed — session may be out of sync, rekey recommended"
            );
            e
        })?;

        let snapshot = session.to_snapshot();
        drop(sessions);

        if let Err(e) = self.db.save_ratchet_session(&snapshot) {
            warn!("Failed to save ratchet session after decrypt: {}", e);
        }

        self.metrics.inc(&self.metrics.ratchet_decrypt_total);
        Ok(plaintext)
    }

    /// Возвращает хеш последнего локального события.
    pub fn latest_event_hash(&self) -> Result<Option<String>, PlexError> {
        self.db
            .latest_event_hash()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Возвращает количество событий в локальном логе.
    pub fn event_count(&self) -> Result<u64, PlexError> {
        self.db
            .all_events()
            .map(|events| events.len() as u64)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Явно инициализирует Double Ratchet-сессию как инициатор.
    ///
    /// Возвращает локальный ratchet public key, который можно передать пирy.
    pub fn ratchet_init_initiator(
        &self,
        peer_id: String,
        shared_secret: Vec<u8>,
        remote_ratchet_pub: Vec<u8>,
    ) -> Result<Vec<u8>, PlexError> {
        let key = crypto::SymmetricKey::from_bytes(shared_secret)?;
        let remote_pub: [u8; 32] =
            remote_ratchet_pub
                .try_into()
                .map_err(|_| PlexError::Validation {
                    msg: "remote_ratchet_pub must be exactly 32 bytes".into(),
                })?;

        let session = crypto::RatchetSession::new_initiator(peer_id.clone(), key, remote_pub)?;
        let local_pub = session.ratchet_public_key().to_vec();

        let snapshot = session.to_snapshot();
        self.db.save_ratchet_session(&snapshot)?;

        self.ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?
            .insert(peer_id, session);

        Ok(local_pub)
    }

    /// Явно инициализирует Double Ratchet-сессию как ответчик.
    ///
    /// Возвращает локальный ratchet public key, который нужно отдать инициатору.
    pub fn ratchet_init_responder(
        &self,
        peer_id: String,
        shared_secret: Vec<u8>,
    ) -> Result<Vec<u8>, PlexError> {
        let key = crypto::SymmetricKey::from_bytes(shared_secret)?;
        let session = crypto::RatchetSession::new_responder(peer_id.clone(), key);
        let local_pub = session.ratchet_public_key().to_vec();

        let snapshot = session.to_snapshot();
        self.db.save_ratchet_session(&snapshot)?;

        self.ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?
            .insert(peer_id, session);

        Ok(local_pub)
    }

    /// Возвращает локальный ratchet public key уже созданной сессии.
    pub fn ratchet_public_key_for_peer(&self, peer_id: String) -> Result<Vec<u8>, PlexError> {
        self.ensure_ratchet_session_loaded(&peer_id)?;

        let sessions = self
            .ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?;

        sessions
            .get(&peer_id)
            .map(|session| session.ratchet_public_key().to_vec())
            .ok_or_else(|| PlexError::Crypto {
                msg: format!("Ratchet session for peer '{peer_id}' is not initialized"),
            })
    }

    /// Удаляет ratchet-сессию из памяти и БД для указанного пира.
    pub fn ratchet_drop_session(&self, peer_id: String) -> Result<(), PlexError> {
        {
            let mut sessions = self
                .ratchet_sessions
                .lock()
                .map_err(|e| PlexError::Internal {
                    msg: format!("Ratchet mutex poisoned: {e}"),
                })?;
            sessions.remove(&peer_id);
        }

        self.db.delete_ratchet_session(&peer_id)
    }

    /// Возвращает `true` если ratchet-сессия с данным peer_id существует (в памяти или в БД).
    ///
    /// Используется мобильным слоем для определения необходимости ratchet re-key (S4).
    pub fn ratchet_session_exists(&self, peer_id: String) -> bool {
        // Проверяем кэш в памяти
        if let Ok(sessions) = self.ratchet_sessions.lock() {
            if sessions.contains_key(&peer_id) {
                return true;
            }
        }
        // Проверяем БД
        self.db
            .load_ratchet_session(&peer_id)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    /// Выводит 32-байтовый ключ из passphrase + salt через Argon2id.
    pub fn derive_db_key_from_passphrase(&self, passphrase: String, salt: Vec<u8>) -> Vec<u8> {
        let mut passphrase = passphrase;
        let key = crypto::derive_key_from_passphrase(&passphrase, &salt);
        passphrase.zeroize();
        key.expose().to_vec()
    }
}

// ── Приватные хелперы ─────────────────────────────────────────────────────────

impl PlexNode {
    /// Загружает ratchet-сессию из БД в память, если она ещё не загружена.
    pub(crate) fn ensure_ratchet_session_loaded(&self, peer_id: &str) -> Result<(), PlexError> {
        {
            let sessions = self
                .ratchet_sessions
                .lock()
                .map_err(|e| PlexError::Internal {
                    msg: format!("Ratchet mutex poisoned: {e}"),
                })?;
            if sessions.contains_key(peer_id) {
                return Ok(());
            }
        }

        let Some(snapshot) = self.db.load_ratchet_session(peer_id)? else {
            return Ok(());
        };

        let session = match crypto::RatchetSession::from_snapshot(snapshot) {
            Ok(session) => session,
            Err(error) => {
                self.db.delete_ratchet_session(peer_id)?;
                return Err(PlexError::Crypto {
                    msg: format!("Failed to restore ratchet session for peer '{peer_id}': {error}"),
                });
            }
        };

        let mut sessions = self
            .ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?;
        sessions.entry(peer_id.to_string()).or_insert(session);

        Ok(())
    }
}
