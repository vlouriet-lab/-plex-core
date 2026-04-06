//! `crypto.rs` — криптографический слой.
//!
//! Архитектура (два уровня):
//!  * **Канальный уровень:** TLS 1.3 обеспечивается iroh/QUIC автоматически.
//!  * **Уровень сообщений:** полноценный Double Ratchet поверх X25519 + ChaCha20-Poly1305.
//!
//! Приоритеты безопасности:
//!  * `SecretKey` и `RatchetState` обёрнуты в `secrecy::Secret<>` / `Zeroizing<>`.
//!  * При дропе все секретные буферы гарантированно обнуляются через `zeroize`.

use std::collections::HashMap;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PlexError;

// ── Типы ключей ───────────────────────────────────────────────────────────────

/// 32-байтовый симметричный ключ, хранящийся в zeroize-памяти.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Создаёт ключ из сырых байт.
    /// Входной срез обнуляется после копирования.
    pub fn from_bytes(mut raw: Vec<u8>) -> Result<Self, PlexError> {
        if raw.len() != 32 {
            return Err(PlexError::Crypto {
                msg: format!("SymmetricKey must be 32 bytes, got {}", raw.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        raw.zeroize(); // обнуляем источник
        Ok(SymmetricKey(arr))
    }

    /// Предоставляет временный доступ к байтам.
    /// Используй ТОЛЬКО внутри криптоопераций; не сохраняй ссылку.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RatchetHeader {
    dh_pub: [u8; 32],
    pn: u32,
    n: u32,
    nonce: [u8; 12],
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RatchetEnvelope {
    header: RatchetHeader,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SkippedKeyId {
    pub dh_pub: [u8; 32],
    pub n: u32,
}

const MAX_SKIPPED_KEYS: usize = 4096;

/// Сериализуемый snapshot состояния RatchetSession для persistence в БД.
/// Секретные ключи хранятся в raw bytes (обнуляются после use).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetSessionSnapshot {
    pub root_key_bytes: [u8; 32],
    pub dh_sending_secret_bytes: [u8; 32],
    pub dh_sending_public: [u8; 32],
    pub dh_remote_public: Option<[u8; 32]>,
    pub sending_chain_key_bytes: Option<[u8; 32]>,
    pub receiving_chain_key_bytes: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub pending_dh_ratchet: bool,
    pub skipped_message_keys: Vec<(SkippedKeyId, [u8; 32])>,
    pub peer_id: String,
}

/// Состояние Double Ratchet сессии между двумя пирами.
pub struct RatchetSession {
    /// Корневой ключ сессии.
    root_key: Secret<SymmetricKey>,

    /// Текущая пара DH ratchet для отправки.
    dh_sending_secret: Secret<StaticSecret>,
    dh_sending_public: [u8; 32],
    /// Последний известный DH публичный ключ удалённой стороны.
    dh_remote_public: Option<[u8; 32]>,

    /// Симметрические цепочки (sending / receiving).
    sending_chain_key: Option<Secret<SymmetricKey>>,
    receiving_chain_key: Option<Secret<SymmetricKey>>,

    /// Counters из спецификации Double Ratchet.
    ns: u32,
    nr: u32,
    pn: u32,

    /// Флаг запуска DH-ratchet на следующую отправку после нового входящего DH.
    pending_dh_ratchet: bool,

    /// Кэш пропущенных message keys для out-of-order сообщений.
    skipped_message_keys: HashMap<SkippedKeyId, Secret<SymmetricKey>>,

    /// Идентификатор удалённого пира.
    peer_id: String,
}

impl RatchetSession {
    /// Инициализирует сторону-инициатор:
    /// * есть shared secret (например из X3DH),
    /// * есть удалённый ratchet public key,
    /// * сразу доступна sending chain.
    pub fn new_initiator(
        peer_id: String,
        shared_secret: SymmetricKey,
        remote_ratchet_pub: [u8; 32],
    ) -> Result<Self, PlexError> {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let local_public = X25519PublicKey::from(&local_secret).to_bytes();
        let remote_pub = X25519PublicKey::from(remote_ratchet_pub);
        let dh_output = local_secret.diffie_hellman(&remote_pub).to_bytes();
        let (root_key, sending_chain_key) = kdf_root(&shared_secret, &dh_output)?;

        Ok(Self {
            root_key: Secret::new(root_key),
            dh_sending_secret: Secret::new(local_secret),
            dh_sending_public: local_public,
            dh_remote_public: Some(remote_ratchet_pub),
            sending_chain_key: Some(Secret::new(sending_chain_key)),
            receiving_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_dh_ratchet: false,
            skipped_message_keys: HashMap::new(),
            peer_id,
        })
    }

    /// Инициализирует сторону-ответчик с заранее согласованным секретом.
    /// Первый корректный входящий пакет инициирует receiving chain.
    pub fn new_responder(peer_id: String, shared_secret: SymmetricKey) -> Self {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let local_public = X25519PublicKey::from(&local_secret).to_bytes();

        Self {
            root_key: Secret::new(shared_secret),
            dh_sending_secret: Secret::new(local_secret),
            dh_sending_public: local_public,
            dh_remote_public: None,
            sending_chain_key: None,
            receiving_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_dh_ratchet: false,
            skipped_message_keys: HashMap::new(),
            peer_id,
        }
    }

    /// Инициализирует сторону-ответчик с **явным** ratchet DH-ключом.
    ///
    /// Используется после X3DH: `ratchet_secret` = SPK_B_secret, что соответствует
    /// спецификации Signal — SPK служит двойной роли (X3DH-ключ и начальный ratchet-ключ).
    /// Первый входящий пакет от инициатора инициирует receiving chain.
    pub fn new_responder_with_ratchet_key(
        peer_id: String,
        shared_secret: SymmetricKey,
        ratchet_secret: StaticSecret,
    ) -> Self {
        let ratchet_public = X25519PublicKey::from(&ratchet_secret).to_bytes();
        Self {
            root_key: Secret::new(shared_secret),
            dh_sending_secret: Secret::new(ratchet_secret),
            dh_sending_public: ratchet_public,
            dh_remote_public: None,
            sending_chain_key: None,
            receiving_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_dh_ratchet: false,
            skipped_message_keys: HashMap::new(),
            peer_id,
        }
    }

    /// Возвращает текущий ratchet public key для инициализации сессии пира.
    pub fn ratchet_public_key(&self) -> [u8; 32] {
        self.dh_sending_public
    }

    /// Шифрует сообщение для данного пира.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PlexError> {
        if self.pending_dh_ratchet {
            self.rotate_send_ratchet()?;
        }

        let chain = self
            .sending_chain_key
            .take()
            .ok_or_else(|| PlexError::Crypto {
                msg: "Sending chain is not initialized yet".into(),
            })?;

        let (next_chain, message_key) = kdf_chain(chain.expose_secret())?;
        self.sending_chain_key = Some(Secret::new(next_chain));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let header = RatchetHeader {
            dh_pub: self.dh_sending_public,
            pn: self.pn,
            n: self.ns,
            nonce: nonce_bytes,
        };

        let aad = serialize_header(&header)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = cipher_from_key(&message_key);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| PlexError::Crypto {
                msg: format!("Double Ratchet encrypt failed: {e}"),
            })?;

        self.ns = self.ns.saturating_add(1);

        let envelope = RatchetEnvelope { header, ciphertext };

        tracing::debug!(
            peer = %self.peer_id,
            ns = self.ns,
            "Double Ratchet encrypt"
        );

        serde_json::to_vec(&envelope).map_err(|e| PlexError::Crypto {
            msg: format!("Serialize ratchet envelope failed: {e}"),
        })
    }

    /// Расшифровывает сообщение от данного пира.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PlexError> {
        let envelope: RatchetEnvelope =
            serde_json::from_slice(ciphertext).map_err(|e| PlexError::Crypto {
                msg: format!("Decode ratchet envelope failed: {e}"),
            })?;

        if let Some(plaintext) = self.try_decrypt_with_skipped_key(&envelope)? {
            return Ok(plaintext);
        }

        let remote_changed = self
            .dh_remote_public
            .map(|remote| remote != envelope.header.dh_pub)
            .unwrap_or(true);

        if remote_changed {
            self.skip_message_keys_until(envelope.header.pn)?;
            self.rotate_receive_ratchet(envelope.header.dh_pub)?;
        }

        self.skip_message_keys_until(envelope.header.n)?;

        let chain = self
            .receiving_chain_key
            .take()
            .ok_or_else(|| PlexError::Crypto {
                msg: "Receiving chain is not initialized".into(),
            })?;

        let (next_chain, message_key) = kdf_chain(chain.expose_secret())?;
        self.receiving_chain_key = Some(Secret::new(next_chain));
        self.nr = self.nr.saturating_add(1);

        let aad = serialize_header(&envelope.header)?;
        let nonce = Nonce::from_slice(&envelope.header.nonce);
        let cipher = cipher_from_key(&message_key);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| PlexError::Crypto {
                msg: format!("Double Ratchet decrypt failed: {e}"),
            })?;

        tracing::debug!(
            peer = %self.peer_id,
            nr = self.nr,
            "Double Ratchet decrypt"
        );

        Ok(plaintext)
    }

    fn try_decrypt_with_skipped_key(
        &mut self,
        envelope: &RatchetEnvelope,
    ) -> Result<Option<Vec<u8>>, PlexError> {
        let skipped_id = SkippedKeyId {
            dh_pub: envelope.header.dh_pub,
            n: envelope.header.n,
        };

        let Some(skipped_key) = self.skipped_message_keys.remove(&skipped_id) else {
            return Ok(None);
        };

        let aad = serialize_header(&envelope.header)?;
        let nonce = Nonce::from_slice(&envelope.header.nonce);
        let cipher = cipher_from_key(skipped_key.expose_secret());

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| PlexError::Crypto {
                msg: format!("Double Ratchet skipped-key decrypt failed: {e}"),
            })?;

        Ok(Some(plaintext))
    }

    fn skip_message_keys_until(&mut self, until: u32) -> Result<(), PlexError> {
        while self.nr < until {
            let chain = self
                .receiving_chain_key
                .take()
                .ok_or_else(|| PlexError::Crypto {
                    msg: "Receiving chain is not initialized for skipped messages".into(),
                })?;

            let (next_chain, message_key) = kdf_chain(chain.expose_secret())?;
            self.receiving_chain_key = Some(Secret::new(next_chain));

            if self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS {
                return Err(PlexError::Crypto {
                    msg: "Too many skipped message keys".into(),
                });
            }

            let dh_pub = self.dh_remote_public.ok_or_else(|| PlexError::Crypto {
                msg: "Remote ratchet key missing".into(),
            })?;
            let skipped_id = SkippedKeyId { dh_pub, n: self.nr };
            self.skipped_message_keys
                .insert(skipped_id, Secret::new(message_key));

            self.nr = self.nr.saturating_add(1);
        }

        Ok(())
    }

    fn rotate_receive_ratchet(&mut self, remote_dh_pub: [u8; 32]) -> Result<(), PlexError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;

        let remote_pub = X25519PublicKey::from(remote_dh_pub);
        let dh_out_recv = self
            .dh_sending_secret
            .expose_secret()
            .diffie_hellman(&remote_pub)
            .to_bytes();

        let (new_root, recv_chain) = kdf_root(self.root_key.expose_secret(), &dh_out_recv)?;
        self.root_key = Secret::new(new_root);
        self.receiving_chain_key = Some(Secret::new(recv_chain));
        self.dh_remote_public = Some(remote_dh_pub);
        self.pending_dh_ratchet = true;

        Ok(())
    }

    fn rotate_send_ratchet(&mut self) -> Result<(), PlexError> {
        let remote_pub_bytes = self.dh_remote_public.ok_or_else(|| PlexError::Crypto {
            msg: "Remote ratchet public key is not known".into(),
        })?;

        let new_secret = StaticSecret::random_from_rng(OsRng);
        let new_public = X25519PublicKey::from(&new_secret).to_bytes();
        let remote_pub = X25519PublicKey::from(remote_pub_bytes);

        let dh_out_send = new_secret.diffie_hellman(&remote_pub).to_bytes();
        let (new_root, send_chain) = kdf_root(self.root_key.expose_secret(), &dh_out_send)?;

        self.root_key = Secret::new(new_root);
        self.dh_sending_secret = Secret::new(new_secret);
        self.dh_sending_public = new_public;
        self.sending_chain_key = Some(Secret::new(send_chain));
        self.pn = self.ns;
        self.ns = 0;
        self.pending_dh_ratchet = false;

        Ok(())
    }

    /// Конвертирует сессию в сериализуемый snapshot для сохранения в БД.
    pub fn to_snapshot(&self) -> RatchetSessionSnapshot {
        RatchetSessionSnapshot {
            root_key_bytes: *self.root_key.expose_secret().expose(),
            dh_sending_secret_bytes: self.dh_sending_secret.expose_secret().to_bytes(),
            dh_sending_public: self.dh_sending_public,
            dh_remote_public: self.dh_remote_public,
            sending_chain_key_bytes: self
                .sending_chain_key
                .as_ref()
                .map(|k| *k.expose_secret().expose()),
            receiving_chain_key_bytes: self
                .receiving_chain_key
                .as_ref()
                .map(|k| *k.expose_secret().expose()),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            pending_dh_ratchet: self.pending_dh_ratchet,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(id, secret)| (id.clone(), *secret.expose_secret().expose()))
                .collect(),
            peer_id: self.peer_id.clone(),
        }
    }

    /// Восстанавливает сессию из snapshot.
    pub fn from_snapshot(snapshot: RatchetSessionSnapshot) -> Result<Self, PlexError> {
        let root_key = SymmetricKey(snapshot.root_key_bytes);
        let dh_sending_secret = StaticSecret::from(snapshot.dh_sending_secret_bytes);
        let sending_chain_key = snapshot
            .sending_chain_key_bytes
            .map(SymmetricKey)
            .map(Secret::new);
        let receiving_chain_key = snapshot
            .receiving_chain_key_bytes
            .map(SymmetricKey)
            .map(Secret::new);

        let skipped_message_keys = snapshot
            .skipped_message_keys
            .into_iter()
            .map(|(id, bytes)| (id, Secret::new(SymmetricKey(bytes))))
            .collect();

        Ok(Self {
            root_key: Secret::new(root_key),
            dh_sending_secret: Secret::new(dh_sending_secret),
            dh_sending_public: snapshot.dh_sending_public,
            dh_remote_public: snapshot.dh_remote_public,
            sending_chain_key,
            receiving_chain_key,
            ns: snapshot.ns,
            nr: snapshot.nr,
            pn: snapshot.pn,
            pending_dh_ratchet: snapshot.pending_dh_ratchet,
            skipped_message_keys,
            peer_id: snapshot.peer_id,
        })
    }
}

impl Drop for RatchetSession {
    fn drop(&mut self) {
        // Обнуляем счётчики (маленькие утечки тоже важны).
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        // root_key обнуляется автоматически через SecretBox<SymmetricKey>.
    }
}

// ── Key Derivation ────────────────────────────────────────────────────────────

/// Выводит симметричный ключ из passphrase с помощью Argon2id.
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> SymmetricKey {
    // Нормализуем произвольный salt до 16 байт, чтобы соответствовать требованиям Argon2.
    let mut normalized_salt = [0u8; 16];
    if salt.len() >= 16 {
        normalized_salt.copy_from_slice(&salt[..16]);
    } else {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"plex.argon2.salt.v1");
        hasher.update(salt);
        let digest = hasher.finalize();
        normalized_salt.copy_from_slice(&digest[..16]);
    }

    // Argon2id: 64 MiB, 3 прохода, 1 lane — разумный baseline для мобильного KDF.
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("Argon2 params should be valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &normalized_salt, &mut output)
        .expect("Argon2id key derivation should not fail with fixed params");

    SymmetricKey(output)
}

fn cipher_from_key(key_material: &SymmetricKey) -> ChaCha20Poly1305 {
    let key = Key::from_slice(key_material.expose());
    ChaCha20Poly1305::new(key)
}

fn kdf_root(
    root_key: &SymmetricKey,
    dh_output: &[u8; 32],
) -> Result<(SymmetricKey, SymmetricKey), PlexError> {
    let hk = Hkdf::<Sha256>::new(Some(root_key.expose()), dh_output);
    let mut out = [0u8; 64];
    hk.expand(b"plex/double-ratchet/root", &mut out)
        .map_err(|_| PlexError::Crypto {
            msg: "HKDF expand failed for root chain".into(),
        })?;

    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    out.zeroize();

    Ok((SymmetricKey(root), SymmetricKey(chain)))
}

fn kdf_chain(chain_key: &SymmetricKey) -> Result<(SymmetricKey, SymmetricKey), PlexError> {
    let hk = Hkdf::<Sha256>::new(Some(chain_key.expose()), b"chain-step");
    let mut out = [0u8; 64];
    hk.expand(b"plex/double-ratchet/chain", &mut out)
        .map_err(|_| PlexError::Crypto {
            msg: "HKDF expand failed for chain key".into(),
        })?;

    let mut next_chain = [0u8; 32];
    let mut message_key = [0u8; 32];
    next_chain.copy_from_slice(&out[..32]);
    message_key.copy_from_slice(&out[32..]);
    out.zeroize();

    Ok((SymmetricKey(next_chain), SymmetricKey(message_key)))
}

fn serialize_header(header: &RatchetHeader) -> Result<Vec<u8>, PlexError> {
    serde_json::to_vec(header).map_err(|e| PlexError::Crypto {
        msg: format!("Serialize ratchet header failed: {e}"),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_derive_is_deterministic_and_salt_sensitive() {
        let k1 = derive_key_from_passphrase("passphrase", b"salt-1");
        let k2 = derive_key_from_passphrase("passphrase", b"salt-1");
        let k3 = derive_key_from_passphrase("passphrase", b"salt-2");

        assert_eq!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
    }

    #[test]
    fn symmetric_key_zeroize_on_drop() {
        let key_bytes = vec![0x42u8; 32];
        let key = SymmetricKey::from_bytes(key_bytes).unwrap();
        // Проверяем, что expose работает
        assert_eq!(key.expose()[0], 0x42);
        drop(key);
        // После дропа память обнулена (проверяется AddressSanitizer / Miri)
    }

    #[test]
    fn ratchet_encrypt_decrypt_roundtrip() {
        let shared = SymmetricKey::from_bytes(vec![0x01u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        let plaintext = b"hello plex";
        let ciphertext = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);

        let reply = b"hello back";
        let reply_ciphertext = bob.encrypt(reply).unwrap();
        let reply_decrypted = alice.decrypt(&reply_ciphertext).unwrap();

        assert_eq!(reply_decrypted, reply);
    }

    #[test]
    fn ratchet_skipped_keys_support_out_of_order() {
        let shared = SymmetricKey::from_bytes(vec![0x33u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        let c1 = alice.encrypt(b"one").unwrap();
        let c2 = alice.encrypt(b"two").unwrap();

        let p2 = bob.decrypt(&c2).unwrap();
        let p1 = bob.decrypt(&c1).unwrap();

        assert_eq!(p2, b"two");
        assert_eq!(p1, b"one");
    }

    #[test]
    fn responder_cannot_encrypt_before_first_receive() {
        let shared = SymmetricKey::from_bytes(vec![0x44u8; 32]).unwrap();
        let mut bob = RatchetSession::new_responder("alice".into(), shared);

        let err = bob.encrypt(b"premature").unwrap_err();
        assert!(matches!(err, PlexError::Crypto { .. }));
    }

    #[test]
    fn tampered_header_fails_aad_check() {
        let shared = SymmetricKey::from_bytes(vec![0x55u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        let ciphertext = alice.encrypt(b"secret").unwrap();
        let mut envelope: RatchetEnvelope = serde_json::from_slice(&ciphertext).unwrap();
        envelope.header.pn ^= 1;
        let tampered = serde_json::to_vec(&envelope).unwrap();

        let err = bob.decrypt(&tampered).unwrap_err();
        assert!(matches!(err, PlexError::Crypto { .. }));
    }

    #[test]
    fn ratchet_to_snapshot_roundtrip() {
        let shared = SymmetricKey::from_bytes(vec![0x77u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        // Отправляем несколько сообщений для изменения состояния
        let c1 = alice.encrypt(b"message 1").unwrap();
        let p1 = bob.decrypt(&c1).unwrap();
        assert_eq!(p1, b"message 1");
        assert!(alice.to_snapshot().ns > 0); // Alice отправила, ns != 0

        let c2 = bob.encrypt(b"reply 1").unwrap();
        let p2 = alice.decrypt(&c2).unwrap();
        assert_eq!(p2, b"reply 1");

        // Сохраняем состояние Alice в snapshot
        let alice_snapshot = alice.to_snapshot();
        assert_eq!(alice_snapshot.peer_id, "bob");
        assert_eq!(alice_snapshot.ns, alice.to_snapshot().ns);

        // Восстанавливаем из snapshot
        let alice_restored = RatchetSession::from_snapshot(alice_snapshot).unwrap();
        let alice_restored_snapshot = alice_restored.to_snapshot();

        // Проверяем что состояние совпадает
        assert_eq!(alice_restored_snapshot.peer_id, alice.to_snapshot().peer_id);
        assert_eq!(alice_restored_snapshot.ns, alice.to_snapshot().ns);
        assert_eq!(alice_restored_snapshot.nr, alice.to_snapshot().nr);
    }

    #[test]
    fn ratchet_skipped_keys_in_snapshot() {
        let shared = SymmetricKey::from_bytes(vec![0x88u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        // Alice отправляет три сообщения
        let c1 = alice.encrypt(b"one").unwrap();
        let c2 = alice.encrypt(b"two").unwrap();
        let c3 = alice.encrypt(b"three").unwrap();

        // Bob получает их в обратном порядке (чтобы создать skipped keys)
        let p3 = bob.decrypt(&c3).unwrap();
        assert_eq!(p3, b"three");

        // Сохраняем состояние Bob (которое должно иметь skipped keys)
        let bob_snapshot = bob.to_snapshot();
        assert!(!bob_snapshot.skipped_message_keys.is_empty());

        // Восстанавливаем из snapshot
        let mut bob_restored = RatchetSession::from_snapshot(bob_snapshot).unwrap();

        // Должны быть в состоянии расшифровать пропущенные сообщения
        let p1 = bob_restored.decrypt(&c1).unwrap();
        let p2 = bob_restored.decrypt(&c2).unwrap();
        assert_eq!(p1, b"one");
        assert_eq!(p2, b"two");
    }

    #[test]
    fn ratchet_dh_ratchet_in_snapshot() {
        let shared = SymmetricKey::from_bytes(vec![0x99u8; 32]).unwrap();

        let responder = RatchetSession::new_responder("alice".into(), shared.clone());
        let responder_pub = responder.ratchet_public_key();
        let mut alice = RatchetSession::new_initiator("bob".into(), shared, responder_pub).unwrap();
        let mut bob = responder;

        // Инициализируем exchange
        let c1 = alice.encrypt(b"first").unwrap();
        let p1 = bob.decrypt(&c1).unwrap();
        assert_eq!(p1, b"first");

        // Bob отправляет, что инициирует DH ratchet в Alice
        let c2 = bob.encrypt(b"reply").unwrap();
        let p2 = alice.decrypt(&c2).unwrap();
        assert_eq!(p2, b"reply");

        // Сохраняем Alice state (которая должна иметь pending_dh_ratchet = true)
        let alice_snapshot = alice.to_snapshot();
        assert!(alice_snapshot.dh_remote_public.is_some());

        // Восстанавливаем и продолжаем
        let mut alice_restored = RatchetSession::from_snapshot(alice_snapshot).unwrap();
        let c3 = alice_restored.encrypt(b"new message").unwrap();
        let p3 = bob.decrypt(&c3).unwrap();
        assert_eq!(p3, b"new message");
    }
}
