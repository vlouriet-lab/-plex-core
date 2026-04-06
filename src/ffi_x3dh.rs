//! `ffi_x3dh.rs` — FFI-методы X3DH key agreement для Kotlin/Swift.
//!
//! ## Типичный сценарий использования
//!
//! **Первичная настройка (Bob публикует prekey bundle):**
//! ```ignore
//! node.x3dh_publish_prekeys(20)   // генерирует IK_dh + SPK + 20 OPKs, публикует в DHT
//! ```
//!
//! **Alice инициирует сессию:**
//! ```ignore
//! let init_msg = node.x3dh_init_session(bob_node_id)  // → X3dhInitMessageRecord
//! // передаём init_msg Bob через любой транспорт (outbox, push, QR, etc.)
//! ```
//!
//! **Bob принимает сессию:**
//! ```ignore
//! node.x3dh_accept_session(init_msg)
//! // теперь оба конца имеют инициализированный Double Ratchet
//! ```
//!
//! **Ротация SPK (еженедельно рекомендуется):**
//! ```ignore
//! node.x3dh_rotate_spk()
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use iroh_base::Signature;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use crate::{crypto, x3dh, PlexError, PlexNode};

// ── FFI record types ──────────────────────────────────────────────────────────

/// Публичная часть prekey bundle — содержит всё необходимое инициатору X3DH.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PrekeyBundleRecord {
    /// Ed25519 NodeID владельца bundle (для верификации подписи SPK).
    pub node_id: String,
    /// X25519 Identity DH public key (32 байта).
    pub ik_dh_pub: Vec<u8>,
    /// ID Signed Prekey.
    pub spk_id: u32,
    /// X25519 Signed Prekey public key (32 байта).
    pub spk_pub: Vec<u8>,
    /// Ed25519 подпись SPK (64 байта).
    pub spk_signature: Vec<u8>,
    /// Unix-timestamp создания SPK.
    pub spk_created_at: i64,
    /// ID одноразового prekey (`None` если пул исчерпан).
    pub opk_id: Option<u32>,
    /// X25519 One-Time Prekey public key (32 байта, `None` если пул исчерпан).
    pub opk_pub: Option<Vec<u8>>,
}

/// Инициирующее X3DH-сообщение (Alice → Bob).
/// Передаётся через любой транспортный канал (outbox, push, QR, etc.).
#[derive(Debug, Clone, uniffi::Record)]
pub struct X3dhInitMessageRecord {
    /// NodeID инициатора.
    pub from_node_id: String,
    /// X25519 Identity DH public key инициатора (32 байта).
    pub ik_a_pub: Vec<u8>,
    /// X25519 Ephemeral key публичная часть (32 байта).
    pub ek_a_pub: Vec<u8>,
    /// ID OPK, использованного при инициализации (`None` если OPK отсутствовал).
    pub opk_id: Option<u32>,
    /// ID SPK Bob, использованного при инициализации.
    pub spk_id: u32,
}

/// Статус X3DH prekey материала локального узла.
#[derive(Debug, Clone, uniffi::Record)]
pub struct X3dhPrekeyStatsRecord {
    /// `true` если X25519 identity DH ключ создан и хранится в БД.
    pub has_identity_key: bool,
    /// `true` если есть активный (не superseded) Signed Prekey.
    pub has_active_spk: bool,
    /// ID активного SPK (`None` если нет).
    pub spk_id: Option<u32>,
    /// Unix-timestamp создания активного SPK.
    pub spk_created_at: Option<i64>,
    /// Количество неиспользованных OPK в пуле.
    pub remaining_opk_count: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bundle_to_record(bundle: &x3dh::PrekeyBundle) -> PrekeyBundleRecord {
    PrekeyBundleRecord {
        node_id: bundle.node_id.clone(),
        ik_dh_pub: bundle.ik_dh_pub.to_vec(),
        spk_id: bundle.spk_id,
        spk_pub: bundle.spk_pub.to_vec(),
        spk_signature: bundle.spk_signature.clone(),
        spk_created_at: bundle.spk_created_at,
        opk_id: bundle.opk_id,
        opk_pub: bundle.opk_pub.map(|p| p.to_vec()),
    }
}

fn record_to_init_msg(r: &X3dhInitMessageRecord) -> Result<x3dh::X3dhInitMessage, PlexError> {
    let ik_a_pub: [u8; 32] =
        r.ik_a_pub
            .as_slice()
            .try_into()
            .map_err(|_| PlexError::Validation {
                msg: "ik_a_pub must be exactly 32 bytes".into(),
            })?;
    let ek_a_pub: [u8; 32] =
        r.ek_a_pub
            .as_slice()
            .try_into()
            .map_err(|_| PlexError::Validation {
                msg: "ek_a_pub must be exactly 32 bytes".into(),
            })?;
    Ok(x3dh::X3dhInitMessage {
        from_node_id: r.from_node_id.clone(),
        ik_a_pub,
        ek_a_pub,
        opk_id: r.opk_id,
        spk_id: r.spk_id,
    })
}

fn unix_now() -> Result<i64, PlexError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

impl PlexNode {
    /// Генерирует новый SPK, подписывает его iroh NodeID, сохраняет в БД.
    /// Возвращает `(spk_id, spk_secret_bytes, spk_pub, sig, created_at)`.
    #[allow(clippy::type_complexity)]
    fn generate_and_save_spk(
        &self,
        now: i64,
    ) -> Result<(u32, [u8; 32], [u8; 32], Vec<u8>, i64), PlexError> {
        let next_id = self.db.x3dh_next_spk_id()?;

        let spk_secret = StaticSecret::random_from_rng(OsRng);
        let spk_pub = X25519Pub::from(&spk_secret).to_bytes();

        let payload = x3dh::spk_signing_payload(&spk_pub, next_id);
        let sig = self.iroh.secret_key().sign(&payload).to_bytes().to_vec();

        let spk_id =
            self.db
                .x3dh_save_spk(next_id, spk_secret.to_bytes(), spk_pub, sig.clone(), now)?;

        Ok((spk_id, spk_secret.to_bytes(), spk_pub, sig, now))
    }

    /// Строит prekey bundle и публикует его в DHT.
    /// Возвращает `PrekeyBundleRecord`.
    fn build_and_publish_bundle(
        &self,
        ik_dh_pub: [u8; 32],
        spk_id: u32,
        spk_pub: [u8; 32],
        spk_sig: Vec<u8>,
        spk_created_at: i64,
        now: i64,
    ) -> Result<PrekeyBundleRecord, PlexError> {
        let node_id = self.iroh.node_id().to_string();
        let (opk_id, opk_pub) = match self.db.x3dh_get_oldest_unused_opk()? {
            Some((id, pub_key)) => (Some(id), Some(pub_key)),
            None => (None, None),
        };

        let bundle = x3dh::PrekeyBundle {
            node_id: node_id.clone(),
            ik_dh_pub,
            spk_id,
            spk_pub,
            spk_signature: spk_sig,
            spk_created_at,
            opk_id,
            opk_pub,
        };

        let bundle_json = serde_json::to_vec(&bundle).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize prekey bundle: {e}"),
        })?;

        let dht_key = format!("{}{}", x3dh::PREKEY_BUNDLE_DHT_PREFIX, node_id);
        self.db
            .publish_dht_record(&dht_key, &bundle_json, x3dh::PREKEY_BUNDLE_TTL_SECS, now)?;

        tracing::debug!(spk_id, opk_id = ?opk_id, "X3DH prekey bundle published to DHT");

        Ok(bundle_to_record(&bundle))
    }
}

// ── #[uniffi::export] impl PlexNode ──────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    /// Гарантирует наличие X3DH identity key и активного SPK, добавляет `opk_count` новых OPK,
    /// и публикует актуальный prekey bundle в DHT.
    ///
    /// Вызывать при первом запуске и при пополнении пула OPK.
    /// `opk_count` — количество новых OPK для добавления (1..=100).
    pub fn x3dh_publish_prekeys(&self, opk_count: u32) -> Result<PrekeyBundleRecord, PlexError> {
        if opk_count == 0 || opk_count > 100 {
            return Err(PlexError::Validation {
                msg: format!("opk_count must be in 1..=100, got {opk_count}"),
            });
        }

        let now = unix_now()?;

        // 1. IK_dh: загружаем или создаём.
        let (ik_secret, ik_dh_pub) = self.db.x3dh_load_or_create_identity_key()?;
        drop(ik_secret); // публичный ключ получен, секрет не нужен здесь

        // 2. SPK: берём активный или генерируем новый.
        let (spk_id, spk_pub, spk_sig, spk_created_at) = match self.db.x3dh_get_active_spk()? {
            Some((id, _secret, pub_key, sig, created_at)) => (id, pub_key, sig, created_at),
            None => {
                let (id, _secret, pub_key, sig, created_at) = self.generate_and_save_spk(now)?;
                (id, pub_key, sig, created_at)
            }
        };

        // 3. Добавляем новые OPK.
        let mut opk_items = Vec::with_capacity(opk_count as usize);
        for _ in 0..opk_count {
            let opk_secret = StaticSecret::random_from_rng(OsRng);
            let opk_pub = X25519Pub::from(&opk_secret).to_bytes();
            opk_items.push((opk_secret.to_bytes(), opk_pub));
        }
        self.db.x3dh_add_opks(opk_items)?;

        // 4. Строим и публикуем bundle.
        self.build_and_publish_bundle(ik_dh_pub, spk_id, spk_pub, spk_sig, spk_created_at, now)
    }

    /// Возвращает статус X3DH prekey материала локального узла.
    pub fn x3dh_prekey_stats(&self) -> Result<X3dhPrekeyStatsRecord, PlexError> {
        // Проверяем наличие IK.
        let has_identity_key = {
            let (key, _pub) = self.db.x3dh_load_or_create_identity_key()?;
            drop(key);
            true
        };

        // Статус SPK.
        let (has_active_spk, spk_id, spk_created_at) = match self.db.x3dh_get_active_spk()? {
            Some((id, _secret, _pub, _sig, created_at)) => (true, Some(id), Some(created_at)),
            None => (false, None, None),
        };

        let remaining_opk_count = self.db.x3dh_remaining_opk_count()?;

        Ok(X3dhPrekeyStatsRecord {
            has_identity_key,
            has_active_spk,
            spk_id,
            spk_created_at,
            remaining_opk_count,
        })
    }

    /// Ищет prekey bundle пира в DHT и возвращает его.
    ///
    /// Возвращает `None` если bundle не найден или истёк его TTL.
    /// **Не верифицирует подпись SPK** — для верификации используй `x3dh_init_session`.
    pub fn x3dh_lookup_bundle(
        &self,
        peer_node_id: String,
    ) -> Result<Option<PrekeyBundleRecord>, PlexError> {
        if peer_node_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "peer_node_id must not be empty".into(),
            });
        }

        let now = unix_now()?;
        let dht_key = format!("{}{}", x3dh::PREKEY_BUNDLE_DHT_PREFIX, peer_node_id);

        let Some(bundle_bytes) = self.db.lookup_dht_record(&dht_key, now)? else {
            return Ok(None);
        };

        let bundle: x3dh::PrekeyBundle =
            serde_json::from_slice(&bundle_bytes).map_err(|e| PlexError::Internal {
                msg: format!("Failed to deserialize prekey bundle: {e}"),
            })?;

        Ok(Some(bundle_to_record(&bundle)))
    }

    /// **Сторона Alice**: полный X3DH initiator flow.
    ///
    /// 1. Загружает bundle Bob из DHT.
    /// 2. Верифицирует подпись SPK через NodeID Bob (Ed25519).
    /// 3. Загружает локальный IK_dh.
    /// 4. Вычисляет X3DH → `master_secret`.
    /// 5. Инициализирует Double Ratchet-сессию как инициатор.
    ///
    /// Возвращает `X3dhInitMessageRecord`, который нужно передать Bob
    /// (через outbox, push, mesh, etc.).
    pub fn x3dh_init_session(
        &self,
        peer_node_id: String,
    ) -> Result<X3dhInitMessageRecord, PlexError> {
        if peer_node_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "peer_node_id must not be empty".into(),
            });
        }

        let now = unix_now()?;
        let dht_key = format!("{}{}", x3dh::PREKEY_BUNDLE_DHT_PREFIX, peer_node_id);

        // 1. Загружаем bundle из DHT.
        let bundle_bytes =
            self.db
                .lookup_dht_record(&dht_key, now)?
                .ok_or_else(|| PlexError::NotFound {
                    msg: format!("No prekey bundle found for peer '{peer_node_id}'"),
                })?;

        let bundle: x3dh::PrekeyBundle =
            serde_json::from_slice(&bundle_bytes).map_err(|e| PlexError::Internal {
                msg: format!("Failed to deserialize prekey bundle for '{peer_node_id}': {e}"),
            })?;

        // 2. Верифицируем подпись SPK → аутентификация связки «NodeID ↔ SPK».
        let peer_key =
            peer_node_id
                .parse::<iroh_base::PublicKey>()
                .map_err(|e| PlexError::Crypto {
                    msg: format!("Invalid peer node_id '{peer_node_id}': {e}"),
                })?;
        let signing_payload = x3dh::spk_signing_payload(&bundle.spk_pub, bundle.spk_id);
        let sig = Signature::from_slice(&bundle.spk_signature).map_err(|e| PlexError::Crypto {
            msg: format!("Invalid SPK signature bytes: {e}"),
        })?;
        peer_key
            .verify(&signing_payload, &sig)
            .map_err(|_| PlexError::Crypto {
                msg: format!(
                    "SPK signature verification failed for peer '{peer_node_id}' (spk_id={})",
                    bundle.spk_id
                ),
            })?;

        // 3. Загружаем наш IK_dh.
        let (ik_a_secret, ik_a_pub) = self.db.x3dh_load_or_create_identity_key()?;

        // 4. X3DH initiator.
        let (master_bytes, mut init_msg) = x3dh::x3dh_initiate(&ik_a_secret, ik_a_pub, &bundle)?;
        init_msg.from_node_id = self.iroh.node_id().to_string();

        // 5. Инициализируем Double Ratchet-сессию.
        let master_key = crypto::SymmetricKey::from_bytes(master_bytes.to_vec())?;
        let session = crypto::RatchetSession::new_initiator(
            peer_node_id.clone(),
            master_key,
            bundle.spk_pub,
        )?;

        let snapshot = session.to_snapshot();
        self.db.save_ratchet_session(&snapshot)?;
        self.ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?
            .insert(peer_node_id.clone(), session);

        tracing::debug!(
            peer_node_id = %peer_node_id,
            spk_id = bundle.spk_id,
            opk_id = ?init_msg.opk_id,
            "X3DH session initiated"
        );

        Ok(X3dhInitMessageRecord {
            from_node_id: init_msg.from_node_id,
            ik_a_pub: init_msg.ik_a_pub.to_vec(),
            ek_a_pub: init_msg.ek_a_pub.to_vec(),
            opk_id: init_msg.opk_id,
            spk_id: init_msg.spk_id,
        })
    }

    /// **Сторона Bob**: полный X3DH responder flow.
    ///
    /// 1. Загружает локальный IK_dh.
    /// 2. Загружает SPK по `init_msg.spk_id` (включая superseded).
    /// 3. Если `opk_id` задан — потребляет соответствующий OPK.
    /// 4. Вычисляет X3DH → `master_secret`.
    /// 5. Инициализирует Double Ratchet-сессию как ответчик (с SPK как ratchet ключом).
    pub fn x3dh_accept_session(&self, init_msg: X3dhInitMessageRecord) -> Result<(), PlexError> {
        if init_msg.from_node_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "from_node_id must not be empty".into(),
            });
        }

        let internal_msg = record_to_init_msg(&init_msg)?;
        let peer_id = init_msg.from_node_id.clone();

        // 1. Наш IK_dh.
        let (ik_b_secret, _ik_b_pub) = self.db.x3dh_load_or_create_identity_key()?;

        // 2. Загружаем SPK по ID.
        let (spk_b_secret, _spk_b_pub) = self
            .db
            .x3dh_get_spk_by_id(internal_msg.spk_id)?
            .ok_or_else(|| PlexError::NotFound {
                msg: format!(
                    "SPK with id={} not found (may have been rotated too aggressively)",
                    internal_msg.spk_id
                ),
            })?;

        // 3. Потребляем OPK (если использовался).
        let opk_secret_bytes = if let Some(opk_id) = internal_msg.opk_id {
            self.db.x3dh_consume_opk(opk_id)?
            // Если OPK не найден (уже использован или не существует) — продолжаем без него.
            // Это может означать атаку на повторное использование OPK или race condition.
            // В продакшне стоит залогировать предупреждение.
        } else {
            None
        };
        // Предупреждение если OPK был заявлен, но не найден.
        if internal_msg.opk_id.is_some() && opk_secret_bytes.is_none() {
            tracing::warn!(
                opk_id = ?internal_msg.opk_id,
                peer = %peer_id,
                "[security] X3DH accept: claimed OPK not found or already used — proceeding without OPK"
            );
        }

        // 4. X3DH responder.
        let master_bytes = x3dh::x3dh_respond(
            &ik_b_secret,
            &spk_b_secret,
            opk_secret_bytes.as_ref(),
            &internal_msg,
        )?;

        // 5. Инициализируем Double Ratchet как ответчик с SPK_B в роли ratchet ключа.
        let master_key = crypto::SymmetricKey::from_bytes(master_bytes.to_vec())?;
        let session = crypto::RatchetSession::new_responder_with_ratchet_key(
            peer_id.clone(),
            master_key,
            spk_b_secret,
        );

        let snapshot = session.to_snapshot();
        self.db.save_ratchet_session(&snapshot)?;
        self.ratchet_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Ratchet mutex poisoned: {e}"),
            })?
            .insert(peer_id.clone(), session);

        tracing::debug!(
            peer = %peer_id,
            spk_id = internal_msg.spk_id,
            "X3DH session accepted"
        );

        Ok(())
    }

    /// Генерирует новый SPK (ротация), добавляет `opk_count` новых OPK и
    /// публикует обновлённый prekey bundle в DHT.
    ///
    /// Старый SPK сохраняется в БД для обработки in-flight сессий.
    /// `opk_count` — количество новых OPK (1..=100).
    pub fn x3dh_rotate_spk(&self, opk_count: u32) -> Result<PrekeyBundleRecord, PlexError> {
        if opk_count == 0 || opk_count > 100 {
            return Err(PlexError::Validation {
                msg: format!("opk_count must be in 1..=100, got {opk_count}"),
            });
        }

        let now = unix_now()?;

        // Загружаем IK_dh (должен уже существовать — rotate_spk вызывается после publish).
        let (ik_secret, ik_dh_pub) = self.db.x3dh_load_or_create_identity_key()?;
        drop(ik_secret);

        // Генерируем новый SPK (предыдущий будет помечен superseded).
        let (spk_id, _spk_secret, spk_pub, sig, spk_created_at) =
            self.generate_and_save_spk(now)?;

        // Добавляем новые OPK.
        let mut opk_items = Vec::with_capacity(opk_count as usize);
        for _ in 0..opk_count {
            let opk_secret = StaticSecret::random_from_rng(OsRng);
            let opk_pub_key = X25519Pub::from(&opk_secret).to_bytes();
            opk_items.push((opk_secret.to_bytes(), opk_pub_key));
        }
        self.db.x3dh_add_opks(opk_items)?;

        tracing::debug!(spk_id, "X3DH SPK rotated");

        // Строим и публикуем bundle.
        self.build_and_publish_bundle(ik_dh_pub, spk_id, spk_pub, sig, spk_created_at, now)
    }
}
