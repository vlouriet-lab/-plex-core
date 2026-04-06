//! `x3dh.rs` — Extended Triple Diffie-Hellman (X3DH).
//!
//! Реализует протокол X3DH согласно спецификации Signal:
//! <https://signal.org/docs/specifications/x3dh/>
//!
//! ## Особенности реализации
//!
//! * **IK_dh** (Identity DH key) — отдельный X25519-ключ, хранящийся в SQLCipher.
//!   НЕ путать с iroh Ed25519 NodeID — тот используется **только** для подписи SPK.
//! * **SPK** (Signed Prekey) служит двойной роли: X3DH-ключ и первый ratchet DH-ключ.
//! * **OPK** (One-Time Prekeys) — best-effort; после использования помечаются `used=1`.

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};
use zeroize::Zeroize;

use crate::PlexError;

// ── Константы ─────────────────────────────────────────────────────────────────

/// Префикс DHT-ключа для prekey bundle: `plex/prekeys/v1/{node_id}`.
pub const PREKEY_BUNDLE_DHT_PREFIX: &str = "plex/prekeys/v1/";

/// TTL prekey bundle в секундах (30 дней).
/// Передаётся напрямую в `db.publish_dht_record` (минуя FFI-валидацию MAX_DHT_TTL_SECS).
pub const PREKEY_BUNDLE_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Количество OPK, генерируемых по умолчанию за один вызов `x3dh_publish_prekeys`.
#[allow(dead_code)]
pub const DEFAULT_OPK_COUNT: u32 = 20;

/// Минимальный запас OPK; при достижении рекомендуется пополнить пул.
#[allow(dead_code)]
pub const LOW_OPK_THRESHOLD: u32 = 5;

/// Контекстная метка X3DH KDF.
const X3DH_KDF_INFO: &[u8] = b"plex/x3dh/v1";

/// Контекстная метка подписи SPK (защищает от кросс-контекстного повторного использования).
pub const SPK_SIG_CONTEXT: &[u8] = b"plex/spk-sig/v1";

// ── Типы ──────────────────────────────────────────────────────────────────────

/// Prekey bundle, публикуемый в DHT.
/// Содержит все публичные ключи, необходимые инициатору для X3DH.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBundle {
    /// Ed25519 NodeID владельца (для верификации подписи SPK).
    pub node_id: String,
    /// X25519 Identity DH public key (IK_dh_pub).
    pub ik_dh_pub: [u8; 32],
    /// ID активного Signed Prekey.
    pub spk_id: u32,
    /// X25519 Signed Prekey public key (SPK_pub).
    pub spk_pub: [u8; 32],
    /// Ed25519 подпись: `SPK_SIG_CONTEXT || spk_pub || spk_id_le_bytes`.
    pub spk_signature: Vec<u8>,
    /// Unix-timestamp создания SPK (для проверки актуальности на стороне Bob).
    pub spk_created_at: i64,
    /// ID одноразового prekey (`None` если пул исчерпан).
    pub opk_id: Option<u32>,
    /// X25519 One-Time Prekey public key.
    pub opk_pub: Option<[u8; 32]>,
}

/// Инициирующее X3DH-сообщение от Alice (инициатора) к Bob (ответчику).
/// Передаётся по любому транспортному каналу (outbox, mesh, PUSH, etc.).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct X3dhInitMessage {
    /// NodeID инициатора (Alice).
    pub from_node_id: String,
    /// X25519 IK_A_dh_pub инициатора.
    pub ik_a_pub: [u8; 32],
    /// X25519 ephemeral key (EK_A) публичная часть.
    pub ek_a_pub: [u8; 32],
    /// ID использованного OPK Bob (`None` если OPK не использовался).
    pub opk_id: Option<u32>,
    /// ID SPK Bob, использованного при инициализации (Bob выбирает нужный секрет).
    pub spk_id: u32,
}

// ── Вспомогательные функции ───────────────────────────────────────────────────

/// Формирует байтовый payload для подписи SPK через Ed25519 NodeID.
///
/// Формат: `SPK_SIG_CONTEXT || spk_pub[32] || spk_id_le[4]`
pub fn spk_signing_payload(spk_pub: &[u8; 32], spk_id: u32) -> Vec<u8> {
    let mut v = SPK_SIG_CONTEXT.to_vec();
    v.extend_from_slice(spk_pub);
    v.extend_from_slice(&spk_id.to_le_bytes());
    v
}

/// X3DH KDF: `HKDF-SHA256(F || DH1 || DH2 || DH3 [|| DH4], info="plex/x3dh/v1")`.
///
/// `F = 0xFF * 32` — domain separation constant согласно Signal X3DH spec §2.2.
pub fn x3dh_kdf(dh_concat: &[u8]) -> Result<[u8; 32], PlexError> {
    let f = [0xFFu8; 32];
    let ikm: Vec<u8> = f.iter().chain(dh_concat.iter()).copied().collect();
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(X3DH_KDF_INFO, &mut okm)
        .map_err(|_| PlexError::Crypto {
            msg: "X3DH KDF expand failed".into(),
        })?;
    Ok(okm)
}

/// Сторона **Alice** (инициатор) в X3DH.
///
/// Вычисляет `master_secret` и формирует `X3dhInitMessage` для отправки Bob.
/// Ephemeral key `EK_A` уничтожается после вычислений (ZeroizeOnDrop).
///
/// # Аргументы
/// * `ik_a_secret` — X25519 секретный Identity DH ключ Alice.
/// * `ik_a_pub`   — соответствующий публичный ключ (включается в init message).
/// * `bundle`     — prekey bundle Bob (подпись должна быть верифицирована до вызова).
pub fn x3dh_initiate(
    ik_a_secret: &StaticSecret,
    ik_a_pub: [u8; 32],
    bundle: &PrekeyBundle,
) -> Result<([u8; 32], X3dhInitMessage), PlexError> {
    let ek_a = StaticSecret::random_from_rng(OsRng);
    let ek_a_pub = X25519Pub::from(&ek_a).to_bytes();

    let ik_b = X25519Pub::from(bundle.ik_dh_pub);
    let spk_b = X25519Pub::from(bundle.spk_pub);

    let mut dh1 = ik_a_secret.diffie_hellman(&spk_b).to_bytes(); // DH(IK_A, SPK_B)
    let mut dh2 = ek_a.diffie_hellman(&ik_b).to_bytes(); // DH(EK_A, IK_B)
    let mut dh3 = ek_a.diffie_hellman(&spk_b).to_bytes(); // DH(EK_A, SPK_B)

    let mut dh_concat = Vec::with_capacity(32 * 4);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    let opk_id = if let (Some(oid), Some(opub)) = (bundle.opk_id, bundle.opk_pub) {
        let opk_b = X25519Pub::from(opub);
        let mut dh4 = ek_a.diffie_hellman(&opk_b).to_bytes(); // DH(EK_A, OPK_B)
        dh_concat.extend_from_slice(&dh4);
        dh4.zeroize();
        Some(oid)
    } else {
        None
    };

    let master = x3dh_kdf(&dh_concat)?;

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    dh_concat.zeroize();

    let init_msg = X3dhInitMessage {
        from_node_id: String::new(), // заполняется вызывающей стороной перед отправкой
        ik_a_pub,
        ek_a_pub,
        opk_id,
        spk_id: bundle.spk_id,
    };

    Ok((master, init_msg))
}

/// Сторона **Bob** (ответчик) в X3DH.
///
/// Возвращает `master_secret`, идентичный вычисленному Alice (при корректных ключах).
///
/// # Аргументы
/// * `ik_b_secret`  — X25519 секретный Identity DH ключ Bob.
/// * `spk_b_secret` — X25519 секретный Signed Prekey (тот, чей ID указан в `init_msg.spk_id`).
/// * `opk_b_secret` — секретный One-Time Prekey (`None` если OPK не использовался).
/// * `init_msg`     — инициирующее сообщение от Alice.
pub fn x3dh_respond(
    ik_b_secret: &StaticSecret,
    spk_b_secret: &StaticSecret,
    opk_b_secret: Option<&[u8; 32]>,
    init_msg: &X3dhInitMessage,
) -> Result<[u8; 32], PlexError> {
    let ik_a = X25519Pub::from(init_msg.ik_a_pub);
    let ek_a = X25519Pub::from(init_msg.ek_a_pub);

    let mut dh1 = spk_b_secret.diffie_hellman(&ik_a).to_bytes(); // DH(SPK_B, IK_A)
    let mut dh2 = ik_b_secret.diffie_hellman(&ek_a).to_bytes(); // DH(IK_B,  EK_A)
    let mut dh3 = spk_b_secret.diffie_hellman(&ek_a).to_bytes(); // DH(SPK_B, EK_A)

    let mut dh_concat = Vec::with_capacity(32 * 4);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(opk_bytes) = opk_b_secret {
        let opk_b = StaticSecret::from(*opk_bytes);
        let mut dh4 = opk_b.diffie_hellman(&ek_a).to_bytes(); // DH(OPK_B, EK_A)
        dh_concat.extend_from_slice(&dh4);
        dh4.zeroize();
    }

    let master = x3dh_kdf(&dh_concat)?;

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    dh_concat.zeroize();

    Ok(master)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x3dh_kdf_is_deterministic() {
        let input = vec![0xABu8; 128];
        let r1 = x3dh_kdf(&input).unwrap();
        let r2 = x3dh_kdf(&input).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn x3dh_kdf_is_input_sensitive() {
        let r1 = x3dh_kdf(&[0u8; 96]).unwrap();
        let r2 = x3dh_kdf(&[1u8; 96]).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn x3dh_kdf_differs_by_length() {
        let r1 = x3dh_kdf(&[0u8; 96]).unwrap();
        let r2 = x3dh_kdf(&[0u8; 128]).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn spk_signing_payload_is_unique_per_id() {
        let pub_k = [0xAAu8; 32];
        let p1 = spk_signing_payload(&pub_k, 1);
        let p2 = spk_signing_payload(&pub_k, 2);
        assert_ne!(p1, p2, "Different IDs must produce different payloads");
    }

    #[test]
    fn spk_signing_payload_is_unique_per_key() {
        let p1 = spk_signing_payload(&[0xAAu8; 32], 1);
        let p2 = spk_signing_payload(&[0xBBu8; 32], 1);
        assert_ne!(p1, p2, "Different keys must produce different payloads");
    }

    #[test]
    fn spk_signing_payload_has_correct_prefix() {
        let payload = spk_signing_payload(&[0u8; 32], 0);
        assert!(payload.starts_with(SPK_SIG_CONTEXT));
        assert_eq!(payload.len(), SPK_SIG_CONTEXT.len() + 32 + 4);
    }

    #[test]
    fn x3dh_roundtrip_with_opk() {
        let ik_a = StaticSecret::random_from_rng(OsRng);
        let ik_a_pub = X25519Pub::from(&ik_a).to_bytes();
        let ik_b = StaticSecret::random_from_rng(OsRng);
        let ik_b_pub = X25519Pub::from(&ik_b).to_bytes();
        let spk_b = StaticSecret::random_from_rng(OsRng);
        let spk_b_pub = X25519Pub::from(&spk_b).to_bytes();
        let opk_b = StaticSecret::random_from_rng(OsRng);
        let opk_b_pub = X25519Pub::from(&opk_b).to_bytes();
        let opk_b_bytes = opk_b.to_bytes();

        let bundle = PrekeyBundle {
            node_id: "test-node".into(),
            ik_dh_pub: ik_b_pub,
            spk_id: 1,
            spk_pub: spk_b_pub,
            spk_signature: vec![],
            spk_created_at: 0,
            opk_id: Some(42),
            opk_pub: Some(opk_b_pub),
        };

        let (master_a, init_msg) = x3dh_initiate(&ik_a, ik_a_pub, &bundle).unwrap();
        let master_b = x3dh_respond(&ik_b, &spk_b, Some(&opk_b_bytes), &init_msg).unwrap();

        assert_eq!(
            master_a, master_b,
            "X3DH master secrets must match (with OPK)"
        );
    }

    #[test]
    fn x3dh_roundtrip_no_opk() {
        let ik_a = StaticSecret::random_from_rng(OsRng);
        let ik_a_pub = X25519Pub::from(&ik_a).to_bytes();
        let ik_b = StaticSecret::random_from_rng(OsRng);
        let ik_b_pub = X25519Pub::from(&ik_b).to_bytes();
        let spk_b = StaticSecret::random_from_rng(OsRng);
        let spk_b_pub = X25519Pub::from(&spk_b).to_bytes();

        let bundle = PrekeyBundle {
            node_id: "test-node".into(),
            ik_dh_pub: ik_b_pub,
            spk_id: 7,
            spk_pub: spk_b_pub,
            spk_signature: vec![],
            spk_created_at: 0,
            opk_id: None,
            opk_pub: None,
        };

        let (master_a, init_msg) = x3dh_initiate(&ik_a, ik_a_pub, &bundle).unwrap();
        let master_b = x3dh_respond(&ik_b, &spk_b, None, &init_msg).unwrap();

        assert_eq!(
            master_a, master_b,
            "X3DH master secrets must match (no OPK)"
        );
    }

    #[test]
    fn x3dh_wrong_spk_secret_differs() {
        let ik_a = StaticSecret::random_from_rng(OsRng);
        let ik_a_pub = X25519Pub::from(&ik_a).to_bytes();
        let ik_b = StaticSecret::random_from_rng(OsRng);
        let ik_b_pub = X25519Pub::from(&ik_b).to_bytes();
        let spk_b = StaticSecret::random_from_rng(OsRng);
        let spk_b_pub = X25519Pub::from(&spk_b).to_bytes();
        let wrong_spk = StaticSecret::random_from_rng(OsRng);

        let bundle = PrekeyBundle {
            node_id: "test".into(),
            ik_dh_pub: ik_b_pub,
            spk_id: 1,
            spk_pub: spk_b_pub,
            spk_signature: vec![],
            spk_created_at: 0,
            opk_id: None,
            opk_pub: None,
        };

        let (master_a, init_msg) = x3dh_initiate(&ik_a, ik_a_pub, &bundle).unwrap();
        let master_b_wrong = x3dh_respond(&ik_b, &wrong_spk, None, &init_msg).unwrap();

        assert_ne!(
            master_a, master_b_wrong,
            "Wrong SPK must produce different master secret"
        );
    }
}
