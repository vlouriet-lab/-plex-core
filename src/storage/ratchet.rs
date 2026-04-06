use super::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    ChaCha20Poly1305, Nonce as ChaNonce,
};
use rand::RngCore;
use tracing::info;

// ── Helpers шифрования ─────────────────────────────────────────────────────

/// Шифрует `plaintext` ключом `key` (ChaCha20-Poly1305) с AAD.
/// `aad` = peer_id байты — аутентифицирует привязку снапшота к конкретному пиру.
/// Возвращает `(nonce: [u8;12], ciphertext)`.
fn encrypt_snapshot(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; 12], Vec<u8>), PlexError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = ChaNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            AeadPayload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PlexError::Crypto {
            msg: "ratchet snapshot encryption failed".into(),
        })?;
    Ok((nonce_bytes, ciphertext))
}

/// Расшифровывает `ciphertext` ключом `key`, `nonce` и `aad` (peer_id байты).
/// При несовпадении AAD тег аутентификации провалится — возвращает ошибку.
fn decrypt_snapshot(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PlexError> {
    if nonce.len() != 12 {
        return Err(PlexError::Crypto {
            msg: format!("bad nonce length: {}", nonce.len()),
        });
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            AeadPayload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| PlexError::Crypto {
            msg: "ratchet snapshot decryption failed".into(),
        })
}

impl Db {
    /// Сохраняет состояние Double Ratchet сессии в зашифрованном виде.
    ///
    /// Снапшот сериализуется в JSON, затем шифруется ChaCha20-Poly1305
    /// ключом `ratchet_enc_key` (HKDF от passphrase). Запись идёт в
    /// `ratchet_sessions_enc`. Старая таблица `ratchet_sessions` не
    /// обновляется, но и не удаляется — legacy fallback для чтения.
    pub fn save_ratchet_session(
        &self,
        snapshot: &crate::crypto::RatchetSessionSnapshot,
    ) -> Result<(), PlexError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .as_secs() as i64;

        let plaintext = serde_json::to_vec(snapshot).map_err(|e| PlexError::Storage {
            msg: format!("Failed to serialize ratchet snapshot: {e}"),
        })?;

        let (nonce, ciphertext) = encrypt_snapshot(
            &self.ratchet_enc_key,
            &plaintext,
            snapshot.peer_id.as_bytes(),
        )?;

        self.conn()?
            .execute(
                "INSERT INTO ratchet_sessions_enc
                 (peer_id, nonce, snapshot_encrypted, updated_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(peer_id) DO UPDATE SET
                    nonce = excluded.nonce,
                    snapshot_encrypted = excluded.snapshot_encrypted,
                    updated_at = excluded.updated_at",
                rusqlite::params![&snapshot.peer_id, &nonce[..], &ciphertext[..], now,],
            )
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to save encrypted ratchet session: {e}"),
            })?;

        Ok(())
    }

    /// Загружает состояние Double Ratchet сессии из БД.
    ///
    /// Сначала ищет в `ratchet_sessions_enc` (зашифрованная); при отсутствии
    /// делает legacy-fallback на старую таблицу `ratchet_sessions`.
    pub fn load_ratchet_session(
        &self,
        peer_id: &str,
    ) -> Result<Option<crate::crypto::RatchetSessionSnapshot>, PlexError> {
        // Пробуем новую зашифрованную таблицу
        {
            let conn = self.reader()?;
            let enc_row = conn
                .query_row(
                    "SELECT nonce, snapshot_encrypted FROM ratchet_sessions_enc WHERE peer_id = ?1",
                    [peer_id],
                    |row| {
                        let nonce: Vec<u8> = row.get(0)?;
                        let ct: Vec<u8> = row.get(1)?;
                        Ok((nonce, ct))
                    },
                )
                .optional()
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            if let Some((nonce, ct)) = enc_row {
                let (plaintext, needs_re_encrypt) = match decrypt_snapshot(
                    &self.ratchet_enc_key,
                    &nonce,
                    &ct,
                    peer_id.as_bytes(),
                ) {
                    Ok(pt) => (pt, false),
                    Err(_) => {
                        // Legacy snapshots were encrypted without AAD; retry and migrate.
                        info!(
                            peer_id,
                            "[audit] ratchet: retrying decrypt with empty AAD (migration)"
                        );
                        let pt = decrypt_snapshot(&self.ratchet_enc_key, &nonce, &ct, b"")?;
                        (pt, true)
                    }
                };
                let snapshot: crate::crypto::RatchetSessionSnapshot =
                    serde_json::from_slice(&plaintext).map_err(|e| PlexError::Storage {
                        msg: format!("Failed to deserialize ratchet snapshot: {e}"),
                    })?;
                if needs_re_encrypt {
                    // Re-save with correct AAD so future loads use proper binding.
                    let _ = self.save_ratchet_session(&snapshot);
                }
                return Ok(Some(snapshot));
            }
        }

        // Legacy fallback: не зашифрованная таблица
        info!(
            peer_id,
            "[audit] ratchet: falling back to legacy plaintext table"
        );
        let conn = self.reader()?;
        let mut stmt = conn
            .prepare(
                "SELECT root_key_bytes, dh_sending_secret_bytes, dh_sending_public,
                         dh_remote_public, sending_chain_key_bytes, receiving_chain_key_bytes,
                         ns, nr, pn, pending_dh_ratchet, skipped_message_keys, peer_id
                  FROM ratchet_sessions WHERE peer_id = ?1",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        stmt.query_row([peer_id], decode_legacy_row)
            .optional()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })
    }

    /// Загружает все сохраненные ratchet sessions.
    ///
    /// Объединяет записи из `ratchet_sessions_enc` (приоритет) и fallback из
    /// старой таблицы `ratchet_sessions` для peer_id без зашифрованной записи.
    pub fn load_all_ratchet_sessions(
        &self,
    ) -> Result<Vec<crate::crypto::RatchetSessionSnapshot>, PlexError> {
        let mut result: Vec<crate::crypto::RatchetSessionSnapshot> = Vec::new();
        let mut loaded_peer_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // 1. Зашифрованные записи
        {
            let conn = self.reader()?;
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, nonce, snapshot_encrypted FROM ratchet_sessions_enc ORDER BY updated_at DESC",
                )
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            let rows: Vec<(String, Vec<u8>, Vec<u8>)> = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            for (peer_id, nonce, ct) in rows {
                let (plaintext, needs_re_encrypt) = match decrypt_snapshot(
                    &self.ratchet_enc_key,
                    &nonce,
                    &ct,
                    peer_id.as_bytes(),
                ) {
                    Ok(pt) => (pt, false),
                    Err(_) => {
                        info!(
                            peer_id,
                            "[audit] ratchet: retrying bulk decrypt with empty AAD (migration)"
                        );
                        let pt = decrypt_snapshot(&self.ratchet_enc_key, &nonce, &ct, b"")?;
                        (pt, true)
                    }
                };
                let snapshot: crate::crypto::RatchetSessionSnapshot =
                    serde_json::from_slice(&plaintext).map_err(|e| PlexError::Storage {
                        msg: format!("Failed to deserialize ratchet snapshot for {peer_id}: {e}"),
                    })?;
                if needs_re_encrypt {
                    let _ = self.save_ratchet_session(&snapshot);
                }
                loaded_peer_ids.insert(peer_id.clone());
                info!(peer_id, "[audit] ratchet: loaded encrypted snapshot");
                result.push(snapshot);
            }
        }

        // 2. Legacy fallback для peer_id не найденных в зашифрованной таблице
        {
            let conn = self.reader()?;
            let mut stmt = conn
                .prepare(
                    "SELECT root_key_bytes, dh_sending_secret_bytes, dh_sending_public,
                             dh_remote_public, sending_chain_key_bytes, receiving_chain_key_bytes,
                             ns, nr, pn, pending_dh_ratchet, skipped_message_keys, peer_id
                      FROM ratchet_sessions ORDER BY updated_at DESC",
                )
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            let legacy: Vec<crate::crypto::RatchetSessionSnapshot> = stmt
                .query_map([], decode_legacy_row)
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            for snap in legacy {
                if !loaded_peer_ids.contains(&snap.peer_id) {
                    result.push(snap);
                }
            }
        }

        Ok(result)
    }

    /// Удаляет сохранённую ratchet сессию из обеих таблиц.
    pub fn delete_ratchet_session(&self, peer_id: &str) -> Result<(), PlexError> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM ratchet_sessions_enc WHERE peer_id = ?1",
            [peer_id],
        )
        .map_err(|e| PlexError::Storage {
            msg: format!("Failed to delete encrypted ratchet session: {e}"),
        })?;
        conn.execute("DELETE FROM ratchet_sessions WHERE peer_id = ?1", [peer_id])
            .map_err(|e| PlexError::Storage {
                msg: format!("Failed to delete legacy ratchet session: {e}"),
            })?;
        Ok(())
    }
}

/// Декодирует строку из legacy-таблицы `ratchet_sessions`.
fn decode_legacy_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::crypto::RatchetSessionSnapshot> {
    let root_key_bytes: Vec<u8> = row.get(0)?;
    let dh_sending_secret_bytes: Vec<u8> = row.get(1)?;
    let dh_sending_public: Vec<u8> = row.get(2)?;
    let dh_remote_public: Option<Vec<u8>> = row.get(3)?;
    let sending_chain_key_bytes: Option<Vec<u8>> = row.get(4)?;
    let receiving_chain_key_bytes: Option<Vec<u8>> = row.get(5)?;
    let ns: i32 = row.get(6)?;
    let nr: i32 = row.get(7)?;
    let pn: i32 = row.get(8)?;
    let pending_dh_ratchet: i32 = row.get(9)?;
    let skipped_keys_bytes: Vec<u8> = row.get(10)?;
    let peer_id: String = row.get(11)?;

    let skipped_message_keys: Vec<(crate::crypto::SkippedKeyId, [u8; 32])> =
        serde_json::from_slice(&skipped_keys_bytes)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

    Ok(crate::crypto::RatchetSessionSnapshot {
        root_key_bytes: array_from_vec(root_key_bytes)?,
        dh_sending_secret_bytes: array_from_vec(dh_sending_secret_bytes)?,
        dh_sending_public: array_from_vec(dh_sending_public)?,
        dh_remote_public: dh_remote_public.map(array_from_vec).transpose()?,
        sending_chain_key_bytes: sending_chain_key_bytes.map(array_from_vec).transpose()?,
        receiving_chain_key_bytes: receiving_chain_key_bytes.map(array_from_vec).transpose()?,
        ns: ns as u32,
        nr: nr as u32,
        pn: pn as u32,
        pending_dh_ratchet: pending_dh_ratchet != 0,
        skipped_message_keys,
        peer_id,
    })
}

fn array_from_vec(v: Vec<u8>) -> Result<[u8; 32], rusqlite::Error> {
    if v.len() != 32 {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "Expected 32 bytes, got {}",
            v.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}
