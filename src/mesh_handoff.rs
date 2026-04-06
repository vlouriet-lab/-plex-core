use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::PlexError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshHandoffOffer {
    pub session_id: String,
    pub generated_at: i64,
    pub total_bytes: u64,
    pub chunk_size: u64,
    pub total_chunks: u64,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshHandoffChunk {
    pub session_id: String,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IncomingMeshHandoff {
    pub offer: MeshHandoffOffer,
    pub chunks: HashMap<u64, Vec<u8>>,
    pub accepted_at: i64,
    pub last_updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct MeshHandoffProgress {
    pub received_chunks: u64,
    pub total_chunks: u64,
    pub received_bytes: u64,
    pub total_bytes: u64,
    pub is_complete: bool,
    pub accepted_at: i64,
    pub last_updated_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshHandoffRetransmitRequest {
    pub session_id: String,
    pub requested_at: i64,
    pub missing_chunk_indices: Vec<u64>,
}

pub fn prepare_bundle_adaptive(
    bundle_json: &str,
    preferred_chunk_size: usize,
    max_chunk_size: usize,
    target_chunks: usize,
) -> Result<(MeshHandoffOffer, Vec<MeshHandoffChunk>), PlexError> {
    let effective_chunk_size = choose_chunk_size(
        bundle_json.len(),
        preferred_chunk_size,
        max_chunk_size,
        target_chunks,
    )?;
    prepare_bundle(bundle_json, effective_chunk_size)
}

pub fn prepare_bundle(
    bundle_json: &str,
    chunk_size: usize,
) -> Result<(MeshHandoffOffer, Vec<MeshHandoffChunk>), PlexError> {
    if chunk_size == 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff chunk_size must be greater than zero".into(),
        });
    }

    let bytes = bundle_json.as_bytes();
    let generated_at = unix_now_secs()?;
    let total_bytes = bytes.len() as u64;
    let total_chunks = bytes.len().div_ceil(chunk_size) as u64;
    let bundle_sha256 = sha256_hex(bytes);
    let session_id = sha256_hex(
        format!("mesh-handoff:{generated_at}:{bundle_sha256}:{total_bytes}:{chunk_size}")
            .as_bytes(),
    );

    let offer = MeshHandoffOffer {
        session_id: session_id.clone(),
        generated_at,
        total_bytes,
        chunk_size: chunk_size as u64,
        total_chunks,
        bundle_sha256,
    };

    let chunks = bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, payload)| MeshHandoffChunk {
            session_id: session_id.clone(),
            chunk_index: index as u64,
            total_chunks,
            payload: payload.to_vec(),
        })
        .collect::<Vec<_>>();

    Ok((offer, chunks))
}

pub fn accept_offer(
    sessions: &mut HashMap<String, IncomingMeshHandoff>,
    offer: MeshHandoffOffer,
) -> Result<(), PlexError> {
    if offer.session_id.trim().is_empty() {
        return Err(PlexError::Network {
            msg: "Mesh handoff session_id must not be empty".into(),
        });
    }
    if offer.total_chunks == 0 && offer.total_bytes > 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff total_chunks must be positive for non-empty payload".into(),
        });
    }
    if offer.chunk_size == 0 && offer.total_bytes > 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff chunk_size must be positive for non-empty payload".into(),
        });
    }

    match sessions.get(&offer.session_id) {
        Some(existing) if !same_offer(&existing.offer, &offer) => Err(PlexError::Network {
            msg: format!(
                "Mesh handoff session {} already exists with different metadata",
                offer.session_id
            ),
        }),
        Some(_) => Ok(()),
        None => {
            let now = unix_now_secs()?;
            sessions.insert(
                offer.session_id.clone(),
                IncomingMeshHandoff {
                    offer,
                    chunks: HashMap::new(),
                    accepted_at: now,
                    last_updated_at: now,
                },
            );
            Ok(())
        }
    }
}

pub fn ingest_chunk(
    sessions: &mut HashMap<String, IncomingMeshHandoff>,
    chunk: MeshHandoffChunk,
) -> Result<MeshHandoffProgress, PlexError> {
    let session = sessions
        .get_mut(&chunk.session_id)
        .ok_or_else(|| PlexError::Network {
            msg: format!("Unknown mesh handoff session {}", chunk.session_id),
        })?;

    if chunk.total_chunks != session.offer.total_chunks {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff chunk total mismatch for session {}: {} != {}",
                chunk.session_id, chunk.total_chunks, session.offer.total_chunks
            ),
        });
    }

    if chunk.chunk_index >= session.offer.total_chunks {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff chunk index {} out of bounds for session {}",
                chunk.chunk_index, chunk.session_id
            ),
        });
    }

    if chunk.payload.is_empty() && session.offer.total_bytes > 0 {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff chunk {} for session {} is empty",
                chunk.chunk_index, chunk.session_id
            ),
        });
    }

    session
        .chunks
        .entry(chunk.chunk_index)
        .or_insert(chunk.payload);

    session.last_updated_at = unix_now_secs()?;

    Ok(progress_for(session))
}

pub fn assemble_bundle_json(
    sessions: &HashMap<String, IncomingMeshHandoff>,
    session_id: &str,
) -> Result<String, PlexError> {
    let session = sessions.get(session_id).ok_or_else(|| PlexError::Network {
        msg: format!("Unknown mesh handoff session {session_id}"),
    })?;

    if session.chunks.len() != session.offer.total_chunks as usize {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff session {} is incomplete: {}/{} chunks",
                session_id,
                session.chunks.len(),
                session.offer.total_chunks
            ),
        });
    }

    let mut bytes = Vec::with_capacity(session.offer.total_bytes as usize);
    for index in 0..session.offer.total_chunks {
        let chunk = session
            .chunks
            .get(&index)
            .ok_or_else(|| PlexError::Network {
                msg: format!(
                    "Missing mesh handoff chunk {} for session {}",
                    index, session_id
                ),
            })?;
        bytes.extend_from_slice(chunk);
    }

    if bytes.len() as u64 != session.offer.total_bytes {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff session {} byte size mismatch: {} != {}",
                session_id,
                bytes.len(),
                session.offer.total_bytes
            ),
        });
    }

    let actual_hash = sha256_hex(&bytes);
    if actual_hash != session.offer.bundle_sha256 {
        return Err(PlexError::Network {
            msg: format!("Mesh handoff checksum mismatch for session {}", session_id),
        });
    }

    String::from_utf8(bytes).map_err(|e| PlexError::Network {
        msg: format!(
            "Mesh handoff session {} is not valid UTF-8 JSON: {e}",
            session_id
        ),
    })
}

pub fn discard_session(
    sessions: &mut HashMap<String, IncomingMeshHandoff>,
    session_id: &str,
) -> bool {
    sessions.remove(session_id).is_some()
}

pub fn build_retransmit_request(
    sessions: &HashMap<String, IncomingMeshHandoff>,
    session_id: &str,
) -> Result<MeshHandoffRetransmitRequest, PlexError> {
    Ok(MeshHandoffRetransmitRequest {
        session_id: session_id.to_string(),
        requested_at: unix_now_secs()?,
        missing_chunk_indices: missing_chunk_indices(sessions, session_id)?,
    })
}

pub fn select_requested_chunks(
    chunks: &[MeshHandoffChunk],
    request: &MeshHandoffRetransmitRequest,
) -> Result<Vec<MeshHandoffChunk>, PlexError> {
    let session_id = chunks
        .first()
        .map(|chunk| chunk.session_id.clone())
        .unwrap_or_else(|| request.session_id.clone());

    if session_id != request.session_id {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff retransmit request session mismatch: {} != {}",
                request.session_id, session_id,
            ),
        });
    }

    let chunk_map = chunks
        .iter()
        .cloned()
        .map(|chunk| (chunk.chunk_index, chunk))
        .collect::<HashMap<_, _>>();

    request
        .missing_chunk_indices
        .iter()
        .map(|index| {
            chunk_map
                .get(index)
                .cloned()
                .ok_or_else(|| PlexError::Network {
                    msg: format!(
                    "Mesh handoff retransmit request references unknown chunk {} for session {}",
                    index,
                    request.session_id,
                ),
                })
        })
        .collect()
}

pub fn missing_chunk_indices(
    sessions: &HashMap<String, IncomingMeshHandoff>,
    session_id: &str,
) -> Result<Vec<u64>, PlexError> {
    let session = sessions.get(session_id).ok_or_else(|| PlexError::Network {
        msg: format!("Unknown mesh handoff session {session_id}"),
    })?;

    Ok((0..session.offer.total_chunks)
        .filter(|index| !session.chunks.contains_key(index))
        .collect())
}

pub fn session_progress(
    sessions: &HashMap<String, IncomingMeshHandoff>,
    session_id: &str,
) -> Result<MeshHandoffProgress, PlexError> {
    let session = sessions.get(session_id).ok_or_else(|| PlexError::Network {
        msg: format!("Unknown mesh handoff session {session_id}"),
    })?;
    Ok(progress_for(session))
}

pub fn prune_expired_sessions(
    sessions: &mut HashMap<String, IncomingMeshHandoff>,
    older_than: i64,
) -> u64 {
    let before = sessions.len();
    sessions.retain(|_, session| session.last_updated_at >= older_than);
    (before.saturating_sub(sessions.len())) as u64
}

fn progress_for(session: &IncomingMeshHandoff) -> MeshHandoffProgress {
    let received_bytes = session
        .chunks
        .values()
        .map(|chunk| chunk.len() as u64)
        .sum::<u64>();
    MeshHandoffProgress {
        received_chunks: session.chunks.len() as u64,
        total_chunks: session.offer.total_chunks,
        received_bytes,
        total_bytes: session.offer.total_bytes,
        is_complete: session.chunks.len() == session.offer.total_chunks as usize,
        accepted_at: session.accepted_at,
        last_updated_at: session.last_updated_at,
    }
}

fn same_offer(left: &MeshHandoffOffer, right: &MeshHandoffOffer) -> bool {
    left.session_id == right.session_id
        && left.total_bytes == right.total_bytes
        && left.chunk_size == right.chunk_size
        && left.total_chunks == right.total_chunks
        && left.bundle_sha256 == right.bundle_sha256
}

fn choose_chunk_size(
    total_bytes: usize,
    preferred_chunk_size: usize,
    max_chunk_size: usize,
    target_chunks: usize,
) -> Result<usize, PlexError> {
    if total_bytes == 0 {
        return Ok(1);
    }
    if preferred_chunk_size == 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff preferred_chunk_size must be greater than zero".into(),
        });
    }
    if max_chunk_size == 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff max_chunk_size must be greater than zero".into(),
        });
    }
    if target_chunks == 0 {
        return Err(PlexError::Network {
            msg: "Mesh handoff target_chunks must be greater than zero".into(),
        });
    }

    let min_chunk_size = total_bytes.div_ceil(target_chunks).max(1);
    let effective = preferred_chunk_size.max(min_chunk_size);
    if effective > max_chunk_size {
        return Err(PlexError::Network {
            msg: format!(
                "Mesh handoff payload requires chunk size {} which exceeds max_chunk_size {}",
                effective, max_chunk_size,
            ),
        });
    }

    Ok(effective)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now_secs() -> Result<i64, PlexError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_roundtrip_reassembles_payload() {
        let payload = r#"{"kind":"mesh","value":42}"#;
        let (offer, chunks) = prepare_bundle(payload, 5).unwrap();
        let mut sessions = HashMap::new();

        accept_offer(&mut sessions, offer.clone()).unwrap();
        for chunk in chunks.into_iter().rev() {
            ingest_chunk(&mut sessions, chunk).unwrap();
        }

        let restored = assemble_bundle_json(&sessions, &offer.session_id).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn rejects_commit_for_incomplete_session() {
        let payload = "abcdef";
        let (offer, mut chunks) = prepare_bundle(payload, 2).unwrap();
        let mut sessions = HashMap::new();

        accept_offer(&mut sessions, offer.clone()).unwrap();
        ingest_chunk(&mut sessions, chunks.remove(0)).unwrap();

        let error = assemble_bundle_json(&sessions, &offer.session_id).unwrap_err();
        assert!(matches!(error, PlexError::Network { .. }));
    }

    #[test]
    fn adaptive_preparation_scales_chunk_size_to_target() {
        let payload = "x".repeat(100);
        let (offer, chunks) = prepare_bundle_adaptive(&payload, 8, 64, 4).unwrap();

        assert_eq!(offer.chunk_size, 25);
        assert_eq!(chunks.len(), 4);
    }

    #[test]
    fn reports_missing_chunks_for_resume_flow() {
        let payload = "abcdefgh";
        let (offer, chunks) = prepare_bundle(payload, 2).unwrap();
        let mut sessions = HashMap::new();

        accept_offer(&mut sessions, offer.clone()).unwrap();
        ingest_chunk(&mut sessions, chunks[0].clone()).unwrap();
        ingest_chunk(&mut sessions, chunks[2].clone()).unwrap();

        assert_eq!(
            missing_chunk_indices(&sessions, &offer.session_id).unwrap(),
            vec![1, 3]
        );
        let progress = session_progress(&sessions, &offer.session_id).unwrap();
        assert_eq!(progress.received_chunks, 2);
        assert!(!progress.is_complete);
    }

    #[test]
    fn builds_retransmit_request_and_selects_requested_chunks() {
        let payload = "abcdefgh";
        let (offer, chunks) = prepare_bundle(payload, 2).unwrap();
        let mut sessions = HashMap::new();

        accept_offer(&mut sessions, offer.clone()).unwrap();
        ingest_chunk(&mut sessions, chunks[0].clone()).unwrap();
        ingest_chunk(&mut sessions, chunks[3].clone()).unwrap();

        let request = build_retransmit_request(&sessions, &offer.session_id).unwrap();
        assert_eq!(request.missing_chunk_indices, vec![1, 2]);

        let selected = select_requested_chunks(&chunks, &request).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].chunk_index, 1);
        assert_eq!(selected[1].chunk_index, 2);
    }

    #[test]
    fn prunes_expired_sessions_by_last_update() {
        let payload = "abcdef";
        let (offer, _) = prepare_bundle(payload, 2).unwrap();
        let mut sessions = HashMap::new();

        accept_offer(&mut sessions, offer.clone()).unwrap();
        sessions.get_mut(&offer.session_id).unwrap().last_updated_at = 10;

        let pruned = prune_expired_sessions(&mut sessions, 11);
        assert_eq!(pruned, 1);
        assert!(!sessions.contains_key(&offer.session_id));
    }
}
