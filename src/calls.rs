use crate::PlexError;

pub const CALL_SIGNAL_PROTOCOL: &str = "plex.call.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallSignalKind {
    Ring,
    Offer,
    Answer,
    IceCandidate,
    End,
    Reject,
    Busy,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallSignal {
    pub protocol: String,
    pub call_id: String,
    pub from_peer_id: String,
    pub to_peer_id: String,
    pub kind: CallSignalKind,
    pub payload: String,
    pub created_at: i64,
}

pub fn encode_signal(signal: &CallSignal) -> Result<Vec<u8>, PlexError> {
    validate_signal(signal)?;
    serde_json::to_vec(signal).map_err(|e| PlexError::Internal {
        msg: format!("Failed to encode call signal: {e}"),
    })
}

pub fn decode_signal(bytes: &[u8]) -> Result<CallSignal, PlexError> {
    let signal: CallSignal = serde_json::from_slice(bytes).map_err(|e| PlexError::Network {
        msg: format!("Invalid call signal payload: {e}"),
    })?;
    validate_signal(&signal)?;
    Ok(signal)
}

pub fn validate_signal(signal: &CallSignal) -> Result<(), PlexError> {
    if signal.protocol != CALL_SIGNAL_PROTOCOL {
        return Err(PlexError::Network {
            msg: format!("Unsupported call signal protocol: {}", signal.protocol),
        });
    }
    if signal.call_id.trim().is_empty() {
        return Err(PlexError::Network {
            msg: "call_id must not be empty".into(),
        });
    }
    if signal.from_peer_id.trim().is_empty() || signal.to_peer_id.trim().is_empty() {
        return Err(PlexError::Network {
            msg: "from_peer_id and to_peer_id must not be empty".into(),
        });
    }
    if signal.payload.len() > 64 * 1024 {
        return Err(PlexError::Network {
            msg: "call signal payload exceeds 64 KiB".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let signal = CallSignal {
            protocol: CALL_SIGNAL_PROTOCOL.to_string(),
            call_id: "call-1".into(),
            from_peer_id: "peer-a".into(),
            to_peer_id: "peer-b".into(),
            kind: CallSignalKind::Offer,
            payload: "v=0...sdp".into(),
            created_at: 123,
        };

        let encoded = encode_signal(&signal).unwrap();
        let decoded = decode_signal(&encoded).unwrap();
        assert_eq!(decoded.call_id, signal.call_id);
        assert_eq!(decoded.kind, CallSignalKind::Offer);
    }

    #[test]
    fn rejects_unknown_protocol() {
        let signal = CallSignal {
            protocol: "other.v1".into(),
            call_id: "call-1".into(),
            from_peer_id: "peer-a".into(),
            to_peer_id: "peer-b".into(),
            kind: CallSignalKind::Ring,
            payload: String::new(),
            created_at: 1,
        };

        let error = encode_signal(&signal).unwrap_err();
        assert!(matches!(error, PlexError::Network { .. }));
    }
}
