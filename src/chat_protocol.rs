use sha2::{Digest, Sha256};

use crate::PlexError;

pub const CHAT_PROTOCOL: &str = "plex.chat.v1";
/// Все поддерживаемые версии chat-протокола.
/// Добавьте новые версии сюда при будущих обновлениях протокола.
pub const SUPPORTED_CHAT_PROTOCOLS: &[&str] = &["plex.chat.v1"];
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_MEDIA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageKind {
    Text,
    Photo,
    File,
    VoiceNote,
    VideoNote,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatMediaMeta {
    pub file_name: String,
    pub mime_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatMessagePayload {
    pub protocol: String,
    pub message_id: String,
    pub from_peer_id: String,
    pub to_peer_id: String,
    pub kind: ChatMessageKind,
    pub text: Option<String>,
    pub media_meta: Option<ChatMediaMeta>,
    pub media_bytes: Option<Vec<u8>>,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatReadReceiptPayload {
    pub protocol: String,
    pub message_id: String,
    pub reader_peer_id: String,
    pub chat_peer_id: String,
    pub read_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEnvelope {
    Message { payload: ChatMessagePayload },
    ReadReceipt { payload: ChatReadReceiptPayload },
}

pub fn encode_envelope(envelope: &ChatEnvelope) -> Result<Vec<u8>, PlexError> {
    validate_envelope(envelope)?;
    serde_json::to_vec(envelope).map_err(|e| PlexError::Internal {
        msg: format!("Failed to encode chat envelope: {e}"),
    })
}

pub fn decode_envelope(bytes: &[u8]) -> Result<ChatEnvelope, PlexError> {
    let envelope: ChatEnvelope = serde_json::from_slice(bytes).map_err(|e| PlexError::Network {
        msg: format!("Invalid chat envelope payload: {e}"),
    })?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub fn generate_message_id(
    from_peer_id: &str,
    to_peer_id: &str,
    kind: ChatMessageKind,
    created_at: i64,
    body_fingerprint: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"plex.chat.msg.v1");
    hasher.update(from_peer_id.as_bytes());
    hasher.update(to_peer_id.as_bytes());
    hasher.update((kind as u8).to_le_bytes());
    hasher.update(created_at.to_le_bytes());
    hasher.update(body_fingerprint);
    encode_hex(&hasher.finalize())
}

fn validate_envelope(envelope: &ChatEnvelope) -> Result<(), PlexError> {
    match envelope {
        ChatEnvelope::Message { payload } => validate_message(payload),
        ChatEnvelope::ReadReceipt { payload } => validate_read_receipt(payload),
    }
}

fn validate_message(payload: &ChatMessagePayload) -> Result<(), PlexError> {
    if !SUPPORTED_CHAT_PROTOCOLS.contains(&payload.protocol.as_str()) {
        return Err(PlexError::Validation {
            msg: format!(
                "Unsupported chat protocol: '{}'. Supported: {:?}",
                payload.protocol, SUPPORTED_CHAT_PROTOCOLS
            ),
        });
    }
    if payload.message_id.trim().is_empty() {
        return Err(PlexError::Validation {
            msg: "chat message_id must not be empty".into(),
        });
    }
    if payload.from_peer_id.trim().is_empty() || payload.to_peer_id.trim().is_empty() {
        return Err(PlexError::Validation {
            msg: "chat from_peer_id and to_peer_id must not be empty".into(),
        });
    }

    if let Some(text) = &payload.text {
        if text.len() > MAX_TEXT_BYTES {
            return Err(PlexError::Validation {
                msg: format!("chat text exceeds {MAX_TEXT_BYTES} bytes"),
            });
        }
    }

    if let Some(media) = &payload.media_bytes {
        if media.len() > MAX_MEDIA_BYTES {
            return Err(PlexError::Validation {
                msg: format!("chat media exceeds {MAX_MEDIA_BYTES} bytes"),
            });
        }
    }

    match payload.kind {
        ChatMessageKind::Text => {
            if payload.text.as_deref().unwrap_or("").trim().is_empty() {
                return Err(PlexError::Validation {
                    msg: "text message body must not be empty".into(),
                });
            }
            if payload.media_bytes.is_some() || payload.media_meta.is_some() {
                return Err(PlexError::Validation {
                    msg: "text message must not contain media".into(),
                });
            }
        }
        ChatMessageKind::Photo
        | ChatMessageKind::File
        | ChatMessageKind::VoiceNote
        | ChatMessageKind::VideoNote => {
            if payload
                .media_bytes
                .as_ref()
                .map_or(true, |bytes| bytes.is_empty())
            {
                return Err(PlexError::Validation {
                    msg: "media message must contain media_bytes".into(),
                });
            }
            if payload.media_meta.is_none() {
                return Err(PlexError::Validation {
                    msg: "media message must contain media_meta".into(),
                });
            }
        }
    }

    Ok(())
}

fn validate_read_receipt(payload: &ChatReadReceiptPayload) -> Result<(), PlexError> {
    if !SUPPORTED_CHAT_PROTOCOLS.contains(&payload.protocol.as_str()) {
        return Err(PlexError::Validation {
            msg: format!(
                "Unsupported chat protocol: '{}'. Supported: {:?}",
                payload.protocol, SUPPORTED_CHAT_PROTOCOLS
            ),
        });
    }
    if payload.message_id.trim().is_empty() {
        return Err(PlexError::Validation {
            msg: "read receipt message_id must not be empty".into(),
        });
    }
    if payload.reader_peer_id.trim().is_empty() || payload.chat_peer_id.trim().is_empty() {
        return Err(PlexError::Validation {
            msg: "read receipt peer ids must not be empty".into(),
        });
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrip_text() {
        let msg = ChatMessagePayload {
            protocol: CHAT_PROTOCOL.to_string(),
            message_id: "m1".into(),
            from_peer_id: "peer-a".into(),
            to_peer_id: "peer-b".into(),
            kind: ChatMessageKind::Text,
            text: Some("hello".into()),
            media_meta: None,
            media_bytes: None,
            created_at: 100,
        };

        let encoded = encode_envelope(&ChatEnvelope::Message { payload: msg }).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();

        let ChatEnvelope::Message { payload } = decoded else {
            unreachable!("wrong envelope variant");
        };

        assert_eq!(payload.message_id, "m1");
        assert_eq!(payload.text.as_deref(), Some("hello"));
    }

    #[test]
    fn message_rejects_text_with_media() {
        let msg = ChatMessagePayload {
            protocol: CHAT_PROTOCOL.to_string(),
            message_id: "m1".into(),
            from_peer_id: "peer-a".into(),
            to_peer_id: "peer-b".into(),
            kind: ChatMessageKind::Text,
            text: Some("hello".into()),
            media_meta: Some(ChatMediaMeta {
                file_name: "x.jpg".into(),
                mime_type: "image/jpeg".into(),
                width: Some(100),
                height: Some(100),
                duration_ms: None,
            }),
            media_bytes: Some(vec![1, 2, 3]),
            created_at: 100,
        };

        let err = encode_envelope(&ChatEnvelope::Message { payload: msg }).unwrap_err();
        assert!(matches!(err, PlexError::Validation { .. }));
    }

    #[test]
    fn receipt_roundtrip() {
        let receipt = ChatReadReceiptPayload {
            protocol: CHAT_PROTOCOL.to_string(),
            message_id: "m1".into(),
            reader_peer_id: "peer-b".into(),
            chat_peer_id: "peer-a".into(),
            read_at: 500,
        };

        let encoded = encode_envelope(&ChatEnvelope::ReadReceipt { payload: receipt }).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();

        let ChatEnvelope::ReadReceipt { payload } = decoded else {
            unreachable!("wrong envelope variant");
        };
        assert_eq!(payload.message_id, "m1");
        assert_eq!(payload.read_at, 500);
    }
}
