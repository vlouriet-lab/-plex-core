//! FFI-слой для Transfer Manager
//!
//! Экспортирует методы для управления передачей файлов через UniFFI.

use crate::transfer::{FileTransferEnvelope, FileTransferMetadata, TransferProgress};
use serde::{Deserialize, Serialize};

/// Record для FFI-передачи метаданных трансфера
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct FileTransferRecord {
    pub transfer_id: String,
    pub peer_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub checksum: String,
    pub chunk_size: u32,
    pub encryption_key: String,
    pub is_inbound: bool,
    pub created_at: u64,
}

impl From<&FileTransferMetadata> for FileTransferRecord {
    fn from(m: &FileTransferMetadata) -> Self {
        FileTransferRecord {
            transfer_id: m.transfer_id.clone(),
            peer_id: m.peer_id.clone(),
            file_name: m.file_name.clone(),
            file_size: m.file_size,
            mime_type: m.mime_type.clone(),
            checksum: m.checksum.clone(),
            chunk_size: m.chunk_size,
            encryption_key: m.encryption_key.clone(),
            is_inbound: m.is_inbound,
            created_at: m.created_at,
        }
    }
}

/// Record для FFI-передачи прогресса трансфера
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct TransferProgressRecord {
    pub chunks_done: u32,
    pub chunks_total: u32,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub state: String, // "pending", "negotiating", "transferring", "paused", "verifying", "complete", "failed", "cancelled"
    pub percent: f32,
}

impl From<&TransferProgress> for TransferProgressRecord {
    fn from(p: &TransferProgress) -> Self {
        TransferProgressRecord {
            chunks_done: p.chunks_done,
            chunks_total: p.chunks_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            state: p.state.as_str().to_string(),
            percent: p.percent,
        }
    }
}

/// Record для FFI-передачи полного состояния трансфера
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct FileTransferStatusRecord {
    pub metadata: FileTransferRecord,
    pub progress: TransferProgressRecord,
    pub last_attempt_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub error_reason: Option<String>,
}

impl From<&FileTransferEnvelope> for FileTransferStatusRecord {
    fn from(e: &FileTransferEnvelope) -> Self {
        FileTransferStatusRecord {
            metadata: (&e.metadata).into(),
            progress: (&e.progress()).into(),
            last_attempt_at: e.last_attempt_at,
            completed_at: e.completed_at,
            error_reason: e.error_reason.clone(),
        }
    }
}
