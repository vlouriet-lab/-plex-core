//! Transfer Manager — управление передачей файлов с progress-tracking
//!
//! Отвечает за:
//! - Инициирование передачи файла
//! - Разбиение на chunks и шифрование
//! - Progress-tracking и pause/resume
//! - Blake3 checksums для верификации
//! - Статистика передачи

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{info, warn};

/// Размеры по умолчанию
pub const DEFAULT_CHUNK_SIZE: u32 = 262_144; // 256 KiB
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const TRANSFER_ID_LEN: usize = 16;

/// Уникальный идентификатор трансфера ([u8; 16])
pub type TransferId = [u8; 16];

/// Состояние трансфера файла
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferState {
    /// Ожидает начала
    Pending,
    /// Согласование с пиром (обмен метаданными)
    Negotiating,
    /// В процессе передачи
    Transferring,
    /// Приостановлен пользователем
    Paused,
    /// Проверка checksum
    Verifying,
    /// Успешно завершена
    Complete,
    /// Ошибка при передаче
    Failed,
    /// Отменена пользователем
    Cancelled,
}

impl TransferState {
    pub fn as_str(&self) -> &str {
        match self {
            TransferState::Pending => "pending",
            TransferState::Negotiating => "negotiating",
            TransferState::Transferring => "transferring",
            TransferState::Paused => "paused",
            TransferState::Verifying => "verifying",
            TransferState::Complete => "complete",
            TransferState::Failed => "failed",
            TransferState::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferState::Complete | TransferState::Failed | TransferState::Cancelled
        )
    }
}

/// Прогресс трансфера
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferProgress {
    /// Передано chunks
    pub chunks_done: u32,
    /// Всего chunks
    pub chunks_total: u32,
    /// Передано байт
    pub bytes_done: u64,
    /// Всего байт
    pub bytes_total: u64,
    /// Состояние
    pub state: TransferState,
    /// Прогресс (0.0-1.0)
    pub percent: f32,
}

impl TransferProgress {
    pub fn from_envelope(env: &FileTransferEnvelope) -> Self {
        let chunk_size = env.metadata.chunk_size;
        let file_size = env.metadata.file_size;

        let chunks_total = if chunk_size > 0 {
            file_size.div_ceil(chunk_size as u64) as u32
        } else {
            0
        };

        let bytes_done = (env.chunks_done as u64) * (chunk_size as u64);
        let bytes_done = bytes_done.min(file_size);

        let percent = if file_size > 0 {
            ((bytes_done as f32) / (file_size as f32)).min(1.0)
        } else {
            0.0
        };

        TransferProgress {
            chunks_done: env.chunks_done,
            chunks_total,
            bytes_done,
            bytes_total: file_size,
            state: env.state,
            percent,
        }
    }
}

/// Метаданные трансфера файла
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct FileTransferMetadata {
    /// TransferId в hex формате для передачи
    pub transfer_id: String,
    /// Peer ID получателя
    pub peer_id: String,
    /// Имя файла
    pub file_name: String,
    /// Размер файла в байтах
    pub file_size: u64,
    /// MIME type файла
    pub mime_type: String,
    /// Blake3 checksum файла (32 байта в hex)
    pub checksum: String,
    /// Размер одного chunk'a
    pub chunk_size: u32,
    /// Симметричный ключ для шифрования (ChaCha20Poly1305, в hex)
    pub encryption_key: String,
    /// Входящий (true) или исходящий (false)
    pub is_inbound: bool,
    /// Когда был создан трансфер (Unix timestamp, сек)
    pub created_at: u64,
}

/// Конверт трансфера (состояние в памяти/БД)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileTransferEnvelope {
    pub metadata: FileTransferMetadata,
    pub state: TransferState,
    /// Кол-во успешно передано chunks
    pub chunks_done: u32,
    /// Последняя попытка (Unix timestamp, сек)
    pub last_attempt_at: Option<u64>,
    /// Завершено в (Unix timestamp, сек)
    pub completed_at: Option<u64>,
    /// Причина ошибки
    pub error_reason: Option<String>,
}

impl FileTransferEnvelope {
    pub fn new(metadata: FileTransferMetadata) -> Self {
        FileTransferEnvelope {
            metadata,
            state: TransferState::Pending,
            chunks_done: 0,
            last_attempt_at: None,
            completed_at: None,
            error_reason: None,
        }
    }

    pub fn progress(&self) -> TransferProgress {
        TransferProgress::from_envelope(self)
    }

    pub fn mark_completed(&mut self) {
        self.state = TransferState::Complete;
        self.completed_at = Some(current_unix_timestamp());
    }

    pub fn mark_failed(&mut self, reason: String) {
        self.state = TransferState::Failed;
        self.error_reason = Some(reason);
        self.completed_at = Some(current_unix_timestamp());
    }

    pub fn mark_cancelled(&mut self) {
        self.state = TransferState::Cancelled;
        self.completed_at = Some(current_unix_timestamp());
    }
}

/// Менеджер трансфера файлов
pub struct TransferManager {
    /// transfer_id (hex) -> FileTransferEnvelope
    transfers: std::sync::Arc<std::sync::Mutex<HashMap<String, FileTransferEnvelope>>>,
}

impl TransferManager {
    /// Создаёт новый менеджер трансферов
    pub fn new() -> Self {
        TransferManager {
            transfers: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Начинает новый трансфер
    pub fn start_transfer(&self, metadata: FileTransferMetadata) -> Result<String, TransferError> {
        if metadata.file_size > MAX_FILE_SIZE {
            return Err(TransferError::FileTooLarge(metadata.file_size));
        }

        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        let envelope = FileTransferEnvelope::new(metadata);
        let transfer_id = envelope.metadata.transfer_id.clone();

        info!(
            "Starting file transfer: {} ({} bytes)",
            transfer_id, envelope.metadata.file_size
        );
        transfers.insert(transfer_id.clone(), envelope);
        Ok(transfer_id)
    }

    /// Получает прогресс трансфера
    pub fn get_progress(
        &self,
        transfer_id: &str,
    ) -> Result<Option<TransferProgress>, TransferError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        Ok(transfers.get(transfer_id).map(|e| e.progress()))
    }

    /// Отмечает chunk как успешно передано
    pub fn mark_chunk_done(&self, transfer_id: &str) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            envelope.chunks_done += 1;
            envelope.last_attempt_at = Some(current_unix_timestamp());

            let total_chunks = if envelope.metadata.chunk_size > 0 {
                envelope
                    .metadata
                    .file_size
                    .div_ceil(envelope.metadata.chunk_size as u64) as u32
            } else {
                0
            };

            if envelope.chunks_done >= total_chunks {
                envelope.state = TransferState::Verifying;
                info!(
                    "Transfer {} ready for verification ({}/{} chunks)",
                    transfer_id, envelope.chunks_done, total_chunks
                );
            }

            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Приостанавливает трансфер
    pub fn pause_transfer(&self, transfer_id: &str) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            if envelope.state.is_terminal() {
                return Err(TransferError::TransferTerminal);
            }
            envelope.state = TransferState::Paused;
            info!(
                "Transfer {} paused at {} chunks",
                transfer_id, envelope.chunks_done
            );
            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Возобновляет трансфер
    pub fn resume_transfer(&self, transfer_id: &str) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            if envelope.state != TransferState::Paused {
                return Err(TransferError::NotPaused);
            }
            envelope.state = TransferState::Transferring;
            info!("Transfer {} resumed", transfer_id);
            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Отменяет трансфер
    pub fn cancel_transfer(&self, transfer_id: &str) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            if envelope.state.is_terminal() {
                return Err(TransferError::TransferTerminal);
            }
            envelope.mark_cancelled();
            info!("Transfer {} cancelled", transfer_id);
            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Отмечает трансфер как успешно завершённый и проверен
    pub fn mark_completed(&self, transfer_id: &str) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            envelope.mark_completed();
            info!("Transfer {} completed successfully", transfer_id);
            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Отмечает трансфер как неудачный
    pub fn mark_failed(&self, transfer_id: &str, reason: String) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        if let Some(envelope) = transfers.get_mut(transfer_id) {
            envelope.mark_failed(reason);
            warn!(
                "Transfer {} failed: {}",
                transfer_id,
                envelope
                    .error_reason
                    .as_ref()
                    .unwrap_or(&"unknown".to_string())
            );
            Ok(())
        } else {
            Err(TransferError::TransferNotFound(transfer_id.to_string()))
        }
    }

    /// Получает метаданные трансфера
    pub fn get_metadata(
        &self,
        transfer_id: &str,
    ) -> Result<Option<FileTransferMetadata>, TransferError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        Ok(transfers.get(transfer_id).map(|e| e.metadata.clone()))
    }

    /// Получает полный конверт трансфера
    pub fn get_envelope(
        &self,
        transfer_id: &str,
    ) -> Result<Option<FileTransferEnvelope>, TransferError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        Ok(transfers.get(transfer_id).cloned())
    }

    /// Получает все активные трансферы
    pub fn get_active_transfers(&self) -> Result<Vec<FileTransferEnvelope>, TransferError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;

        Ok(transfers
            .values()
            .filter(|e| !e.state.is_terminal())
            .cloned()
            .collect())
    }

    /// Количество трансферов (всех)
    pub fn transfer_count(&self) -> Result<usize, TransferError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;
        Ok(transfers.len())
    }

    /// Очистить всё
    pub fn clear(&self) -> Result<(), TransferError> {
        let mut transfers = self
            .transfers
            .lock()
            .map_err(|_| TransferError::LockFailure)?;
        transfers.clear();
        Ok(())
    }
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Ошибки transfer manager'а
#[derive(Error, Debug)]
pub enum TransferError {
    #[error("Lock failure (mutex poisoned)")]
    LockFailure,

    #[error("Transfer not found: {0}")]
    TransferNotFound(String),

    #[error("File too large: {0} bytes (max {})", MAX_FILE_SIZE)]
    FileTooLarge(u64),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Transfer is in terminal state")]
    TransferTerminal,

    #[error("Transfer is not paused")]
    NotPaused,

    #[error("Invalid state transition")]
    InvalidStateTransition,

    #[error("IO error: {0}")]
    IoError(String),
}

/// Хелпер функция — текущий Unix timestamp
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_state_str() {
        assert_eq!(TransferState::Pending.as_str(), "pending");
        assert_eq!(TransferState::Complete.as_str(), "complete");
        assert_eq!(TransferState::Failed.as_str(), "failed");
    }

    #[test]
    fn test_transfer_state_terminal() {
        assert!(TransferState::Complete.is_terminal());
        assert!(TransferState::Failed.is_terminal());
        assert!(TransferState::Cancelled.is_terminal());
        assert!(!TransferState::Transferring.is_terminal());
    }

    #[test]
    fn test_transfer_manager_lifecycle() {
        let mgr = TransferManager::new();

        let metadata = FileTransferMetadata {
            transfer_id: "test-123".to_string(),
            peer_id: "peer1".to_string(),
            file_name: "test.txt".to_string(),
            file_size: 1024,
            mime_type: "text/plain".to_string(),
            checksum: "abc123".to_string(),
            chunk_size: 256,
            encryption_key: "key123".to_string(),
            is_inbound: false,
            created_at: current_unix_timestamp(),
        };

        // Start transfer
        let id = mgr.start_transfer(metadata).unwrap();
        assert_eq!(mgr.transfer_count().unwrap(), 1);

        // Check progress
        let progress = mgr.get_progress(&id).unwrap().unwrap();
        assert_eq!(progress.percent, 0.0);
        assert_eq!(progress.state, TransferState::Pending);

        // Pause
        mgr.pause_transfer(&id).unwrap();
        let progress = mgr.get_progress(&id).unwrap().unwrap();
        assert_eq!(progress.state, TransferState::Paused);

        // Resume
        mgr.resume_transfer(&id).unwrap();
        let progress = mgr.get_progress(&id).unwrap().unwrap();
        assert_eq!(progress.state, TransferState::Transferring);

        // Mark done
        mgr.mark_completed(&id).unwrap();
        let progress = mgr.get_progress(&id).unwrap().unwrap();
        assert!(progress.state.is_terminal());
    }

    #[test]
    fn test_transfer_progress_calculation() {
        let metadata = FileTransferMetadata {
            transfer_id: "test".to_string(),
            peer_id: "p1".to_string(),
            file_name: "f.bin".to_string(),
            file_size: 1024,
            mime_type: "application/octet-stream".to_string(),
            checksum: "aaa".to_string(),
            chunk_size: 256,
            encryption_key: "key".to_string(),
            is_inbound: true,
            created_at: current_unix_timestamp(),
        };

        let mut envelope = FileTransferEnvelope::new(metadata);

        // 1 of 4 chunks done
        envelope.chunks_done = 1;
        let progress = envelope.progress();
        assert_eq!(progress.chunks_total, 4);
        assert_eq!(progress.chunks_done, 1);
        assert_eq!(progress.percent, 0.25);

        // All done
        envelope.chunks_done = 4;
        let progress = envelope.progress();
        assert_eq!(progress.percent, 1.0);
    }
}
