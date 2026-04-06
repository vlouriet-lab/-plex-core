//! Message Router — интеллектуальная маршрутизация сообщений с retry-логикой
//!
//! Отвечает за:
//! - Выбор оптимального маршрута (Direct, Relay, Local mDNS, GroupBroadcast)
//! - Retry-очередь для неудачных сообщений
//! - Exponential backoff при переотправке
//! - Статистика доставки

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{info, warn};

/// Решение о маршруте доставки сообщения
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Отправить прямо пиру через P2P
    Direct { peer_id: String, via_relay: bool },
    /// Отправить группе (gossipsub broadcast)
    GroupBroadcast { group_id: [u8; 16] },
    /// Отправить локально через mDNS (Bluetooth, локальная сеть)
    LocalMdns { peer_id: String },
}

impl RoutingDecision {
    pub fn target_peer_id(&self) -> Option<&str> {
        match self {
            RoutingDecision::Direct { peer_id, .. } => Some(peer_id),
            RoutingDecision::LocalMdns { peer_id } => Some(peer_id),
            RoutingDecision::GroupBroadcast { .. } => None,
        }
    }

    pub fn is_group_broadcast(&self) -> bool {
        matches!(self, RoutingDecision::GroupBroadcast { .. })
    }
}

/// Исходящее сообщение с метаданными для retry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundMessageEnvelope {
    /// Уникальный ID сообщения ([u8; 16] в hex)
    pub message_id: String,
    /// Байтовое представление сообщения (bincode-серилизованное)
    pub payload: Vec<u8>,
    /// Решение о маршруте
    pub routing: RoutingDecision,
    /// Номер попытки доставки (0 = первая попытка)
    pub attempt: u32,
    /// Quando было создано сообщение (Unix timestamp, секи)
    pub created_at: u64,
    /// Когда можно повторить попытку (Unix timestamp, секи). None = немедленно.
    pub backoff_until: Option<u64>,
    /// Максимум попыток (default: 5)
    pub max_attempts: u32,
}

impl OutboundMessageEnvelope {
    pub fn new(message_id: String, payload: Vec<u8>, routing: RoutingDecision) -> Self {
        OutboundMessageEnvelope {
            message_id,
            payload,
            routing,
            attempt: 0,
            created_at: current_unix_timestamp(),
            backoff_until: None,
            max_attempts: 5,
        }
    }

    /// Возвращает true если сообщение "бесполезно" повторять (избыток попыток)
    pub fn should_give_up(&self) -> bool {
        self.attempt >= self.max_attempts
    }

    /// Возвращает true если сейчас можно повторить попытку
    pub fn can_retry_now(&self) -> bool {
        if let Some(backoff_until) = self.backoff_until {
            current_unix_timestamp() >= backoff_until
        } else {
            true
        }
    }

    /// Вычисляет exponential backoff для следующей попытки
    /// Formula: 2^attempt * 1s, max 5 минут
    pub fn calculate_next_backoff_secs(attempt: u32) -> u64 {
        let base_secs = 1u64 << attempt.min(16);
        base_secs.min(300) // cap at 5 minutes
    }

    /// Подготавливает сообщение к переотправке
    pub fn prepare_retry(&mut self) {
        self.attempt += 1;
        let backoff_secs = Self::calculate_next_backoff_secs(self.attempt);
        self.backoff_until = Some(current_unix_timestamp() + backoff_secs);
        info!(
            "Prepared message {} for retry (attempt {}, backoff {}s)",
            self.message_id, self.attempt, backoff_secs
        );
    }

    /// Размер в байтах
    pub fn size_bytes(&self) -> usize {
        self.payload.len()
    }
}

/// Статус доставки сообщения
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Ожидает отправки
    Pending,
    /// В процессе отправки
    Sending,
    /// Успешно доставлено
    Delivered,
    /// Неудача после всех попыток
    Failed,
    /// Отменено пользователем
    Cancelled,
}

impl DeliveryStatus {
    pub fn as_str(&self) -> &str {
        match self {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::Sending => "sending",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::Failed => "failed",
            DeliveryStatus::Cancelled => "cancelled",
        }
    }
}

/// Запись доставки сообщения в БД
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub message_id: String,
    pub routing: RoutingDecision,
    pub status: DeliveryStatus,
    pub attempt: u32,
    pub max_attempts: u32,
    pub created_at: u64,
    pub last_attempt_at: Option<u64>,
    pub delivered_at: Option<u64>,
    pub failed_reason: Option<String>,
}

/// Менеджер retry-очереди для неудачных сообщений
pub struct MessageRetryQueue {
    /// message_id -> OutboundMessageEnvelope
    pending: std::sync::Arc<std::sync::Mutex<HashMap<String, OutboundMessageEnvelope>>>,
    /// message_id -> DeliveryRecord (история)
    history: std::sync::Arc<std::sync::Mutex<HashMap<String, DeliveryRecord>>>,
}

impl MessageRetryQueue {
    /// Создаёт новую пусту очередь
    pub fn new() -> Self {
        MessageRetryQueue {
            pending: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            history: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Добавляет сообщение в очередь
    pub fn enqueue(&self, envelope: OutboundMessageEnvelope) -> Result<(), MessageRouterError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;

        info!(
            "Enqueued message {} for delivery (routing: {:?})",
            envelope.message_id, envelope.routing
        );
        pending.insert(envelope.message_id.clone(), envelope);
        Ok(())
    }

    /// Получает все сообщения для повторной отправки
    pub fn get_pending_for_retry(
        &self,
    ) -> Result<Vec<OutboundMessageEnvelope>, MessageRouterError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;

        let mut result = Vec::new();
        let mut to_remove = Vec::new();

        for (msg_id, envelope) in pending.iter_mut() {
            if envelope.should_give_up() {
                to_remove.push(msg_id.clone());
                warn!(
                    "Giving up on message {} after {} attempts",
                    msg_id, envelope.attempt
                );
            } else if envelope.can_retry_now() {
                result.push(envelope.clone());
                to_remove.push(msg_id.clone());
            }
        }

        // Удаляем обработанные сообщения
        for msg_id in to_remove {
            pending.remove(&msg_id);
        }

        Ok(result)
    }

    /// Отмечает сообщение как успешно доставленное
    pub fn mark_delivered(&self, message_id: &str) -> Result<(), MessageRouterError> {
        let mut history = self
            .history
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;

        if let Some(record) = history.get_mut(message_id) {
            record.status = DeliveryStatus::Delivered;
            record.delivered_at = Some(current_unix_timestamp());
            info!("Message {} marked as delivered", message_id);
        }

        Ok(())
    }

    /// Отмечает сообщение как неудачное
    pub fn mark_failed(
        &self,
        message_id: &str,
        reason: Option<String>,
    ) -> Result<(), MessageRouterError> {
        let mut history = self
            .history
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;

        if let Some(record) = history.get_mut(message_id) {
            record.status = DeliveryStatus::Failed;
            record.failed_reason = reason;
            warn!(
                "Message {} marked as failed: {:?}",
                message_id, record.failed_reason
            );
        }

        Ok(())
    }

    /// Получает историю доставки сообщения
    pub fn get_delivery_record(
        &self,
        message_id: &str,
    ) -> Result<Option<DeliveryRecord>, MessageRouterError> {
        let history = self
            .history
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;
        Ok(history.get(message_id).cloned())
    }

    /// Количество сообщений в очереди
    pub fn pending_count(&self) -> Result<usize, MessageRouterError> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;
        Ok(pending.len())
    }

    /// Очистить всю очередь
    pub fn clear(&self) -> Result<(), MessageRouterError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;
        pending.clear();
        Ok(())
    }

    /// Получить все записи истории
    pub fn get_all_history(&self) -> Result<Vec<DeliveryRecord>, MessageRouterError> {
        let history = self
            .history
            .lock()
            .map_err(|_| MessageRouterError::LockFailure)?;
        Ok(history.values().cloned().collect())
    }
}

impl Default for MessageRetryQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Ошибки message router'а
#[derive(Error, Debug)]
pub enum MessageRouterError {
    #[error("Lock failure (mutex poisoned)")]
    LockFailure,

    #[error("Invalid routing decision: {0}")]
    InvalidRoutingDecision(String),

    #[error("Queue overflow: {0}")]
    QueueOverflow(String),

    #[error("No route available")]
    NoRouteAvailable,

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("Failed to send: {0}")]
    SendFailure(String),
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
    fn test_routing_decision_target_peer_id() {
        let direct = RoutingDecision::Direct {
            peer_id: "peer123".to_string(),
            via_relay: false,
        };
        assert_eq!(direct.target_peer_id(), Some("peer123"));

        let mdns = RoutingDecision::LocalMdns {
            peer_id: "peer456".to_string(),
        };
        assert_eq!(mdns.target_peer_id(), Some("peer456"));

        let group = RoutingDecision::GroupBroadcast {
            group_id: [0u8; 16],
        };
        assert_eq!(group.target_peer_id(), None);
        assert!(group.is_group_broadcast());
    }

    #[test]
    fn test_backoff_calculation() {
        let backoff_0 = OutboundMessageEnvelope::calculate_next_backoff_secs(0);
        assert_eq!(backoff_0, 1); // 2^0 = 1

        let backoff_1 = OutboundMessageEnvelope::calculate_next_backoff_secs(1);
        assert_eq!(backoff_1, 2); // 2^1 = 2

        let backoff_5 = OutboundMessageEnvelope::calculate_next_backoff_secs(5);
        assert_eq!(backoff_5, 32); // 2^5 = 32

        let backoff_max = OutboundMessageEnvelope::calculate_next_backoff_secs(100);
        assert_eq!(backoff_max, 300); // capped at 300s (5 minutes)
    }

    #[test]
    fn test_envelope_retry_logic() {
        let mut envelope = OutboundMessageEnvelope::new(
            "msg-123".to_string(),
            vec![1, 2, 3],
            RoutingDecision::Direct {
                peer_id: "peer1".to_string(),
                via_relay: false,
            },
        );

        assert!(!envelope.should_give_up());
        assert!(envelope.can_retry_now());

        // Simulate retry
        for i in 0..3 {
            envelope.prepare_retry();
            assert_eq!(envelope.attempt, i + 1);
            assert!(!envelope.can_retry_now()); // backoff is set
        }

        assert!(!envelope.should_give_up());

        // Max out attempts
        for _ in 0..10 {
            envelope.prepare_retry();
        }
        assert!(envelope.should_give_up());
    }

    #[test]
    fn test_retry_queue() {
        let queue = MessageRetryQueue::new();

        let envelope = OutboundMessageEnvelope::new(
            "msg-1".to_string(),
            vec![1, 2, 3],
            RoutingDecision::Direct {
                peer_id: "p1".to_string(),
                via_relay: false,
            },
        );

        queue.enqueue(envelope).unwrap();
        assert_eq!(queue.pending_count().unwrap(), 1);

        let pending = queue.get_pending_for_retry().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(queue.pending_count().unwrap(), 0);
    }

    #[test]
    fn test_delivery_status_str() {
        assert_eq!(DeliveryStatus::Pending.as_str(), "pending");
        assert_eq!(DeliveryStatus::Delivered.as_str(), "delivered");
        assert_eq!(DeliveryStatus::Failed.as_str(), "failed");
    }
}
