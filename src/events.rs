//! Unified Event Stream — типобезопасные события Plex Core
//!
//! Заменяет разрозненные callback'и на единый типобезопасный enum.
//! Используется для уведомлений UI о событиях в ядре.

use serde::{Deserialize, Serialize};

/// Главный event enum для Plex Core
/// Все события, происходящие в ядре, представляются этим типом.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum PlexCoreEvent {
    /// Сетевое соединение восстановлено
    NetworkConnected,

    /// Сетевое соединение потеряно
    NetworkDisconnected { reason: Option<String> },

    /// Пир появился в сети
    PeerOnline { peer_id: String },

    /// Пир отключился
    PeerOffline { peer_id: String },

    /// Получено новое сообщение
    MessageReceived {
        message_id: String,
        from_peer_id: String,
        message_type: String, // "text", "media", "call_signal", ...
    },

    /// Статус доставки сообщения изменился
    MessageStatusChanged {
        message_id: String,
        status: String, // "pending", "delivered", "failed", ...
    },

    /// Уведомление о входящей медиа (звонок, видео, etc.)
    CallIncoming {
        call_id: String,
        from_peer_id: String,
        has_video: bool,
    },

    /// Состояние медиа-сессии изменилось
    CallStateChanged {
        call_id: String,
        state: String, // "ringing", "connecting", "active", "ended"
    },

    /// Событие трансфера файла
    TransferEvent {
        transfer_id: String,
        event_kind: String,    // "started", "progress", "completed", "failed"
        progress: Option<f32>, // 0.0-1.0
    },

    /// Пир обнаружен в DHT (именной поиск)
    PeerDiscovered {
        peer_id: String,
        username: Option<String>,
        display_name: Option<String>,
    },

    /// Ошибка в ядре
    Error { error_code: String, message: String },

    /// Bridge-узел подключился
    BridgeConnected { bridge_id: String },

    /// Bridge-узел отключился
    BridgeDisconnected {
        bridge_id: String,
        reason: Option<String>,
    },

    /// Синхронизация завершена
    SyncCompleted {
        peer_id: Option<String>,
        events_synced: u32,
    },

    /// DHT cache rotation произошла
    DhtCacheRotated { evicted_entries: u32 },
}

impl PlexCoreEvent {
    /// Возвращает категорию события для фильтрации
    pub fn category(&self) -> &str {
        match self {
            PlexCoreEvent::NetworkConnected | PlexCoreEvent::NetworkDisconnected { .. } => {
                "network"
            }
            PlexCoreEvent::PeerOnline { .. } | PlexCoreEvent::PeerOffline { .. } => "peer",
            PlexCoreEvent::MessageReceived { .. } | PlexCoreEvent::MessageStatusChanged { .. } => {
                "message"
            }
            PlexCoreEvent::CallIncoming { .. } | PlexCoreEvent::CallStateChanged { .. } => "call",
            PlexCoreEvent::TransferEvent { .. } => "transfer",
            PlexCoreEvent::PeerDiscovered { .. } => "discovery",
            PlexCoreEvent::BridgeConnected { .. } | PlexCoreEvent::BridgeDisconnected { .. } => {
                "bridge"
            }
            PlexCoreEvent::SyncCompleted { .. } => "sync",
            PlexCoreEvent::DhtCacheRotated { .. } => "dht",
            PlexCoreEvent::Error { .. } => "error",
        }
    }

    /// Возвращает человеко-читаемое описание события
    pub fn description(&self) -> String {
        match self {
            PlexCoreEvent::NetworkConnected => "Network connected".to_string(),
            PlexCoreEvent::NetworkDisconnected { reason } => {
                format!(
                    "Network disconnected{}",
                    reason
                        .as_ref()
                        .map(|r| format!(": {}", r))
                        .unwrap_or_default()
                )
            }
            PlexCoreEvent::PeerOnline { peer_id } => format!("Peer {} is online", peer_id),
            PlexCoreEvent::PeerOffline { peer_id } => format!("Peer {} is offline", peer_id),
            PlexCoreEvent::MessageReceived {
                from_peer_id,
                message_type,
                ..
            } => {
                format!("Message ({}) from {}", message_type, from_peer_id)
            }
            PlexCoreEvent::MessageStatusChanged { message_id, status } => {
                format!("Message {} status: {}", message_id, status)
            }
            PlexCoreEvent::CallIncoming {
                from_peer_id,
                has_video,
                ..
            } => {
                format!(
                    "Incoming call from {} {}",
                    from_peer_id,
                    if *has_video { "(video)" } else { "(audio)" }
                )
            }
            PlexCoreEvent::CallStateChanged { call_id, state } => {
                format!("Call {} state: {}", call_id, state)
            }
            PlexCoreEvent::TransferEvent {
                transfer_id,
                event_kind,
                progress,
            } => {
                if let Some(p) = progress {
                    format!(
                        "Transfer {}: {} ({}%)",
                        transfer_id,
                        event_kind,
                        (p * 100.0) as u32
                    )
                } else {
                    format!("Transfer {}: {}", transfer_id, event_kind)
                }
            }
            PlexCoreEvent::PeerDiscovered {
                username,
                display_name,
                ..
            } => {
                format!(
                    "Peer discovered: {} ({})",
                    username.as_ref().unwrap_or(&"unknown".to_string()),
                    display_name.as_ref().unwrap_or(&"no name".to_string())
                )
            }
            PlexCoreEvent::Error {
                error_code,
                message,
            } => {
                format!("Error [{}]: {}", error_code, message)
            }
            PlexCoreEvent::BridgeConnected { bridge_id } => {
                format!("Bridge {} connected", bridge_id)
            }
            PlexCoreEvent::BridgeDisconnected { bridge_id, reason } => {
                format!(
                    "Bridge {} disconnected{}",
                    bridge_id,
                    reason
                        .as_ref()
                        .map(|r| format!(": {}", r))
                        .unwrap_or_default()
                )
            }
            PlexCoreEvent::SyncCompleted {
                peer_id,
                events_synced,
            } => {
                if let Some(pid) = peer_id {
                    format!("Synced {} events from {}", events_synced, pid)
                } else {
                    format!("Synced {} events", events_synced)
                }
            }
            PlexCoreEvent::DhtCacheRotated { evicted_entries } => {
                format!("DHT cache rotated ({} entries evicted)", evicted_entries)
            }
        }
    }

    /// Возвращает severity level события (для логирования)
    pub fn severity(&self) -> LogLevel {
        match self {
            PlexCoreEvent::Error { .. } => LogLevel::Error,
            PlexCoreEvent::NetworkDisconnected { .. }
            | PlexCoreEvent::BridgeDisconnected { .. } => LogLevel::Warn,
            PlexCoreEvent::MessageReceived { .. } | PlexCoreEvent::CallIncoming { .. } => {
                LogLevel::Info
            }
            _ => LogLevel::Debug,
        }
    }
}

/// Log level для события
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_category() {
        let evt = PlexCoreEvent::MessageReceived {
            message_id: "123".to_string(),
            from_peer_id: "peer1".to_string(),
            message_type: "text".to_string(),
        };
        assert_eq!(evt.category(), "message");

        let evt = PlexCoreEvent::Error {
            error_code: "E001".to_string(),
            message: "Something failed".to_string(),
        };
        assert_eq!(evt.category(), "error");
        assert_eq!(evt.severity(), LogLevel::Error);
    }

    #[test]
    fn test_event_description() {
        let evt = PlexCoreEvent::PeerOnline {
            peer_id: "alice".to_string(),
        };
        let desc = evt.description();
        assert!(desc.contains("alice"));
        assert!(desc.contains("online"));
    }

    #[test]
    fn test_transfer_event_with_progress() {
        let evt = PlexCoreEvent::TransferEvent {
            transfer_id: "t123".to_string(),
            event_kind: "progress".to_string(),
            progress: Some(0.75),
        };
        let desc = evt.description();
        assert!(desc.contains("75%"));
    }

    #[test]
    fn test_event_serialization() {
        let evt = PlexCoreEvent::CallIncoming {
            call_id: "call-123".to_string(),
            from_peer_id: "bob".to_string(),
            has_video: true,
        };

        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("call_incoming"));

        let deserialized: PlexCoreEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, deserialized);
    }
}
