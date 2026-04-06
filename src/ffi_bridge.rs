//! FFI-слой для Bridge Protocol
//!
//! Экспортирует методы для управления bridge-узлами через UniFFI (Kotlin/Swift).

use crate::bridge::{BridgeConfig, BridgeManager, BridgeStatus};
use crate::PlexError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Record для передачи статуса bridge-узла через FFI
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct BridgeStatusRecord {
    pub bridge_id: String,
    pub is_active: bool,
    pub protocol: String,
    pub last_success_at: Option<u64>,
    pub fail_count: u32,
    pub is_temporarily_down: bool,
}

impl From<BridgeStatus> for BridgeStatusRecord {
    fn from(s: BridgeStatus) -> Self {
        BridgeStatusRecord {
            bridge_id: s.bridge_id,
            is_active: s.is_active,
            protocol: s.protocol,
            last_success_at: s.last_success_at,
            fail_count: s.fail_count,
            is_temporarily_down: s.is_temporarily_down,
        }
    }
}

/// Record для передачи конфигурации bridge-узла через FFI
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct BridgeConfigRecord {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub priority: u8,
    pub is_active: bool,
}

impl From<&BridgeConfig> for BridgeConfigRecord {
    fn from(b: &BridgeConfig) -> Self {
        BridgeConfigRecord {
            id: b.id.clone(),
            address: b.address.clone(),
            port: b.port,
            protocol: b.protocol.as_str().to_string(),
            priority: b.priority,
            is_active: b.is_active,
        }
    }
}

/// FFI-обёртка для BridgeManager
#[derive(uniffi::Object)]
pub struct PlexBridgeManager {
    pub(crate) inner: Arc<BridgeManager>,
}

#[uniffi::export]
impl PlexBridgeManager {
    /// Создаёт новый менеджер bridge-узлов
    #[uniffi::constructor]
    pub fn new() -> Self {
        PlexBridgeManager {
            inner: Arc::new(BridgeManager::new()),
        }
    }

    /// Добавляет bridge из строки в формате Tor:
    /// `obfs4 1.2.3.4:1234 fingerprint=... shared_secret=...`
    pub fn add_bridge_from_line(&self, line: String) -> Result<String, PlexError> {
        self.inner
            .add_bridge_from_line(&line)
            .map_err(|e| PlexError::Validation { msg: e.to_string() })
    }

    /// Активирует или деактивирует bridge по ID
    pub fn set_bridge_active(&self, bridge_id: String, active: bool) -> Result<(), PlexError> {
        self.inner
            .set_bridge_active(&bridge_id, active)
            .map_err(|e| PlexError::Validation { msg: e.to_string() })
    }

    /// Получает статусы всех bridge-узлов
    pub fn get_all_statuses(&self) -> Result<Vec<BridgeStatusRecord>, PlexError> {
        self.inner
            .get_all_statuses()
            .map(|statuses| statuses.into_iter().map(|s| s.into()).collect())
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает лучший доступный bridge для соединения
    pub fn get_best_available_bridge(&self) -> Result<Option<BridgeConfigRecord>, PlexError> {
        self.inner
            .get_best_available_bridge()
            .map(|opt| opt.map(|b| (&b).into()))
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Обновляет статус bridge'а после попытки соединения
    pub fn update_bridge_status(&self, bridge_id: String, success: bool) -> Result<(), PlexError> {
        self.inner
            .update_bridge_status(&bridge_id, success)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Получает конфигурацию bridge'а по ID
    pub fn get_bridge(&self, bridge_id: String) -> Result<Option<BridgeConfigRecord>, PlexError> {
        self.inner
            .get_bridge(&bridge_id)
            .map(|opt| opt.map(|b| (&b).into()))
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Кол-во активных bridge-узлов
    pub fn active_count(&self) -> Result<u32, PlexError> {
        self.inner
            .active_count()
            .map(|c| c as u32)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }

    /// Очищает все bridge-узлы
    pub fn clear_all_bridges(&self) -> Result<(), PlexError> {
        self.inner
            .clear_all_bridges()
            .map_err(|e| PlexError::Internal { msg: e.to_string() })
    }
}

impl Default for PlexBridgeManager {
    fn default() -> Self {
        Self::new()
    }
}
