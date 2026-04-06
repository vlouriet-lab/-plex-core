//! Bridge Protocol для обхода цензуры (Obfs4, Meek, Domain Fronting, WebSocket-TLS)
//!
//! Когда прямой P2P и relay-соединение недоступны (РФ, КНР, Иран):
//! используем посредников для туннелирования трафика через менее блокируемые пути.
//!
//! Стратегии:
//! 1. Obfs4 — obfuscated TCP (TLS-подобная завёршка)
//! 2. Meek — HTTPS-маскировка
//! 3. WebSocket TLS — выглядит как обычный WebSocket-трафик
//! 4. Domain Fronting — использование CDN-резидентов (Cloudflare, Fastly)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{info, warn};

/// Bridge-протокол транспорта
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeProtocol {
    /// Obfs4 — obfuscated TCP со скрытой рукопожимкой
    Obfs4,
    /// WebSocket над HTTPS (TLS 1.3)
    WebSocketTLS,
    /// Domain Fronting через CDN
    DomainFronting { front_domain: String },
    /// Meek — HTTPS-маскировка
    Meek { front_url: String },
    /// Fallback: прямой TCP (без обфускации)
    TcpDirect,
}

impl BridgeProtocol {
    pub fn as_str(&self) -> &str {
        match self {
            BridgeProtocol::Obfs4 => "obfs4",
            BridgeProtocol::WebSocketTLS => "websocket",
            BridgeProtocol::DomainFronting { .. } => "domain-fronting",
            BridgeProtocol::Meek { .. } => "meek",
            BridgeProtocol::TcpDirect => "direct",
        }
    }
}

/// Конфигурация bridge-узла
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Уникальный идентификатор моста
    pub id: String,
    /// IP-адрес или домен моста
    pub address: String,
    /// Порт моста
    pub port: u16,
    /// Протокол туннелирования
    pub protocol: BridgeProtocol,
    /// SHA256-отпечаток сертификата (для верификации)
    pub fingerprint: [u8; 32],
    /// Опциональный shared secret для обфускации
    pub shared_secret: Option<[u8; 32]>,
    /// Приоритет (0 = наивысший)
    pub priority: u8,
    /// Активен ли мост
    pub is_active: bool,
    /// Когда был последний успешный коннект
    pub last_success_at: Option<u64>,
    /// Кол-во неудачных попыток подряд
    pub fail_count: u32,
}

impl BridgeConfig {
    /// Создаёт новую конфигурацию bridge-узла
    pub fn new(
        id: impl Into<String>,
        address: impl Into<String>,
        port: u16,
        protocol: BridgeProtocol,
        fingerprint: [u8; 32],
    ) -> Self {
        BridgeConfig {
            id: id.into(),
            address: address.into(),
            port,
            protocol,
            fingerprint,
            shared_secret: None,
            priority: 100,
            is_active: true,
            last_success_at: None,
            fail_count: 0,
        }
    }

    /// Парсит bridge-line в формате Tor:
    /// `obfs4 1.2.3.4:1234 fingerprint=ABCD... shared_secret=XYZ...`
    pub fn from_bridge_line(line: &str) -> Result<Self, BridgeError> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(BridgeError::InvalidBridgeLine(
                "Requires at least: protocol address:port".into(),
            ));
        }

        let protocol_str = parts[0];
        let address_port = parts[1];

        // Парсим address:port
        let (address, port) = if let Some(colon_pos) = address_port.rfind(':') {
            let addr = address_port[..colon_pos].to_string();
            let port_str = &address_port[colon_pos + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| BridgeError::InvalidBridgeLine("Invalid port".into()))?;
            (addr, port)
        } else {
            return Err(BridgeError::InvalidBridgeLine("Missing port".into()));
        };

        // Парсим протокол
        let protocol = match protocol_str {
            "obfs4" => BridgeProtocol::Obfs4,
            "meek" => BridgeProtocol::Meek {
                front_url: String::new(),
            },
            "websocket" => BridgeProtocol::WebSocketTLS,
            "domain-fronting" => BridgeProtocol::DomainFronting {
                front_domain: String::new(),
            },
            _ => BridgeProtocol::TcpDirect,
        };

        // Генерируем ID из address:port
        let id = format!("{}-{}", address, port);

        // Парсим параметры
        let mut fingerprint = [0u8; 32];
        let mut shared_secret = None;

        for part in &parts[2..] {
            if let Some(fp_str) = part.strip_prefix("fingerprint=") {
                if fp_str.len() == 64 {
                    if let Ok(bytes) = hex::decode(fp_str) {
                        if bytes.len() == 32 {
                            fingerprint.copy_from_slice(&bytes[..32]);
                        }
                    }
                }
            } else if let Some(secret_str) = part.strip_prefix("shared_secret=") {
                if secret_str.len() == 64 {
                    if let Ok(bytes) = hex::decode(secret_str) {
                        if bytes.len() == 32 {
                            let mut secret = [0u8; 32];
                            secret.copy_from_slice(&bytes[..32]);
                            shared_secret = Some(secret);
                        }
                    }
                }
            }
        }

        Ok(BridgeConfig {
            id,
            address,
            port,
            protocol,
            fingerprint,
            shared_secret,
            priority: 100,
            is_active: true,
            last_success_at: None,
            fail_count: 0,
        })
    }

    /// Обновляет успешное соединение
    pub fn mark_success(&mut self) {
        self.last_success_at = Some(current_unix_timestamp());
        self.fail_count = 0;
    }

    /// Обновляет неудачное соединение
    pub fn mark_failure(&mut self) {
        self.fail_count += 1;
    }

    /// Вернёт true если мост нужно временно пропустить (много неудач)
    pub fn is_temporarily_down(&self) -> bool {
        // После 5 неудач мост считаем временно недоступным.
        // Если успешного коннекта ещё не было, уходим в cooldown сразу.
        if self.fail_count < 5 {
            return false;
        }

        match self.last_success_at {
            Some(last_success) => current_unix_timestamp().saturating_sub(last_success) < 300,
            None => true,
        }
    }

    /// Преобразует в DNS-подобный адрес для доступа
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Статус bridge-соединения
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeStatus {
    pub bridge_id: String,
    pub is_active: bool,
    pub protocol: String,
    pub last_success_at: Option<u64>,
    pub fail_count: u32,
    pub is_temporarily_down: bool,
}

/// Менеджер bridge-узлов
pub struct BridgeManager {
    bridges: Arc<std::sync::Mutex<HashMap<String, BridgeConfig>>>,
}

impl BridgeManager {
    /// Создаёт новый менеджер
    pub fn new() -> Self {
        BridgeManager {
            bridges: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Добавляет новый bridge
    pub fn add_bridge(&self, config: BridgeConfig) -> Result<(), BridgeError> {
        let mut bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;

        if bridges.contains_key(&config.id) {
            return Err(BridgeError::BridgeAlreadyExists(config.id));
        }

        info!(
            "Adding bridge: {} ({})",
            config.id,
            config.protocol.as_str()
        );
        bridges.insert(config.id.clone(), config);
        Ok(())
    }

    /// Добавляет bridge из строки Tor-формата
    pub fn add_bridge_from_line(&self, line: &str) -> Result<String, BridgeError> {
        let config = BridgeConfig::from_bridge_line(line)?;
        let id = config.id.clone();
        self.add_bridge(config)?;
        Ok(id)
    }

    /// Активирует или деактивирует bridge
    pub fn set_bridge_active(&self, bridge_id: &str, active: bool) -> Result<(), BridgeError> {
        let mut bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;

        if let Some(bridge) = bridges.get_mut(bridge_id) {
            bridge.is_active = active;
            info!(
                "Bridge {} is now {}",
                bridge_id,
                if active { "active" } else { "inactive" }
            );
            Ok(())
        } else {
            Err(BridgeError::BridgeNotFound(bridge_id.to_string()))
        }
    }

    /// Получает статусы всех bridge-узлов
    pub fn get_all_statuses(&self) -> Result<Vec<BridgeStatus>, BridgeError> {
        let bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;

        Ok(bridges
            .values()
            .map(|b| BridgeStatus {
                bridge_id: b.id.clone(),
                is_active: b.is_active,
                protocol: b.protocol.as_str().to_string(),
                last_success_at: b.last_success_at,
                fail_count: b.fail_count,
                is_temporarily_down: b.is_temporarily_down(),
            })
            .collect())
    }

    /// Получает лучший доступный bridge для соединения
    pub fn get_best_available_bridge(&self) -> Result<Option<BridgeConfig>, BridgeError> {
        let mut bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;

        // Фильтруем по активности и временной недоступности
        let mut candidates: Vec<_> = bridges
            .values_mut()
            .filter(|b| b.is_active && !b.is_temporarily_down())
            .collect();

        if candidates.is_empty() {
            return Ok(None);
        }

        // Сортируем по приоритету (0 = наивысший)
        candidates.sort_by_key(|b| (b.priority, b.fail_count));

        Ok(Some(candidates[0].clone()))
    }

    /// Обновляет статус bridge'а после попытки соединения
    pub fn update_bridge_status(&self, bridge_id: &str, success: bool) -> Result<(), BridgeError> {
        let mut bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;

        if let Some(bridge) = bridges.get_mut(bridge_id) {
            if success {
                bridge.mark_success();
                info!("Bridge {} connection successful", bridge_id);
            } else {
                bridge.mark_failure();
                warn!(
                    "Bridge {} connection failed (attempt: {})",
                    bridge_id, bridge.fail_count
                );
            }
            Ok(())
        } else {
            Err(BridgeError::BridgeNotFound(bridge_id.to_string()))
        }
    }

    /// Очищает все bridges
    pub fn clear_all_bridges(&self) -> Result<(), BridgeError> {
        let mut bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;
        bridges.clear();
        Ok(())
    }

    /// Получает bridge по ID
    pub fn get_bridge(&self, bridge_id: &str) -> Result<Option<BridgeConfig>, BridgeError> {
        let bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;
        Ok(bridges.get(bridge_id).cloned())
    }

    /// Количество активных bridges
    pub fn active_count(&self) -> Result<usize, BridgeError> {
        let bridges = self.bridges.lock().map_err(|_| BridgeError::LockFailure)?;
        Ok(bridges.values().filter(|b| b.is_active).count())
    }
}

impl Default for BridgeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Ошибки bridge-протокола
#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Invalid bridge line: {0}")]
    InvalidBridgeLine(String),

    #[error("Bridge not found: {0}")]
    BridgeNotFound(String),

    #[error("Bridge already exists: {0}")]
    BridgeAlreadyExists(String),

    #[error("Bridge connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Lock failure (mutex poisoned)")]
    LockFailure,

    #[error("No available bridges")]
    NoAvailableBridges,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    #[error("TLS error: {0}")]
    TlsError(String),
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
    fn test_bridge_config_from_line() {
        let line = "obfs4 1.2.3.4:1234";
        let config = BridgeConfig::from_bridge_line(line).unwrap();
        assert_eq!(config.address, "1.2.3.4");
        assert_eq!(config.port, 1234);
        assert_eq!(config.protocol, BridgeProtocol::Obfs4);
    }

    #[test]
    fn test_bridge_manager_add() {
        let mgr = BridgeManager::new();
        let config = BridgeConfig::new(
            "test-bridge",
            "example.com",
            8080,
            BridgeProtocol::WebSocketTLS,
            [0u8; 32],
        );
        mgr.add_bridge(config).unwrap();
        assert_eq!(mgr.active_count().unwrap(), 1);
    }

    #[test]
    fn test_bridge_manager_duplicate() {
        let mgr = BridgeManager::new();
        let config = BridgeConfig::new(
            "test-bridge",
            "example.com",
            8080,
            BridgeProtocol::WebSocketTLS,
            [0u8; 32],
        );
        mgr.add_bridge(config.clone()).unwrap();
        let result = mgr.add_bridge(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_fail_count() {
        let mut config = BridgeConfig::new(
            "test-bridge",
            "example.com",
            8080,
            BridgeProtocol::Meek {
                front_url: "https://example.com".into(),
            },
            [0u8; 32],
        );

        for _ in 0..3 {
            config.mark_failure();
        }

        assert_eq!(config.fail_count, 3);
        assert!(!config.is_temporarily_down()); // Нужно 5+ неудач

        for _ in 0..2 {
            config.mark_failure();
        }

        assert!(config.is_temporarily_down());
    }
}
