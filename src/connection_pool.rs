//! `connection_pool.rs` — Пул постоянных QUIC-соединений к известным контактам.
//!
//! # Модель
//!
//! * Для каждого контакта из таблицы `contacts` поддерживается одно QUIC-соединение.
//! * Фоновая задача `run_connection_pool_loop` периодически проверяет все контакты:
//!   - если соединение живо — оставляет его;
//!   - если разорвано — пытается переподключиться (exponential backoff до MAX_BACKOFF_SECS).
//! * Отправка и sync предпочитают уже открытое соединение из пула.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId};
use tracing::{info, warn};

use crate::metrics::CoreMetrics;
use crate::network::SYNC_ALPN;
use crate::storage::Db;

// ── Константы ─────────────────────────────────────────────────────────────────

/// Интервал sweep-цикла (секунды).
const POOL_SWEEP_INTERVAL_SECS: u64 = 30;
/// Начальный интервал backoff (секунды).
const BACKOFF_BASE_SECS: u64 = 5;
/// Максимальный интервал backoff (секунды).
const MAX_BACKOFF_SECS: u64 = 300;
/// Максимальное количество одновременных попыток переподключения.
const MAX_CONCURRENT_RECONNECTS: usize = 4;

// ── Типы ──────────────────────────────────────────────────────────────────────

/// Запись о состоянии соединения с одним пиром.
#[derive(Debug)]
struct ConnectionEntry {
    conn: Option<Connection>,
    consecutive_failures: u32,
    last_attempt: Option<Instant>,
}

impl ConnectionEntry {
    fn new() -> Self {
        Self {
            conn: None,
            consecutive_failures: 0,
            last_attempt: None,
        }
    }

    /// Текущий backoff-интервал перед следующей попыткой.
    fn backoff_duration(&self) -> Duration {
        let secs = BACKOFF_BASE_SECS
            .saturating_mul(2_u64.saturating_pow(self.consecutive_failures.min(10)))
            .min(MAX_BACKOFF_SECS);
        Duration::from_secs(secs)
    }

    /// Готов ли к повторной попытке (backoff истёк)?
    fn ready_to_retry(&self) -> bool {
        match self.last_attempt {
            None => true,
            Some(t) => t.elapsed() >= self.backoff_duration(),
        }
    }

    /// Пометить соединение как живое.
    fn mark_connected(&mut self, conn: Connection) {
        self.conn = Some(conn);
        self.consecutive_failures = 0;
        self.last_attempt = Some(Instant::now());
    }

    /// Пометить попытку как неуспешную.
    fn mark_failed(&mut self) {
        self.conn = None;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_attempt = Some(Instant::now());
    }

    /// Проверяет, живо ли соединение (QUIC closed → `None`).
    fn is_alive(&mut self) -> bool {
        if let Some(conn) = &self.conn {
            if conn.close_reason().is_some() {
                self.conn = None;
                return false;
            }
            true
        } else {
            false
        }
    }
}

// ── Пул ───────────────────────────────────────────────────────────────────────

/// Пул постоянных QUIC-соединений.
#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<Mutex<HashMap<NodeId, ConnectionEntry>>>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Возвращает живое соединение с пиром, если оно уже открыто.
    #[allow(dead_code)]
    pub fn get_live(&self, peer_id: &NodeId) -> Option<Connection> {
        let mut map = self.inner.lock().ok()?;
        let entry = map.get_mut(peer_id)?;
        if entry.is_alive() {
            entry.conn.clone()
        } else {
            None
        }
    }

    /// Снимок статуса всех записей пула (для FFI/диагностики).
    pub fn status_snapshot(&self) -> Vec<PoolPeerStatus> {
        let mut result = Vec::new();
        if let Ok(mut map) = self.inner.lock() {
            for (peer_id, entry) in map.iter_mut() {
                result.push(PoolPeerStatus {
                    peer_id: peer_id.to_string(),
                    is_connected: entry.is_alive(),
                    consecutive_failures: entry.consecutive_failures,
                    backoff_secs: entry.backoff_duration().as_secs(),
                });
            }
        }
        result
    }

    /// Число активных (живых) соединений.
    pub fn active_count(&self) -> usize {
        let mut count = 0usize;
        if let Ok(mut map) = self.inner.lock() {
            for entry in map.values_mut() {
                if entry.is_alive() {
                    count += 1;
                }
            }
        }
        count
    }
}

/// Снимок статуса одного пира в пуле.
#[derive(Debug, Clone)]
pub struct PoolPeerStatus {
    pub peer_id: String,
    pub is_connected: bool,
    pub consecutive_failures: u32,
    pub backoff_secs: u64,
}

// ── Фоновая задача ────────────────────────────────────────────────────────────

/// Запускает sweep-цикл пула соединений.
///
/// Каждые `POOL_SWEEP_INTERVAL_SECS` секунд:
/// 1. Загружает список контактов из БД.
/// 2. Гарантирует, что у каждого контакта есть запись в пуле.
/// 3. Для записей без живого соединения и с истёкшим backoff — пытается
///    установить новое QUIC-соединение.
///
/// Цикл завершается при закрытии `endpoint` (все connect вернут ошибку).
pub async fn run_connection_pool_loop(
    endpoint: Endpoint,
    db: Arc<Db>,
    pool: ConnectionPool,
    metrics: Arc<CoreMetrics>,
) {
    info!("[pool] connection pool loop started");
    metrics.pool_active_connections.store(
        pool.active_count() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    loop {
        tokio::time::sleep(Duration::from_secs(POOL_SWEEP_INTERVAL_SECS)).await;

        let contacts = match db.list_contacts() {
            Ok(c) => c,
            Err(e) => {
                warn!("[pool] cannot load contacts: {e}");
                continue;
            }
        };

        // Добавить новые записи для контактов, которых ещё нет в пуле.
        {
            let Ok(mut map) = pool.inner.lock() else {
                continue;
            };
            for contact in &contacts {
                if let Ok(node_id) = contact.user_id.parse::<NodeId>() {
                    map.entry(node_id).or_insert_with(ConnectionEntry::new);
                }
            }
        }

        // Собрать пиров, которым нужна попытка переподключения.
        let to_reconnect: Vec<NodeId> = {
            let Ok(mut map) = pool.inner.lock() else {
                continue;
            };
            let mut result = Vec::new();
            for (peer_id, entry) in map.iter_mut() {
                if !entry.is_alive() && entry.ready_to_retry() {
                    result.push(*peer_id);
                    if result.len() >= MAX_CONCURRENT_RECONNECTS {
                        break;
                    }
                }
            }
            result
        };

        for peer_id in to_reconnect {
            // Попытаться найти route hint из DB.
            let node_addr = match build_node_addr_from_hints(&db, &peer_id) {
                Some(addr) => addr,
                None => {
                    // Нет hints — просто NodeId, iroh попробует найти через relay.
                    NodeAddr::new(peer_id)
                }
            };

            let ep = endpoint.clone();
            let pool_clone = pool.clone();
            let peer_id_str = peer_id.to_string();

            // Пометить попытку как начатую (обновить last_attempt), чтобы избежать
            // дублирования задач в следующем цикле sweep, если эта затянется.
            if let Ok(mut map) = pool.inner.lock() {
                if let Some(entry) = map.get_mut(&peer_id) {
                    entry.last_attempt = Some(Instant::now());
                }
            }

            tokio::spawn(async move {
                match ep.connect(node_addr, SYNC_ALPN).await {
                    Ok(conn) => {
                        info!(%peer_id_str, "[pool] connected");
                        if let Ok(mut map) = pool_clone.inner.lock() {
                            if let Some(entry) = map.get_mut(&peer_id) {
                                entry.mark_connected(conn);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(%peer_id_str, err = %e, "[pool] connect failed");
                        if let Ok(mut map) = pool_clone.inner.lock() {
                            if let Some(entry) = map.get_mut(&peer_id) {
                                entry.mark_failed();
                            }
                        }
                    }
                }
            });
        }

        metrics.pool_active_connections.store(
            pool.active_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Строит `NodeAddr` из peer_route_hints таблицы для заданного пира.
fn build_node_addr_from_hints(db: &Db, peer_id: &NodeId) -> Option<NodeAddr> {
    let hint = db.load_peer_route_hint(&peer_id.to_string()).ok()??;
    let mut addr = NodeAddr::new(*peer_id);

    if let Some(relay_url_str) = &hint.relay_url {
        if let Ok(url) = relay_url_str.parse::<iroh::RelayUrl>() {
            addr = addr.with_relay_url(url);
        }
    }

    let direct: Vec<std::net::SocketAddr> = hint
        .direct_addresses
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if !direct.is_empty() {
        addr = addr.with_direct_addresses(direct);
    }

    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_node_id() -> NodeId {
        iroh::SecretKey::generate(&mut OsRng).public()
    }

    #[test]
    fn backoff_is_capped() {
        let mut entry = ConnectionEntry::new();
        for _ in 0..32 {
            entry.mark_failed();
        }
        assert_eq!(
            entry.backoff_duration(),
            Duration::from_secs(MAX_BACKOFF_SECS)
        );
    }

    #[test]
    fn pool_does_not_grow_over_20_cycles_for_same_peers() {
        let pool = ConnectionPool::new();
        let peers: Vec<NodeId> = (0..5).map(|_| random_node_id()).collect();

        for _ in 0..20 {
            let mut map = pool.inner.lock().expect("pool lock");
            for peer_id in &peers {
                let entry = map.entry(*peer_id).or_insert_with(ConnectionEntry::new);
                entry.mark_failed();
            }
        }

        let statuses = pool.status_snapshot();
        assert_eq!(statuses.len(), peers.len());
        assert_eq!(pool.active_count(), 0);
    }
}
