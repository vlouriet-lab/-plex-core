//! `ffi_profile.rs` — FFI-модуль управления профилями, контактами и relay-узлами.
//!
//! Содержит:
//! * Типы: [`UserProfileRecord`], [`ContactRecord`], [`RelayNodeRecord`].
//! * Методы PlexNode для работы с публичными профилями, локальными контактами
//!   и реестром relay-узлов (репутация, выбор лучшего).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{storage, PlexError, PlexNode};

// ── Константы ─────────────────────────────────────────────────────────────────

const RELAY_MIN_REPUTATION: i64 = 20;
const RELAY_MAX_STALE_SECS: i64 = 10 * 60;
const PROFILE_ANNOUNCE_TTL_SECS: u64 = 24 * 60 * 60;

// ── Типы ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Record)]
pub struct UserProfileRecord {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub avatar_data: Option<Vec<u8>>,
    pub bio: Option<String>,
    pub public_key: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ContactRecord {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub custom_avatar_data: Option<Vec<u8>>,
    pub trust_level: String,
    pub added_at: i64,
}

/// Пир, обнаруженный через DHT-поиск по username.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DiscoveredPeerRecord {
    pub node_id: String,
    pub username: String,
    pub display_name: String,
    pub relay_url: Option<String>,
    pub announced_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayNodeRecord {
    pub node_id: String,
    pub reputation: i64,
    pub messages_relayed: u64,
    pub uptime_percent: f64,
    pub last_heartbeat: i64,
    pub is_active: bool,
}

// ── FFI-методы PlexNode ───────────────────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    /// Создает или обновляет мой публичный профиль.
    pub fn create_profile(
        &self,
        username: String,
        display_name: String,
        avatar_data: Vec<u8>,
    ) -> Result<UserProfileRecord, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let user_id = self.iroh.node_id().to_string();
        let existing = self.db.load_public_profile(&user_id)?;
        let created_at = existing.as_ref().map(|p| p.created_at).unwrap_or(now);

        let profile = storage::PublicProfile {
            user_id,
            username,
            display_name,
            avatar_blob: if avatar_data.is_empty() {
                None
            } else {
                Some(avatar_data)
            },
            bio: existing.and_then(|p| p.bio),
            public_key: self.iroh.secret_key().public().to_string(),
            created_at,
            updated_at: now,
        };

        self.db.save_public_profile(&profile)?;
        self.announce_profile_if_present(PROFILE_ANNOUNCE_TTL_SECS)?;
        Ok(to_profile_record(profile))
    }

    /// Обновляет display_name в моем профиле.
    pub fn update_profile(&self, display_name: String) -> Result<(), PlexError> {
        let my_user_id = self.iroh.node_id().to_string();
        let Some(mut profile) = self.db.load_public_profile(&my_user_id)? else {
            return Err(PlexError::NotFound {
                msg: "Profile does not exist. Call create_profile first".into(),
            });
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        profile.display_name = display_name;
        profile.updated_at = now;
        self.db.save_public_profile(&profile)?;
        self.announce_profile_if_present(PROFILE_ANNOUNCE_TTL_SECS)
    }

    /// Возвращает мой профиль.
    pub fn get_my_profile(&self) -> Result<UserProfileRecord, PlexError> {
        let my_user_id = self.iroh.node_id().to_string();
        let profile =
            self.db
                .load_public_profile(&my_user_id)?
                .ok_or_else(|| PlexError::NotFound {
                    msg: "My profile not found".into(),
                })?;

        Ok(to_profile_record(profile))
    }

    /// Возвращает профиль по user_id.
    pub fn get_profile(&self, user_id: String) -> Result<UserProfileRecord, PlexError> {
        let profile =
            self.db
                .load_public_profile(&user_id)?
                .ok_or_else(|| PlexError::NotFound {
                    msg: format!("Profile not found for user_id {user_id}"),
                })?;

        Ok(to_profile_record(profile))
    }

    /// Добавляет контакт в локальный список.
    pub fn add_contact(
        &self,
        user_id: String,
        username: String,
        display_name: String,
    ) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let contact = storage::Contact {
            user_id,
            username,
            display_name,
            custom_avatar_blob: None,
            trust_level: "Unverified".to_string(),
            added_at: now,
        };

        self.db.upsert_contact(&contact)
    }

    /// Список локальных контактов.
    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>, PlexError> {
        let contacts = self.db.list_contacts()?;
        Ok(contacts.into_iter().map(to_contact_record).collect())
    }

    /// Удаляет контакт из локального списка.
    pub fn remove_contact(&self, user_id: String) -> Result<(), PlexError> {
        self.db.remove_contact(&user_id)
    }

    /// Поиск профиля по username в локальном слое данных.
    pub fn lookup_profile_by_username(
        &self,
        username: String,
    ) -> Result<Option<UserProfileRecord>, PlexError> {
        Ok(self
            .db
            .load_public_profile_by_username(&username)?
            .map(to_profile_record))
    }

    /// Поиск локальных контактов по username (substring match, макс 50).
    pub fn search_contacts_by_username(
        &self,
        query: String,
    ) -> Result<Vec<ContactRecord>, PlexError> {
        let rows = self.db.search_contacts_by_username(&query)?;
        Ok(rows.into_iter().map(to_contact_record).collect())
    }

    /// Публикует мой профиль в локальный DHT-кэш по ключу `acct:<username>`.
    ///
    /// Типичное значение TTL: 86400 сек (24 часа).
    /// Анонс автоматически повторяется при `create_profile`/`update_profile`.
    pub fn profile_announce(&self, ttl_secs: u64) -> Result<(), PlexError> {
        use crate::dht;
        use std::time::{SystemTime, UNIX_EPOCH};

        let my_user_id = self.iroh.node_id().to_string();
        let profile =
            self.db
                .load_public_profile(&my_user_id)?
                .ok_or_else(|| PlexError::NotFound {
                    msg: "Cannot announce: profile not set. Call create_profile first.".into(),
                })?;

        let username_norm = profile.username.trim().to_lowercase();
        if username_norm.is_empty() {
            return Err(PlexError::InvalidInput {
                msg: "Cannot announce: username is empty.".into(),
            });
        }

        let dht_key = format!("acct:{username_norm}");
        dht::validate_key(&dht_key)?;

        let announced_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let my_relay = None::<String>; // relay URL не включаем в DHT анонс (iroh маршрутизирует через DERP автоматически)

        let payload = serde_json::json!({
            "node_id": my_user_id,
            "username": profile.username,
            "display_name": profile.display_name,
            "relay_url": my_relay,
            "announced_at": announced_at,
        });
        let value = serde_json::to_vec(&payload).map_err(|e| PlexError::Internal {
            msg: format!("profile_announce serialize: {e}"),
        })?;
        dht::validate_value(&value)?;
        dht::validate_ttl(ttl_secs)?;

        let now_secs = announced_at;
        self.db
            .publish_dht_record(&dht_key, &value, ttl_secs as i64, now_secs)?;
        tracing::info!(%dht_key, %my_user_id, "[profile] announced to DHT");
        Ok(())
    }

    /// Ищет пира по username через локальный DHT-кэш.
    ///
    /// Возвращает `None` если запись не найдена или её TTL истёк.
    pub fn username_lookup(
        &self,
        username: String,
    ) -> Result<Option<DiscoveredPeerRecord>, PlexError> {
        use crate::dht;
        use std::time::{SystemTime, UNIX_EPOCH};

        let username_norm = username.trim().to_lowercase();
        if username_norm.is_empty() {
            return Err(PlexError::InvalidInput {
                msg: "username must not be empty".into(),
            });
        }

        let dht_key = format!("acct:{username_norm}");
        dht::validate_key(&dht_key)?;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let Some(bytes) = self.db.lookup_dht_record(&dht_key, now_secs)? else {
            return Ok(None);
        };

        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| PlexError::Internal {
                msg: format!("username_lookup decode: {e}"),
            })?;

        let node_id = v["node_id"].as_str().unwrap_or_default().to_string();
        if node_id.is_empty() {
            return Ok(None);
        }

        Ok(Some(DiscoveredPeerRecord {
            node_id,
            username: v["username"].as_str().unwrap_or(&username).to_string(),
            display_name: v["display_name"].as_str().unwrap_or_default().to_string(),
            relay_url: v["relay_url"].as_str().map(|s| s.to_string()),
            announced_at: v["announced_at"].as_i64().unwrap_or(0),
        }))
    }

    /// Регистрирует текущий узел как relay.
    pub fn register_as_relay_node(&self) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        let node_id = self.iroh.node_id().to_string();
        self.db.register_relay_node(&node_id, now)
    }

    /// Возвращает список известных relay-узлов.
    pub fn get_relay_nodes(&self) -> Result<Vec<RelayNodeRecord>, PlexError> {
        let nodes = self.db.list_relay_nodes()?;
        Ok(nodes.into_iter().map(to_relay_record).collect())
    }

    /// Выбирает лучший relay по локальной репутационной policy.
    pub fn select_best_relay(&self) -> Result<Option<String>, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        Ok(self
            .db
            .select_best_relay(now, RELAY_MIN_REPUTATION, RELAY_MAX_STALE_SECS)?
            .map(|relay| relay.node_id))
    }

    /// Обновляет репутацию relay-узла по факту последней операции.
    pub fn update_relay_reputation(&self, node_id: String, success: bool) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        self.db.update_relay_reputation(&node_id, success, now)
    }

    /// Возвращает uptime relay-узла в процентах.
    pub fn get_relay_uptime(&self, node_id: String) -> Result<f64, PlexError> {
        let relay = self
            .db
            .load_relay_node(&node_id)?
            .ok_or_else(|| PlexError::NotFound {
                msg: format!("Relay node not found: {node_id}"),
            })?;
        Ok(relay.uptime_percent)
    }

    /// Обновляет heartbeat relay-узла.
    pub fn heartbeat_relay_node(&self, node_id: String) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        self.db.update_relay_heartbeat(&node_id, now)
    }

    /// Деактивирует relay-узел в локальном реестре.
    pub fn deactivate_relay_node(&self, node_id: String) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        self.db.deactivate_relay_node(&node_id, now)
    }
}

impl PlexNode {
    pub(crate) fn announce_profile_if_present(&self, ttl_secs: u64) -> Result<(), PlexError> {
        let my_user_id = self.iroh.node_id().to_string();
        let Some(profile) = self.db.load_public_profile(&my_user_id)? else {
            return Ok(());
        };

        if profile.username.trim().is_empty() {
            return Ok(());
        }

        self.profile_announce(ttl_secs)
    }
}

// ── Blocklist FFI ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Record)]
pub struct BlockedPeerRecord {
    pub peer_id: String,
    pub blocked_at: i64,
}

#[uniffi::export]
impl PlexNode {
    /// Добавляет пира в blocklist.
    /// После этого его sync-соединения закрываются немедленно,
    /// event log для него недоступен.
    pub fn block_peer(&self, peer_id: String) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        self.db.block_peer(&peer_id, now)
    }

    /// Удаляет пира из blocklist.
    pub fn unblock_peer(&self, peer_id: String) -> Result<(), PlexError> {
        self.db.unblock_peer(&peer_id)
    }

    /// Возвращает `true` если пир заблокирован.
    pub fn is_peer_blocked(&self, peer_id: String) -> Result<bool, PlexError> {
        self.db.is_peer_blocked(&peer_id)
    }

    /// Возвращает список всех заблокированных пиров.
    pub fn list_blocked_peers(&self) -> Result<Vec<BlockedPeerRecord>, PlexError> {
        let rows = self.db.list_blocked_peers()?;
        Ok(rows
            .into_iter()
            .map(|(peer_id, blocked_at)| BlockedPeerRecord {
                peer_id,
                blocked_at,
            })
            .collect())
    }
}

// ── Конвертеры ────────────────────────────────────────────────────────────────

fn to_profile_record(profile: storage::PublicProfile) -> UserProfileRecord {
    UserProfileRecord {
        user_id: profile.user_id,
        username: profile.username,
        display_name: profile.display_name,
        avatar_data: profile.avatar_blob,
        bio: profile.bio,
        public_key: profile.public_key,
        created_at: profile.created_at,
        updated_at: profile.updated_at,
    }
}

fn to_contact_record(contact: storage::Contact) -> ContactRecord {
    ContactRecord {
        user_id: contact.user_id,
        username: contact.username,
        display_name: contact.display_name,
        custom_avatar_data: contact.custom_avatar_blob,
        trust_level: contact.trust_level,
        added_at: contact.added_at,
    }
}

fn to_relay_record(relay: storage::RelayNode) -> RelayNodeRecord {
    RelayNodeRecord {
        node_id: relay.node_id,
        reputation: relay.reputation,
        messages_relayed: relay.messages_relayed.max(0) as u64,
        uptime_percent: relay.uptime_percent,
        last_heartbeat: relay.last_heartbeat,
        is_active: relay.is_active,
    }
}

// ── Connection pool FFI ───────────────────────────────────────────────────────

/// Статус соединения с одним пиром в пуле.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PeerConnectionStatusRecord {
    pub peer_id: String,
    pub is_connected: bool,
    pub consecutive_failures: u32,
    pub backoff_secs: u64,
}

#[uniffi::export]
impl PlexNode {
    /// Возвращает снимок статуса пула постоянных соединений.
    pub fn connection_pool_status(&self) -> Vec<PeerConnectionStatusRecord> {
        self.connection_pool
            .status_snapshot()
            .into_iter()
            .map(|s| PeerConnectionStatusRecord {
                peer_id: s.peer_id,
                is_connected: s.is_connected,
                consecutive_failures: s.consecutive_failures,
                backoff_secs: s.backoff_secs,
            })
            .collect()
    }

    /// Число активных (живых) соединений в пуле.
    pub fn connection_pool_active_count(&self) -> u64 {
        self.connection_pool.active_count() as u64
    }
}
