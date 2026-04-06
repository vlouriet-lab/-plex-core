//! `ffi_dht.rs` — FFI-модуль локального DHT-кэша.
//!
//! Содержит:
//! * Типы: [`DhtMaintenanceReport`], [`DhtCacheStatsRecord`], [`DhtEvictionCandidateRecord`].
//! * Методы PlexNode для publish/lookup/maintenance/eviction локального DHT-слоя.
//!
//! ## Жизненный цикл интеллектуальной очистки кэша
//!
//! 1. Мобильный слой вызывает `dht_set_cache_max_bytes(limit)` при старте (0 = без ограничения).
//! 2. Периодически вызывается `dht_maintenance_tick()`.
//!    Если `cache_bytes_used > max_cache_bytes`, в отчёте появляется
//!    `pending_eviction_candidates` — предложение удалить самые старые записи.
//! 3. Мобильный слой показывает UI-диалог подтверждения со списком ключей.
//! 4. Пользователь подтверждает → вызывается `dht_confirm_eviction(keys)`.
//!    Вытеснение постепенное: одна порция за цикл (`dht_eviction_batch_size`).

use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::info;

use crate::{dht, PlexError, PlexNode};

// ── Константы ─────────────────────────────────────────────────────────────────

const DHT_DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
const DHT_REPUBLISH_THRESHOLD_SECS: u64 = 15 * 60;
const DHT_MAINTENANCE_BATCH_LIMIT: u64 = 128;
/// Размер порции вытеснения по умолчанию (записей за один maintenance tick).
pub(crate) const DHT_DEFAULT_EVICTION_BATCH: u32 = 8;
/// Лимит DHT-кэша по умолчанию: 500 МБ.
/// Достаточно для современных смартфонов (128 ГБ+), при этом не занимает
/// значительную долю внутренней памяти при обычном использовании.
pub(crate) const DHT_DEFAULT_CACHE_MAX_BYTES: u64 = 500 * 1024 * 1024;

// ── Типы ──────────────────────────────────────────────────────────────────────

/// Статистика использования DHT-кэша.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DhtCacheStatsRecord {
    /// Количество активных (не истекших) записей в кэше.
    pub total_records: u64,
    /// Суммарный объём `value_blob` всех активных записей в байтах.
    pub total_bytes: u64,
    /// Настроенный лимит в байтах. 0 = без ограничения.
    pub max_cache_bytes: u64,
    /// Превышение в байтах. 0 если укладываемся в лимит.
    pub bytes_over_limit: u64,
    /// Текущий размер порции вытеснения (записей за цикл).
    pub eviction_batch_size: u32,
}

/// Одна запись из списка кандидатов на вытеснение.
///
/// Мобильный слой использует эти данные для отображения
/// списка записей в диалоге подтверждения очистки.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DhtEvictionCandidateRecord {
    /// DHT-ключ (идентификатор записи).
    pub key: String,
    /// Размер значения в байтах.
    pub size_bytes: u64,
    /// Unix-timestamp последнего обновления.
    pub updated_at: i64,
    /// Unix-timestamp истечения TTL записи.
    pub expires_at: i64,
}

/// Отчёт о выполнении maintenance-цикла DHT-кэша.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DhtMaintenanceReport {
    /// Число удалённых просроченных записей.
    pub pruned_records: u64,
    /// Число обновлённых (продлённых) TTL записей.
    pub refreshed_records: u64,
    /// Текущий объём кэша в байтах.
    pub cache_bytes_used: u64,
    /// Настроенный лимит кэша. 0 = без ограничения.
    pub cache_bytes_limit: u64,
    /// Кандидаты на постепенное вытеснение (предложены пользователю для подтверждения).
    ///
    /// Пусто, если лимит не установлен или кэш в пределах нормы.
    /// Мобильный слой должен показать UI-диалог и при подтверждении
    /// вызвать `dht_confirm_eviction(keys)`.
    pub pending_eviction_candidates: Vec<DhtEvictionCandidateRecord>,
}

// ── FFI-методы PlexNode ───────────────────────────────────────────────────────

#[uniffi::export]
impl PlexNode {
    /// Публикует запись в DHT-слой с TTL (локальный кэш-паблиш).
    pub fn publish_to_dht(&self, key: String, value: Vec<u8>) -> Result<(), PlexError> {
        self.publish_to_dht_with_ttl(key, value, DHT_DEFAULT_TTL_SECS)
    }

    /// Публикует запись в DHT-слой с явно заданным TTL.
    pub fn publish_to_dht_with_ttl(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<(), PlexError> {
        dht::validate_key(&key)?;
        dht::validate_value(&value)?;
        dht::validate_ttl(ttl_secs)?;

        let now = unix_now()?;
        self.db
            .publish_dht_record(&key, &value, ttl_secs as i64, now)
    }

    /// Ищет запись в DHT-слое по ключу.
    pub fn lookup_dht(&self, key: String) -> Result<Option<Vec<u8>>, PlexError> {
        dht::validate_key(&key)?;
        let now = unix_now()?;
        self.db.lookup_dht_record(&key, now)
    }

    /// Возвращает текущую статистику DHT-кэша.
    pub fn dht_cache_stats(&self) -> Result<DhtCacheStatsRecord, PlexError> {
        let now = unix_now()?;
        let (total_records, total_bytes) = self.db.dht_cache_usage(now)?;
        let max_cache_bytes = self.dht_cache_max_bytes.load(Ordering::Relaxed);
        let bytes_over_limit = if max_cache_bytes > 0 && total_bytes > max_cache_bytes {
            total_bytes - max_cache_bytes
        } else {
            0
        };
        Ok(DhtCacheStatsRecord {
            total_records,
            total_bytes,
            max_cache_bytes,
            bytes_over_limit,
            eviction_batch_size: self.dht_eviction_batch_size.load(Ordering::Relaxed),
        })
    }

    /// Устанавливает максимально допустимый размер DHT-кэша в байтах.
    ///
    /// При `max_bytes = 0` ограничение снимается.
    /// Новое значение начинает применяться на следующем вызове `dht_maintenance_tick()`.
    pub fn dht_set_cache_max_bytes(&self, max_bytes: u64) {
        self.dht_cache_max_bytes.store(max_bytes, Ordering::Relaxed);
        info!(max_bytes, "[dht] cache size limit updated");
    }

    /// Устанавливает размер порции постепенного вытеснения.
    ///
    /// Определяет, сколько записей будет предложено к удалению за один `dht_maintenance_tick`.
    /// Значение 0 заменяется дефолтным ({}).
    pub fn dht_set_eviction_batch_size(&self, batch_size: u32) {
        let effective = if batch_size == 0 {
            DHT_DEFAULT_EVICTION_BATCH
        } else {
            batch_size
        };
        self.dht_eviction_batch_size
            .store(effective, Ordering::Relaxed);
        info!(effective, "[dht] eviction batch size updated");
    }

    /// Подтверждает и выполняет удаление записей DHT-кэша, выбранных пользователем.
    ///
    /// Вызывается мобильным слоем после того, как пользователь подтвердил список
    /// `pending_eviction_candidates`, полученный из `dht_maintenance_tick()`.
    ///
    /// Ключи, которые уже не существуют, игнорируются.
    /// Возвращает количество фактически удалённых записей.
    pub fn dht_confirm_eviction(&self, keys: Vec<String>) -> Result<u64, PlexError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let deleted = self.db.dht_delete_by_keys(&keys)?;
        info!(
            deleted,
            candidates = keys.len(),
            "[dht] user confirmed eviction of DHT cache records"
        );
        Ok(deleted)
    }

    /// Выполняет maintenance DHT-кэша: удаляет просроченные, продлевает скоро истекающие,
    /// проверяет размер кэша и при превышении лимита предлагает кандидатов для вытеснения.
    ///
    /// ## Логика интеллектуальной очистки
    ///
    /// 1. Удаляются записи с истёкшим TTL (автоматически, без подтверждения).
    /// 2. Продлевается TTL записей, которые скоро истекут.
    /// 3. Если `dht_cache_max_bytes > 0` и текущий размер превышает лимит,
    ///    в отчёте возвращается `pending_eviction_candidates` — порция старейших
    ///    активных записей (размером `dht_eviction_batch_size`).
    /// 4. Мобильный слой показывает диалог. Пользователь даёт согласие →
    ///    вызывается `dht_confirm_eviction(keys)`.
    pub fn dht_maintenance_tick(&self) -> Result<DhtMaintenanceReport, PlexError> {
        let now = unix_now()?;

        // 1. Удалить просроченные записи (без подтверждения — TTL истёк)
        let pruned = self.db.prune_expired_dht_records(now)?;

        // 2. Продлить TTL скоро истекающих записей
        let deadline = now.saturating_add(DHT_REPUBLISH_THRESHOLD_SECS as i64);
        let keys_to_refresh = self
            .db
            .dht_keys_expiring_before(deadline, DHT_MAINTENANCE_BATCH_LIMIT as usize)?;

        let mut refreshed = 0u64;
        for key in keys_to_refresh {
            if self
                .db
                .refresh_dht_record_ttl(&key, DHT_DEFAULT_TTL_SECS as i64, now)?
            {
                refreshed += 1;
            }
        }

        // 3. Проверить лимит кэша и сформировать список кандидатов на вытеснение
        let (_, cache_bytes_used) = self.db.dht_cache_usage(now)?;
        let cache_bytes_limit = self.dht_cache_max_bytes.load(Ordering::Relaxed);
        let batch_size = self.dht_eviction_batch_size.load(Ordering::Relaxed);

        let pending_eviction_candidates =
            if cache_bytes_limit > 0 && cache_bytes_used > cache_bytes_limit {
                let over_by = cache_bytes_used - cache_bytes_limit;
                info!(
                    cache_bytes_used,
                    cache_bytes_limit,
                    over_by,
                    batch_size,
                    "[dht] cache over limit — proposing eviction candidates to user"
                );
                self.db
                    .dht_eviction_candidates(now, batch_size as usize)?
                    .into_iter()
                    .map(|c| DhtEvictionCandidateRecord {
                        key: c.key,
                        size_bytes: c.size_bytes,
                        updated_at: c.updated_at,
                        expires_at: c.expires_at,
                    })
                    .collect()
            } else {
                vec![]
            };

        Ok(DhtMaintenanceReport {
            pruned_records: pruned,
            refreshed_records: refreshed,
            cache_bytes_used,
            cache_bytes_limit,
            pending_eviction_candidates,
        })
    }
}

fn unix_now() -> Result<i64, PlexError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })
}
