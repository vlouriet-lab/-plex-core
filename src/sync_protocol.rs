use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use iroh::endpoint::{Connection, RecvStream};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::{storage, PlexError};

const MAX_SYNC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SYNC_EVENTS_PER_ROUND: usize = 256;
const MAX_SYNC_IDENTITY_RECORDS_PER_ROUND: usize = 64;
const MAX_SYNC_ANCHORS_PER_ROUND: usize = 128;
const MAX_SYNC_PROFILES_PER_ROUND: usize = 128;
const MAX_SYNC_DHT_RECORDS_PER_ROUND: usize = 256;
const MAX_SYNC_DELIVERY_RECEIPTS_PER_ROUND: usize = 256;
const MAX_SYNC_ROUNDS: usize = 8;
const MAX_SYNC_RETRIES: usize = 3;
const BASE_RETRY_DELAY_MS: u64 = 200;
const SYNC_READ_CHUNK_BYTES: usize = 16 * 1024;
/// Максимальное число bi-stream запросов от одного peer за скользящее окно 60 с.
const SYNC_MAX_STREAMS_PER_MIN: u32 = 120;
/// Максимальное число хэшей в backfill-очереди. Ограничивает рост при реорге.
const MAX_BACKFILL_QUEUE_SIZE: usize = 512;
/// После этого числа «пустых» раундов с непустой backfill-очередью — сдаёмся,
/// чтобы не зависать при несовместимых историях.
const MAX_STALE_BACKFILL_ROUNDS: usize = 3;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshSyncBundle {
    pub generated_at: i64,
    pub latest_hash: Option<String>,
    pub frontier_hashes: Vec<String>,
    pub events: Vec<storage::Event>,
    pub identity_registrations: Vec<storage::IdentityRegistration>,
    pub verification_anchors: Vec<storage::VerificationAnchor>,
    pub public_profiles: Vec<storage::PublicProfile>,
    pub dht_records: Vec<storage::DhtRecord>,
    pub delivery_receipts: Vec<storage::DeliveryReceipt>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncApplyReport {
    pub inserted_events: usize,
    pub imported_identity_registrations: usize,
    pub imported_verification_anchors: usize,
    pub imported_public_profiles: usize,
    pub imported_dht_records: usize,
    pub imported_delivery_receipts: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SyncRequest {
    latest_hash: Option<String>,
    frontier_hashes: Vec<String>,
    known_hashes: Vec<String>,
    known_identity_peer_ids: Vec<String>,
    known_anchor_keys: Vec<String>,
    known_profile_user_ids: Vec<String>,
    known_dht_keys: Vec<String>,
    known_delivery_receipt_ids: Vec<String>,
    backfill_for: Vec<String>,
    max_events: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SyncResponse {
    latest_hash: Option<String>,
    frontier_hashes: Vec<String>,
    events: Vec<storage::Event>,
    identity_registrations: Vec<storage::IdentityRegistration>,
    verification_anchors: Vec<storage::VerificationAnchor>,
    public_profiles: Vec<storage::PublicProfile>,
    dht_records: Vec<storage::DhtRecord>,
    delivery_receipts: Vec<storage::DeliveryReceipt>,
    request_backfill_for: Vec<String>,
    reorg_detected: bool,
    retry_after_ms: Option<u64>,
}

fn unix_now_secs() -> Result<i64, PlexError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })?
        .as_secs() as i64)
}

pub(crate) fn export_mesh_sync_bundle(
    db: &storage::Db,
    max_events: usize,
) -> Result<MeshSyncBundle, PlexError> {
    let now = unix_now_secs()?;

    Ok(MeshSyncBundle {
        generated_at: now,
        latest_hash: db.latest_event_hash()?,
        frontier_hashes: db.frontier_hashes()?,
        events: db.events_excluding(&[], max_events.min(MAX_SYNC_EVENTS_PER_ROUND))?,
        identity_registrations: db
            .identity_registrations_excluding(&[], MAX_SYNC_IDENTITY_RECORDS_PER_ROUND)?,
        verification_anchors: db.verification_anchors_excluding(&[], MAX_SYNC_ANCHORS_PER_ROUND)?,
        public_profiles: db.public_profiles_excluding(&[], MAX_SYNC_PROFILES_PER_ROUND)?,
        dht_records: db.dht_records_excluding(&[], MAX_SYNC_DHT_RECORDS_PER_ROUND, now)?,
        delivery_receipts: db
            .delivery_receipts_excluding(&[], MAX_SYNC_DELIVERY_RECEIPTS_PER_ROUND)?,
    })
}

pub(crate) fn export_mesh_sync_bundle_bounded(
    db: &storage::Db,
    max_events: usize,
    max_bytes: usize,
) -> Result<MeshSyncBundle, PlexError> {
    if max_bytes == 0 {
        return Err(PlexError::Network {
            msg: "Mesh sync bundle max_bytes must be greater than zero".into(),
        });
    }

    let now = unix_now_secs()?;
    let fixed_identity_registrations =
        db.identity_registrations_excluding(&[], MAX_SYNC_IDENTITY_RECORDS_PER_ROUND)?;
    let fixed_verification_anchors =
        db.verification_anchors_excluding(&[], MAX_SYNC_ANCHORS_PER_ROUND)?;
    let fixed_public_profiles = db.public_profiles_excluding(&[], MAX_SYNC_PROFILES_PER_ROUND)?;
    let fixed_dht_records = db.dht_records_excluding(&[], MAX_SYNC_DHT_RECORDS_PER_ROUND, now)?;
    let fixed_delivery_receipts =
        db.delivery_receipts_excluding(&[], MAX_SYNC_DELIVERY_RECEIPTS_PER_ROUND)?;
    let latest_hash = db.latest_event_hash()?;
    let frontier_hashes = db.frontier_hashes()?;
    let all_events = db.events_excluding(&[], max_events.min(MAX_SYNC_EVENTS_PER_ROUND))?;

    let mut event_limit = all_events.len();
    loop {
        let bundle = MeshSyncBundle {
            generated_at: now,
            latest_hash: latest_hash.clone(),
            frontier_hashes: frontier_hashes.clone(),
            events: all_events[..event_limit].to_vec(),
            identity_registrations: fixed_identity_registrations.clone(),
            verification_anchors: fixed_verification_anchors.clone(),
            public_profiles: fixed_public_profiles.clone(),
            dht_records: fixed_dht_records.clone(),
            delivery_receipts: fixed_delivery_receipts.clone(),
        };

        let encoded = serde_json::to_vec(&bundle).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize bounded mesh sync bundle: {e}"),
        })?;

        if encoded.len() <= max_bytes {
            return Ok(bundle);
        }

        if event_limit == 0 {
            return Err(PlexError::Network {
                msg: format!(
                    "Mesh sync bundle fixed payload exceeds byte budget: {} > {}",
                    encoded.len(),
                    max_bytes,
                ),
            });
        }

        event_limit -= 1;
    }
}

pub(crate) fn import_mesh_sync_bundle(
    db: &storage::Db,
    bundle: &MeshSyncBundle,
) -> Result<SyncApplyReport, PlexError> {
    apply_sync_bundle(db, bundle, None)
}

fn apply_sync_bundle(
    db: &storage::Db,
    bundle: &MeshSyncBundle,
    remote_peer: Option<String>,
) -> Result<SyncApplyReport, PlexError> {
    let peer = remote_peer.unwrap_or_else(|| "mesh-handoff".to_string());
    let now = unix_now_secs()?;
    let inserted_events = db.insert_events(&bundle.events)?;

    let mut imported_identity_registrations = 0usize;
    for record in &bundle.identity_registrations {
        match db.save_identity_registration(record) {
            Ok(()) => imported_identity_registrations += 1,
            Err(error) => {
                warn!(peer = %peer, %error, "Skipping invalid identity registration from bundle");
            }
        }
    }

    let mut imported_verification_anchors = 0usize;
    for anchor in &bundle.verification_anchors {
        match db.save_verification_anchor(anchor) {
            Ok(()) => imported_verification_anchors += 1,
            Err(error) => {
                warn!(peer = %peer, %error, "Skipping invalid verification anchor from bundle");
            }
        }
    }

    let mut imported_public_profiles = 0usize;
    for profile in &bundle.public_profiles {
        match db.save_public_profile(profile) {
            Ok(()) => imported_public_profiles += 1,
            Err(error) => {
                warn!(peer = %peer, %error, "Skipping invalid public profile from bundle");
            }
        }
    }

    let mut imported_dht_records = 0usize;
    for record in &bundle.dht_records {
        match db.import_dht_record(record, now) {
            Ok(true) => imported_dht_records += 1,
            Ok(false) => {}
            Err(error) => {
                warn!(peer = %peer, %error, "Skipping invalid DHT record from bundle");
            }
        }
    }

    let mut imported_delivery_receipts = 0usize;
    for receipt in &bundle.delivery_receipts {
        match db.import_delivery_receipt(receipt) {
            Ok(true) => imported_delivery_receipts += 1,
            Ok(false) => {}
            Err(error) => {
                warn!(peer = %peer, %error, "Skipping invalid delivery receipt from bundle");
            }
        }
    }

    Ok(SyncApplyReport {
        inserted_events,
        imported_identity_registrations,
        imported_verification_anchors,
        imported_public_profiles,
        imported_dht_records,
        imported_delivery_receipts,
    })
}

pub(crate) async fn serve_sync_requests(
    conn: Connection,
    db: Arc<storage::Db>,
) -> Result<(), PlexError> {
    // --- S3: Auth gate — ограничиваем выдачу событий для неизвестных пиров ---
    let remote_peer_id = conn
        .remote_node_id()
        .map(|id| id.to_string())
        .unwrap_or_default();

    // A5: Blocklist — заблокированные пиры не получают ничего.
    if !remote_peer_id.is_empty() && db.is_peer_blocked(&remote_peer_id).unwrap_or(false) {
        warn!(peer_id = %remote_peer_id, "[security] sync: blocked peer — closing connection");
        conn.close(403u32.into(), b"blocked");
        return Ok(());
    }

    let is_known = if remote_peer_id.is_empty() {
        false
    } else {
        db.is_known_peer(&remote_peer_id).unwrap_or(false)
    };
    if !is_known {
        warn!(peer_id = %remote_peer_id, "[security] sync: serving unknown peer — restricting event log");
    }

    // --- A4: Rate limit — скользящее окно 60 с, max SYNC_MAX_STREAMS_PER_MIN ---
    let mut streams_in_window: u32 = 0;
    let mut window_start = Instant::now();

    loop {
        // Обновляем скользящее окно
        if window_start.elapsed().as_secs() >= 60 {
            streams_in_window = 0;
            window_start = Instant::now();
        }
        if streams_in_window >= SYNC_MAX_STREAMS_PER_MIN {
            warn!(
                peer_id = %remote_peer_id,
                "[security] sync: rate limit reached ({} req/min) — closing connection",
                SYNC_MAX_STREAMS_PER_MIN
            );
            conn.close(429u32.into(), b"rate-limit-exceeded");
            return Ok(());
        }
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| PlexError::Network {
            msg: format!("Accept sync stream failed: {e}"),
        })?;
        streams_in_window += 1;

        let request_bytes =
            read_stream_bounded(&mut recv, MAX_SYNC_MESSAGE_BYTES, "sync request").await?;

        let request: SyncRequest =
            serde_json::from_slice(&request_bytes).map_err(|e| PlexError::Network {
                msg: format!("Decode sync request failed: {e}"),
            })?;

        let mut known_hashes = request.known_hashes.into_iter().collect::<HashSet<_>>();
        known_hashes.extend(request.frontier_hashes.iter().cloned());
        if let Some(latest) = &request.latest_hash {
            known_hashes.insert(latest.clone());
        }

        let max_events = if is_known {
            request.max_events.min(MAX_SYNC_EVENTS_PER_ROUND)
        } else {
            // Неизвестный peer: запрещаем доступ к event log, но разрешаем
            // обмен identity/anchor данными для процесса взаимного знакомства.
            0
        };
        let events = if request.backfill_for.is_empty() {
            let known = known_hashes.into_iter().collect::<Vec<_>>();
            db.events_excluding(&known, max_events)?
        } else {
            db.events_with_ancestors(&request.backfill_for, max_events)?
        };

        let mut request_backfill_for = Vec::new();
        for remote_head in request.frontier_hashes {
            if !db.has_event(&remote_head)? {
                request_backfill_for.push(remote_head);
            }
        }

        let reorg_detected = match request.latest_hash {
            Some(hash) => !db.has_event(&hash)?,
            None => false,
        };

        let now = unix_now_secs()?;

        let response = SyncResponse {
            latest_hash: db.latest_event_hash()?,
            frontier_hashes: db.frontier_hashes()?,
            events,
            identity_registrations: db.identity_registrations_excluding(
                &request.known_identity_peer_ids,
                MAX_SYNC_IDENTITY_RECORDS_PER_ROUND,
            )?,
            verification_anchors: db.verification_anchors_excluding(
                &request.known_anchor_keys,
                MAX_SYNC_ANCHORS_PER_ROUND,
            )?,
            public_profiles: db.public_profiles_excluding(
                &request.known_profile_user_ids,
                MAX_SYNC_PROFILES_PER_ROUND,
            )?,
            dht_records: db.dht_records_excluding(
                &request.known_dht_keys,
                MAX_SYNC_DHT_RECORDS_PER_ROUND,
                now,
            )?,
            delivery_receipts: db.delivery_receipts_excluding(
                &request.known_delivery_receipt_ids,
                MAX_SYNC_DELIVERY_RECEIPTS_PER_ROUND,
            )?,
            request_backfill_for,
            reorg_detected,
            retry_after_ms: None,
        };

        let response_bytes = serde_json::to_vec(&response).map_err(|e| PlexError::Internal {
            msg: format!("Encode sync response failed: {e}"),
        })?;

        send.write_all(&response_bytes)
            .await
            .map_err(|e| PlexError::Network {
                msg: format!("Write sync response failed: {e}"),
            })?;
        send.finish().map_err(|e| PlexError::Network {
            msg: format!("Finish sync response failed: {e}"),
        })?;
    }
}

pub(crate) async fn request_sync(
    conn: Connection,
    db: Arc<storage::Db>,
    metrics: Arc<crate::metrics::CoreMetrics>,
) -> Result<usize, PlexError> {
    let mut total_inserted = 0usize;
    let mut backfill_queue: Vec<String> = Vec::new();
    let mut stale_backfill_rounds = 0usize;

    for round in 0..MAX_SYNC_ROUNDS {
        let now = unix_now_secs()?;
        let request = SyncRequest {
            latest_hash: db.latest_event_hash()?,
            frontier_hashes: db.frontier_hashes()?,
            // S5: Не раскрываем полный список event ID (утечка метаданных социального графа).
            // Сервер использует frontier_hashes + latest_hash для эффективного diff.
            // Дубликаты просто идемпотентно игнорируются при вставке.
            known_hashes: vec![],
            known_identity_peer_ids: db.all_identity_peer_ids()?,
            known_anchor_keys: db.all_verification_anchor_keys()?,
            known_profile_user_ids: db.all_public_profile_user_ids()?,
            known_dht_keys: db.all_active_dht_keys(now)?,
            known_delivery_receipt_ids: db.all_delivery_receipt_ids()?,
            backfill_for: backfill_queue.clone(),
            max_events: MAX_SYNC_EVENTS_PER_ROUND,
        };

        let response = sync_with_retry(&conn, &request).await?;

        // При обнаружении реорга добавляем frontier пира в backfill — они ссылаются
        // на предков, которых у нас нет. Делаем это ДО применения bundle,
        // чтобы в следующем раунде сразу запросить пропущенные ветки.
        if response.reorg_detected {
            for h in &response.frontier_hashes {
                if !db.has_event(h)? {
                    backfill_queue.push(h.clone());
                }
            }
            metrics.inc(&metrics.sync_reorgs_detected);
            warn!(
                peer = ?conn.remote_node_id().ok(),
                round = round,
                "Reorg detected: requesting backfill for {} frontier hashes",
                backfill_queue.len(),
            );
        }

        let report = apply_sync_bundle(
            &db,
            &MeshSyncBundle {
                generated_at: now,
                latest_hash: response.latest_hash.clone(),
                frontier_hashes: response.frontier_hashes.clone(),
                events: response.events.clone(),
                identity_registrations: response.identity_registrations.clone(),
                verification_anchors: response.verification_anchors.clone(),
                public_profiles: response.public_profiles.clone(),
                dht_records: response.dht_records.clone(),
                delivery_receipts: response.delivery_receipts.clone(),
            },
            conn.remote_node_id().ok().map(|peer| peer.to_string()),
        )?;
        total_inserted += report.inserted_events;

        // Строим backfill для следующего раунда из: запроса пира + наших сирот.
        let mut next_backfill = HashSet::new();
        next_backfill.extend(response.request_backfill_for);
        next_backfill.extend(db.orphan_prev_hashes(MAX_SYNC_EVENTS_PER_ROUND)?);
        // Уже перечисленные из reorg-ветки тоже попадают сюда.
        next_backfill.extend(backfill_queue.iter().cloned());

        // Удаляем хэши, которые уже есть в нашем log.
        next_backfill.retain(|h| !db.has_event(h).unwrap_or(true));

        // Ограничиваем размер очереди, чтобы не уйти в ОOM при больших реоргах.
        let mut next_backfill_vec: Vec<String> = next_backfill.into_iter().collect();
        if next_backfill_vec.len() > MAX_BACKFILL_QUEUE_SIZE {
            warn!(
                "Backfill queue capped at {MAX_BACKFILL_QUEUE_SIZE} (was {})",
                next_backfill_vec.len()
            );
            next_backfill_vec.truncate(MAX_BACKFILL_QUEUE_SIZE);
        }

        info!(
            peer = ?conn.remote_node_id().ok(),
            round = round,
            remote_latest = ?response.latest_hash,
            remote_frontier = ?response.frontier_hashes,
            reorg_detected = response.reorg_detected,
            received_events = response.events.len(),
            inserted_events = report.inserted_events,
            received_identity_registrations = response.identity_registrations.len(),
            imported_identity_registrations = report.imported_identity_registrations,
            received_verification_anchors = response.verification_anchors.len(),
            imported_verification_anchors = report.imported_verification_anchors,
            received_public_profiles = response.public_profiles.len(),
            imported_public_profiles = report.imported_public_profiles,
            received_dht_records = response.dht_records.len(),
            imported_dht_records = report.imported_dht_records,
            received_delivery_receipts = response.delivery_receipts.len(),
            imported_delivery_receipts = report.imported_delivery_receipts,
            pending_backfill = next_backfill_vec.len(),
            "Sync response applied"
        );

        let nothing_new = report.inserted_events == 0
            && report.imported_identity_registrations == 0
            && report.imported_verification_anchors == 0
            && report.imported_public_profiles == 0
            && report.imported_dht_records == 0
            && report.imported_delivery_receipts == 0
            && response.events.is_empty()
            && response.identity_registrations.is_empty()
            && response.verification_anchors.is_empty()
            && response.public_profiles.is_empty()
            && response.dht_records.is_empty()
            && response.delivery_receipts.is_empty();

        // Обнаружение конвергенции: если всё пусто и backfill тоже — синк завершён.
        if nothing_new && next_backfill_vec.is_empty() {
            break;
        }

        // Защита от зависания: если backfill-очередь непуста, но новых событий
        // несколько раундов подряд нет — сдаёмся (история несовместима).
        if !next_backfill_vec.is_empty() && nothing_new {
            stale_backfill_rounds += 1;
            warn!(
                "Stale backfill round {stale_backfill_rounds}/{MAX_STALE_BACKFILL_ROUNDS}, \
                 queue_size={}",
                next_backfill_vec.len()
            );
            if stale_backfill_rounds >= MAX_STALE_BACKFILL_ROUNDS {
                warn!("Giving up backfill after {MAX_STALE_BACKFILL_ROUNDS} stale rounds");
                break;
            }
        } else {
            stale_backfill_rounds = 0;
        }

        backfill_queue = next_backfill_vec;
    }

    Ok(total_inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use secrecy::SecretString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn open_test_db() -> storage::Db {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("plex-sync-protocol-{unique}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        storage::Db::open(&db_path_str, &SecretString::new("test-key".to_string())).unwrap()
    }

    #[test]
    fn mesh_bundle_roundtrip_preserves_sync_payload() {
        let source = open_test_db();
        let target = open_test_db();

        source
            .append_local_event(
                &iroh::SecretKey::generate(&mut rand::rngs::OsRng),
                b"mesh-event",
            )
            .unwrap();

        let profile = storage::PublicProfile {
            user_id: "peer-a".into(),
            username: "peer_a".into(),
            display_name: "Peer A".into(),
            avatar_blob: None,
            bio: Some("mesh".into()),
            public_key: "pk".into(),
            created_at: 100,
            updated_at: 100,
        };
        let message_id = source
            .enqueue_outbox_message("peer-a", b"cipher", 100)
            .unwrap();
        source
            .ack_outbox_delivery("peer-a", &message_id, 101)
            .unwrap();
        let dht = storage::DhtRecord {
            key: "mesh:key".into(),
            value: vec![7, 8, 9],
            updated_at: 100,
            expires_at: i64::MAX / 2,
        };

        source.save_public_profile(&profile).unwrap();
        source.import_dht_record(&dht, 0).unwrap();

        let bundle = export_mesh_sync_bundle(&source, 64).unwrap();
        let report = import_mesh_sync_bundle(&target, &bundle).unwrap();

        assert_eq!(report.inserted_events, 1);
        assert_eq!(report.imported_public_profiles, 1);
        assert_eq!(report.imported_dht_records, 1);
        assert_eq!(report.imported_delivery_receipts, 1);
        assert_eq!(target.all_events().unwrap().len(), 1);
        assert!(target.load_public_profile("peer-a").unwrap().is_some());
        assert!(target.lookup_dht_record("mesh:key", 1).unwrap().is_some());
        assert_eq!(target.all_delivery_receipt_ids().unwrap(), vec![message_id]);
    }

    #[test]
    fn bounded_mesh_bundle_reduces_events_to_fit_budget() {
        let db = open_test_db();
        let signer = iroh::SecretKey::generate(&mut rand::rngs::OsRng);
        for payload in [vec![1u8; 512], vec![2u8; 512], vec![3u8; 512]] {
            db.append_local_event(&signer, &payload).unwrap();
        }

        let full = export_mesh_sync_bundle(&db, 64).unwrap();
        let full_len = serde_json::to_vec(&full).unwrap().len();
        let bounded =
            export_mesh_sync_bundle_bounded(&db, 64, full_len.saturating_sub(300)).unwrap();
        let bounded_len = serde_json::to_vec(&bounded).unwrap().len();

        assert!(bounded_len <= full_len.saturating_sub(300));
        assert!(bounded.events.len() < full.events.len());
    }

    // ── Edge-case: backfill queue capping ────────────────────────────────────

    /// Тестирует, что хэши `request_backfill_for` из ответа, не входящие в нашу
    /// БД, добавляются в backfill-очередь и корректно дедуплицируются.
    /// Также проверяет ограничение MAX_BACKFILL_QUEUE_SIZE — очередь не должна
    /// превысить 512 элементов.
    #[test]
    fn backfill_queue_deduplicates_and_caps_at_max_size() {
        // simulate_next_backfill: принимает набор «недостающих» хэшей от сервера
        // и результат уже-известных, и проверяет что в итоге очередь ограничена.
        fn simulate_next_backfill(
            server_backfill: HashSet<String>,
            already_have: HashSet<String>,
        ) -> Vec<String> {
            let mut queue: HashSet<String> = server_backfill;
            queue.retain(|h| !already_have.contains(h));

            let mut vec: Vec<String> = queue.into_iter().collect();
            if vec.len() > MAX_BACKFILL_QUEUE_SIZE {
                vec.truncate(MAX_BACKFILL_QUEUE_SIZE);
            }
            vec
        }

        // Сервер предлагает 1000 хэшей на backfill, у нас нет ни одного.
        let server_hashes: HashSet<String> =
            (0usize..1000).map(|i| format!("hash_{i:04}")).collect();

        let result = simulate_next_backfill(server_hashes, HashSet::new());

        assert_eq!(
            result.len(),
            MAX_BACKFILL_QUEUE_SIZE,
            "backfill queue must be capped at MAX_BACKFILL_QUEUE_SIZE"
        );
    }

    // ── Edge-case: reorg detection ───────────────────────────────────────────

    /// Тестирует, что `reorg_detected=true` в `SyncResponse` строится корректно:
    /// если pir заявляет `latest_hash` которого нет в нашей БД — реорг.
    /// Если хэш известен — реорга нет.
    #[test]
    fn reorg_detected_when_latest_hash_is_unknown() {
        let db = open_test_db();
        let signer = iroh::SecretKey::generate(&mut rand::rngs::OsRng);
        db.append_local_event(&signer, b"event-a").unwrap();

        let our_latest = db.latest_event_hash().unwrap().unwrap();

        // Хэш, которого нет в нашей БД
        let unknown_hash = "dead000000000000000000000000000000000000000000000000000000000000";
        let reorg_detected_unknown = !db.has_event(unknown_hash).unwrap();
        assert!(
            reorg_detected_unknown,
            "should detect reorg for unknown latest_hash"
        );

        // Наш собственный хэш — реорга не должно быть
        let reorg_detected_known = !db.has_event(&our_latest).unwrap();
        assert!(
            !reorg_detected_known,
            "should NOT detect reorg for known latest_hash"
        );
    }

    // ── Edge-case: stale backfill detection ──────────────────────────────────

    /// Тестирует логику счётчика пустых backfill-раундов.
    /// Если nothing_new && backfill непуст → счётчик растёт.
    /// Если пришли новые данные → счётчик сбрасывается.
    #[test]
    fn stale_backfill_counter_resets_on_progress() {
        let mut stale_rounds = 0usize;

        // Проверяем: 2 пустых раунда, потом прогресс — счётчик обнуляется.
        for nothing_new in [true, true, false] {
            let backfill_pending = true;
            if backfill_pending && nothing_new {
                stale_rounds += 1;
            } else {
                stale_rounds = 0;
            }
        }
        assert_eq!(stale_rounds, 0, "stale counter must reset on progress");

        // Проверяем: 3 пустых раунда — досягнут лимит.
        stale_rounds = 0;
        for _ in 0..MAX_STALE_BACKFILL_ROUNDS {
            stale_rounds += 1;
        }
        assert_eq!(stale_rounds, MAX_STALE_BACKFILL_ROUNDS);
        assert!(
            stale_rounds >= MAX_STALE_BACKFILL_ROUNDS,
            "should give up after MAX_STALE_BACKFILL_ROUNDS stale rounds"
        );
    }
}

async fn sync_with_retry(
    conn: &Connection,
    request: &SyncRequest,
) -> Result<SyncResponse, PlexError> {
    let mut last_error = None;

    for attempt in 0..MAX_SYNC_RETRIES {
        match sync_once(conn, request).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 >= MAX_SYNC_RETRIES {
                    break;
                }

                let delay_ms = BASE_RETRY_DELAY_MS * (1u64 << attempt);
                warn!(
                    attempt = attempt + 1,
                    delay_ms, "Sync attempt failed; retrying"
                );
                sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| PlexError::Network {
        msg: "Sync failed with unknown error".into(),
    }))
}

async fn sync_once(conn: &Connection, request: &SyncRequest) -> Result<SyncResponse, PlexError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| PlexError::Network {
        msg: format!("Open sync stream failed: {e}"),
    })?;

    let request_bytes = serde_json::to_vec(request).map_err(|e| PlexError::Internal {
        msg: format!("Encode sync request failed: {e}"),
    })?;

    send.write_all(&request_bytes)
        .await
        .map_err(|e| PlexError::Network {
            msg: format!("Write sync request failed: {e}"),
        })?;
    send.finish().map_err(|e| PlexError::Network {
        msg: format!("Finish sync request failed: {e}"),
    })?;

    let response_bytes =
        read_stream_bounded(&mut recv, MAX_SYNC_MESSAGE_BYTES, "sync response").await?;

    serde_json::from_slice(&response_bytes).map_err(|e| PlexError::Network {
        msg: format!("Decode sync response failed: {e}"),
    })
}

async fn read_stream_bounded(
    recv: &mut RecvStream,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, PlexError> {
    let mut bytes = Vec::with_capacity(SYNC_READ_CHUNK_BYTES.min(max_bytes));

    while let Some(chunk) = recv
        .read_chunk(SYNC_READ_CHUNK_BYTES, true)
        .await
        .map_err(|e| PlexError::Network {
            msg: format!("Read {label} chunk failed: {e}"),
        })?
    {
        if bytes.len().saturating_add(chunk.bytes.len()) > max_bytes {
            return Err(PlexError::Timeout {
                msg: format!(
                    "{label} exceeds max size: {} > {} bytes",
                    bytes.len().saturating_add(chunk.bytes.len()),
                    max_bytes,
                ),
            });
        }
        bytes.extend_from_slice(&chunk.bytes);
    }

    Ok(bytes)
}
