use crate::{mesh_handoff, network, sync_protocol, PlexError, PlexNode};

/// Максимальное число одновременных входящих mesh handoff сессий (DoS-граница).
const MAX_MESH_HANDOFF_SESSIONS: usize = 64;

#[derive(Debug, Clone, uniffi::Record)]
pub struct LocalMeshPeerRecord {
    pub peer_id: String,
    pub medium: String,
    pub endpoint_hint: String,
    pub signal_strength: Option<i32>,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshSyncImportReport {
    pub inserted_events: u64,
    pub imported_identity_registrations: u64,
    pub imported_verification_anchors: u64,
    pub imported_public_profiles: u64,
    pub imported_dht_records: u64,
    pub imported_delivery_receipts: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshHandoffOfferRecord {
    pub session_id: String,
    pub generated_at: i64,
    pub total_bytes: u64,
    pub chunk_size: u64,
    pub total_chunks: u64,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshHandoffChunkRecord {
    pub session_id: String,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshHandoffPreparedRecord {
    pub offer: MeshHandoffOfferRecord,
    pub chunks: Vec<MeshHandoffChunkRecord>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshHandoffProgressRecord {
    pub received_chunks: u64,
    pub total_chunks: u64,
    pub received_bytes: u64,
    pub total_bytes: u64,
    pub is_complete: bool,
    pub accepted_at: i64,
    pub last_updated_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshBundleExportRecord {
    pub bundle_json: String,
    pub encoded_bytes: u64,
    pub event_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MeshHandoffRetransmitRequestRecord {
    pub session_id: String,
    pub requested_at: i64,
    pub missing_chunk_indices: Vec<u64>,
}

#[uniffi::export]
impl PlexNode {
    /// Регистрирует найденного platform-side local mesh пира (BLE/Wi-Fi Direct handoff).
    pub fn report_local_mesh_peer(
        &self,
        peer_id: String,
        medium: String,
        endpoint_hint: String,
        signal_strength: Option<i32>,
        last_seen_at: i64,
    ) -> Result<(), PlexError> {
        self.iroh.report_local_mesh_peer(network::LocalMeshPeer {
            peer_id,
            medium,
            endpoint_hint,
            signal_strength,
            last_seen_at,
        })
    }

    /// Возвращает недавно замеченных local mesh пиров, зарегистрированных платформенным слоем.
    pub fn list_local_mesh_peers(&self) -> Result<Vec<LocalMeshPeerRecord>, PlexError> {
        Ok(self
            .iroh
            .local_mesh_peers()?
            .into_iter()
            .map(|peer| LocalMeshPeerRecord {
                peer_id: peer.peer_id,
                medium: peer.medium,
                endpoint_hint: peer.endpoint_hint,
                signal_strength: peer.signal_strength,
                last_seen_at: peer.last_seen_at,
            })
            .collect())
    }

    /// Удаляет устаревшие local mesh discovery записи из in-memory registry.
    pub fn prune_local_mesh_peers(&self, older_than: i64) -> Result<u64, PlexError> {
        self.iroh.prune_local_mesh_peers(older_than)
    }

    /// Экспортирует transport-neutral sync bundle для local mesh handoff / file drop / side-load.
    pub fn export_mesh_sync_bundle(&self, max_events: u64) -> Result<String, PlexError> {
        let bundle = sync_protocol::export_mesh_sync_bundle(&self.db, max_events as usize)?;
        serde_json::to_string(&bundle).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize mesh sync bundle: {e}"),
        })
    }

    /// Экспортирует sync bundle, ужатый под byte budget за счет ограничения числа events.
    pub fn export_mesh_sync_bundle_bounded(
        &self,
        max_events: u64,
        max_bytes: u64,
    ) -> Result<MeshBundleExportRecord, PlexError> {
        let bundle = sync_protocol::export_mesh_sync_bundle_bounded(
            &self.db,
            max_events as usize,
            max_bytes as usize,
        )?;
        let bundle_json = serde_json::to_string(&bundle).map_err(|e| PlexError::Internal {
            msg: format!("Failed to serialize bounded mesh sync bundle: {e}"),
        })?;

        Ok(MeshBundleExportRecord {
            encoded_bytes: bundle_json.len() as u64,
            event_count: bundle.events.len() as u64,
            bundle_json,
        })
    }

    /// Импортирует transport-neutral sync bundle, полученный через local mesh или внешний handoff.
    pub fn import_mesh_sync_bundle(
        &self,
        bundle_json: String,
    ) -> Result<MeshSyncImportReport, PlexError> {
        let bundle: sync_protocol::MeshSyncBundle =
            serde_json::from_str(&bundle_json).map_err(|e| PlexError::Validation {
                msg: format!("Invalid mesh sync bundle JSON: {e}"),
            })?;

        let report = sync_protocol::import_mesh_sync_bundle(&self.db, &bundle)?;
        Ok(MeshSyncImportReport {
            inserted_events: report.inserted_events as u64,
            imported_identity_registrations: report.imported_identity_registrations as u64,
            imported_verification_anchors: report.imported_verification_anchors as u64,
            imported_public_profiles: report.imported_public_profiles as u64,
            imported_dht_records: report.imported_dht_records as u64,
            imported_delivery_receipts: report.imported_delivery_receipts as u64,
        })
    }

    /// Подготавливает transport-neutral handoff session: offer + чанки sync bundle.
    pub fn prepare_mesh_handoff_bundle(
        &self,
        max_events: u64,
        chunk_size: u64,
    ) -> Result<MeshHandoffPreparedRecord, PlexError> {
        let bundle_json = self.export_mesh_sync_bundle(max_events)?;
        let (offer, chunks) = mesh_handoff::prepare_bundle(&bundle_json, chunk_size as usize)?;

        Ok(MeshHandoffPreparedRecord {
            offer: to_mesh_handoff_offer_record(offer),
            chunks: chunks
                .into_iter()
                .map(to_mesh_handoff_chunk_record)
                .collect(),
        })
    }

    /// Подготавливает handoff session под byte budget и adaptive chunk sizing.
    pub fn prepare_mesh_handoff_bundle_bounded(
        &self,
        max_events: u64,
        max_bytes: u64,
        preferred_chunk_size: u64,
        max_chunk_size: u64,
        target_chunks: u64,
    ) -> Result<MeshHandoffPreparedRecord, PlexError> {
        let export = self.export_mesh_sync_bundle_bounded(max_events, max_bytes)?;
        let (offer, chunks) = mesh_handoff::prepare_bundle_adaptive(
            &export.bundle_json,
            preferred_chunk_size as usize,
            max_chunk_size as usize,
            target_chunks as usize,
        )?;

        Ok(MeshHandoffPreparedRecord {
            offer: to_mesh_handoff_offer_record(offer),
            chunks: chunks
                .into_iter()
                .map(to_mesh_handoff_chunk_record)
                .collect(),
        })
    }

    /// Принимает offer входящей handoff-сессии и создает in-memory accumulator.
    pub fn accept_mesh_handoff_offer(
        &self,
        offer: MeshHandoffOfferRecord,
    ) -> Result<(), PlexError> {
        let mut sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;
        if sessions.len() >= MAX_MESH_HANDOFF_SESSIONS {
            return Err(PlexError::Validation {
                msg: format!("Maximum concurrent mesh handoff sessions ({MAX_MESH_HANDOFF_SESSIONS}) reached"),
            });
        }
        mesh_handoff::accept_offer(&mut sessions, from_mesh_handoff_offer_record(offer))
    }

    /// Добавляет chunk входящей handoff-сессии и возвращает прогресс сборки.
    pub fn ingest_mesh_handoff_chunk(
        &self,
        chunk: MeshHandoffChunkRecord,
    ) -> Result<MeshHandoffProgressRecord, PlexError> {
        let mut sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        let progress =
            mesh_handoff::ingest_chunk(&mut sessions, from_mesh_handoff_chunk_record(chunk))?;
        Ok(to_mesh_handoff_progress_record(progress))
    }

    /// Возвращает индексы отсутствующих chunk'ов для resumable handoff-сессии.
    pub fn missing_mesh_handoff_chunks(&self, session_id: String) -> Result<Vec<u64>, PlexError> {
        let sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        mesh_handoff::missing_chunk_indices(&sessions, &session_id)
    }

    /// Возвращает текущий прогресс входящей handoff-сессии.
    pub fn mesh_handoff_progress(
        &self,
        session_id: String,
    ) -> Result<MeshHandoffProgressRecord, PlexError> {
        let sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        let progress = mesh_handoff::session_progress(&sessions, &session_id)?;
        Ok(to_mesh_handoff_progress_record(progress))
    }

    /// Формирует explicit retransmit request со списком недостающих chunk'ов.
    pub fn request_mesh_handoff_retransmit(
        &self,
        session_id: String,
    ) -> Result<MeshHandoffRetransmitRequestRecord, PlexError> {
        let sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        let request = mesh_handoff::build_retransmit_request(&sessions, &session_id)?;
        Ok(to_mesh_handoff_retransmit_request_record(request))
    }

    /// Выбирает только запрошенные чанки для selective retransmit на стороне отправителя.
    pub fn select_mesh_handoff_retransmit_chunks(
        &self,
        prepared: MeshHandoffPreparedRecord,
        request: MeshHandoffRetransmitRequestRecord,
    ) -> Result<Vec<MeshHandoffChunkRecord>, PlexError> {
        let chunks = prepared
            .chunks
            .into_iter()
            .map(from_mesh_handoff_chunk_record)
            .collect::<Vec<_>>();
        let request = from_mesh_handoff_retransmit_request_record(request);

        Ok(mesh_handoff::select_requested_chunks(&chunks, &request)?
            .into_iter()
            .map(to_mesh_handoff_chunk_record)
            .collect())
    }

    /// Удаляет устаревшие in-memory handoff-сессии по last_updated_at.
    pub fn prune_expired_mesh_handoff_sessions(&self, older_than: i64) -> Result<u64, PlexError> {
        let mut sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        Ok(mesh_handoff::prune_expired_sessions(
            &mut sessions,
            older_than,
        ))
    }

    /// Завершает handoff-сессию: собирает JSON bundle, импортирует его и очищает accumulator.
    pub fn commit_mesh_handoff_session(
        &self,
        session_id: String,
    ) -> Result<MeshSyncImportReport, PlexError> {
        let bundle_json = {
            let sessions = self
                .incoming_mesh_handoffs
                .lock()
                .map_err(|e| PlexError::Internal {
                    msg: format!("Mesh handoff mutex poisoned: {e}"),
                })?;
            mesh_handoff::assemble_bundle_json(&sessions, &session_id)?
        };

        let report = self.import_mesh_sync_bundle(bundle_json)?;

        let mut sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;
        mesh_handoff::discard_session(&mut sessions, &session_id);

        Ok(report)
    }

    /// Отменяет входящую handoff-сессию и удаляет накопленные чанки из памяти.
    pub fn discard_mesh_handoff_session(&self, session_id: String) -> Result<bool, PlexError> {
        let mut sessions = self
            .incoming_mesh_handoffs
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Mesh handoff mutex poisoned: {e}"),
            })?;

        Ok(mesh_handoff::discard_session(&mut sessions, &session_id))
    }
}

fn to_mesh_handoff_offer_record(offer: mesh_handoff::MeshHandoffOffer) -> MeshHandoffOfferRecord {
    MeshHandoffOfferRecord {
        session_id: offer.session_id,
        generated_at: offer.generated_at,
        total_bytes: offer.total_bytes,
        chunk_size: offer.chunk_size,
        total_chunks: offer.total_chunks,
        bundle_sha256: offer.bundle_sha256,
    }
}

fn from_mesh_handoff_offer_record(offer: MeshHandoffOfferRecord) -> mesh_handoff::MeshHandoffOffer {
    mesh_handoff::MeshHandoffOffer {
        session_id: offer.session_id,
        generated_at: offer.generated_at,
        total_bytes: offer.total_bytes,
        chunk_size: offer.chunk_size,
        total_chunks: offer.total_chunks,
        bundle_sha256: offer.bundle_sha256,
    }
}

fn to_mesh_handoff_chunk_record(chunk: mesh_handoff::MeshHandoffChunk) -> MeshHandoffChunkRecord {
    MeshHandoffChunkRecord {
        session_id: chunk.session_id,
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        payload: chunk.payload,
    }
}

fn from_mesh_handoff_chunk_record(chunk: MeshHandoffChunkRecord) -> mesh_handoff::MeshHandoffChunk {
    mesh_handoff::MeshHandoffChunk {
        session_id: chunk.session_id,
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        payload: chunk.payload,
    }
}

fn to_mesh_handoff_progress_record(
    progress: mesh_handoff::MeshHandoffProgress,
) -> MeshHandoffProgressRecord {
    MeshHandoffProgressRecord {
        received_chunks: progress.received_chunks,
        total_chunks: progress.total_chunks,
        received_bytes: progress.received_bytes,
        total_bytes: progress.total_bytes,
        is_complete: progress.is_complete,
        accepted_at: progress.accepted_at,
        last_updated_at: progress.last_updated_at,
    }
}

fn to_mesh_handoff_retransmit_request_record(
    request: mesh_handoff::MeshHandoffRetransmitRequest,
) -> MeshHandoffRetransmitRequestRecord {
    MeshHandoffRetransmitRequestRecord {
        session_id: request.session_id,
        requested_at: request.requested_at,
        missing_chunk_indices: request.missing_chunk_indices,
    }
}

fn from_mesh_handoff_retransmit_request_record(
    request: MeshHandoffRetransmitRequestRecord,
) -> mesh_handoff::MeshHandoffRetransmitRequest {
    mesh_handoff::MeshHandoffRetransmitRequest {
        session_id: request.session_id,
        requested_at: request.requested_at,
        missing_chunk_indices: request.missing_chunk_indices,
    }
}
