use std::time::{SystemTime, UNIX_EPOCH};

use crate::{call_state, calls, PlexError, PlexNode};

/// Максимальный размер call signal payload (16 КБ достаточно для SDP/ICE).
const MAX_CALL_SIGNAL_PAYLOAD_BYTES: usize = 16 * 1024;
/// Максимальное число одновременных call-сессий в памяти (DoS-граница).
const MAX_CALL_SESSIONS: usize = 256;

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CallSignalType {
    Ring,
    Offer,
    Answer,
    IceCandidate,
    End,
    Reject,
    Busy,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallSignalRecord {
    pub call_id: String,
    pub from_peer_id: String,
    pub to_peer_id: String,
    pub signal_type: CallSignalType,
    pub payload: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CallSessionStateRecord {
    RingingOutgoing,
    RingingIncoming,
    Connecting,
    Active,
    Reconnecting,
    Ended,
    Rejected,
    Busy,
    Failed,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallSessionRecord {
    pub call_id: String,
    pub local_peer_id: String,
    pub remote_peer_id: String,
    pub is_outgoing: bool,
    pub state: CallSessionStateRecord,
    pub created_at: i64,
    pub last_updated_at: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallMaintenanceReport {
    pub timed_out_sessions: u64,
    pub pruned_terminal_sessions: u64,
}

#[uniffi::export]
impl PlexNode {
    /// Отправляет call signaling payload в зашифрованный outbox (transport-agnostic delivery).
    pub fn send_call_signal(
        &self,
        to_peer_id: String,
        call_id: String,
        signal_type: CallSignalType,
        payload: String,
    ) -> Result<String, PlexError> {
        if payload.len() > MAX_CALL_SIGNAL_PAYLOAD_BYTES {
            return Err(PlexError::Validation {
                msg: format!(
                    "Call signal payload too large: {} bytes (max {})",
                    payload.len(),
                    MAX_CALL_SIGNAL_PAYLOAD_BYTES,
                ),
            });
        }
        let from_peer_id = self.iroh.node_id().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let signal = calls::CallSignal {
            protocol: calls::CALL_SIGNAL_PROTOCOL.to_string(),
            call_id,
            from_peer_id: from_peer_id.clone(),
            to_peer_id: to_peer_id.clone(),
            kind: to_call_signal_kind(signal_type),
            payload,
            created_at,
        };

        {
            let mut sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
                msg: format!("Call sessions mutex poisoned: {e}"),
            })?;

            call_state::ensure_outgoing_session(
                &mut sessions,
                &from_peer_id,
                &to_peer_id,
                &signal.call_id,
                created_at,
            );
            let _ = call_state::apply_outgoing_signal(
                &mut sessions,
                &signal.call_id,
                signal.kind,
                created_at,
            )?;
        }

        // Track call-lifecycle metrics
        match signal.kind {
            calls::CallSignalKind::Ring => self.metrics.inc(&self.metrics.calls_initiated_total),
            calls::CallSignalKind::End => self.metrics.inc(&self.metrics.calls_ended_total),
            _ => {}
        }

        let plaintext = calls::encode_signal(&signal)?;
        self.queue_encrypted_message_for_peer(to_peer_id, plaintext)
    }

    /// Декодирует plaintext call signaling payload после расшифрования transport-сообщения.
    pub fn decode_call_signal_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<CallSignalRecord, PlexError> {
        let signal = calls::decode_signal(&payload)?;
        Ok(CallSignalRecord {
            call_id: signal.call_id,
            from_peer_id: signal.from_peer_id,
            to_peer_id: signal.to_peer_id,
            signal_type: from_call_signal_kind(signal.kind),
            payload: signal.payload,
            created_at: signal.created_at,
        })
    }

    /// Применяет входящий call signaling payload к локальной call state machine.
    pub fn apply_incoming_call_signal(
        &self,
        payload: Vec<u8>,
    ) -> Result<CallSessionRecord, PlexError> {
        let signal = calls::decode_signal(&payload)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;
        let local_peer = self.iroh.node_id().to_string();

        let mut sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
            msg: format!("Call sessions mutex poisoned: {e}"),
        })?;
        if sessions.len() >= MAX_CALL_SESSIONS && !sessions.contains_key(&signal.call_id) {
            return Err(PlexError::Validation {
                msg: format!("Maximum concurrent call sessions ({MAX_CALL_SESSIONS}) reached"),
            });
        }
        let session = call_state::apply_incoming_signal(&mut sessions, &local_peer, &signal, now)?;

        // Track incoming lifecycle metrics
        match signal.kind {
            calls::CallSignalKind::Ring => self.metrics.inc(&self.metrics.calls_received_total),
            calls::CallSignalKind::End => self.metrics.inc(&self.metrics.calls_ended_total),
            _ => {}
        }

        Ok(to_call_session_record(session))
    }

    /// Принудительно переводит звонок в reconnecting (например, при потере media-сокета).
    pub fn mark_call_reconnecting(&self, call_id: String) -> Result<CallSessionRecord, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let mut sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
            msg: format!("Call sessions mutex poisoned: {e}"),
        })?;
        let session = call_state::mark_reconnecting(&mut sessions, &call_id, now)?;
        Ok(to_call_session_record(session))
    }

    /// Возвращает звонковую сессию по call_id.
    pub fn get_call_session(
        &self,
        call_id: String,
    ) -> Result<Option<CallSessionRecord>, PlexError> {
        let sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
            msg: format!("Call sessions mutex poisoned: {e}"),
        })?;
        Ok(sessions.get(&call_id).cloned().map(to_call_session_record))
    }

    /// Возвращает все известные звонковые сессии.
    pub fn list_call_sessions(&self) -> Result<Vec<CallSessionRecord>, PlexError> {
        let sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
            msg: format!("Call sessions mutex poisoned: {e}"),
        })?;
        Ok(sessions
            .values()
            .cloned()
            .map(to_call_session_record)
            .collect())
    }

    /// Выполняет timeout/GC call-сессий.
    pub fn call_maintenance_tick(
        &self,
        stale_after_secs: u64,
        prune_terminal_after_secs: u64,
    ) -> Result<CallMaintenanceReport, PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let stale_before = now.saturating_sub(stale_after_secs as i64);
        let prune_before = now.saturating_sub(prune_terminal_after_secs as i64);

        let mut sessions = self.call_sessions.lock().map_err(|e| PlexError::Internal {
            msg: format!("Call sessions mutex poisoned: {e}"),
        })?;

        let timed_out_sessions = call_state::timeout_stale_sessions(&mut sessions, stale_before);
        let pruned_terminal_sessions =
            call_state::prune_terminal_sessions(&mut sessions, prune_before);

        Ok(CallMaintenanceReport {
            timed_out_sessions,
            pruned_terminal_sessions,
        })
    }
}

fn to_call_signal_kind(signal_type: CallSignalType) -> calls::CallSignalKind {
    match signal_type {
        CallSignalType::Ring => calls::CallSignalKind::Ring,
        CallSignalType::Offer => calls::CallSignalKind::Offer,
        CallSignalType::Answer => calls::CallSignalKind::Answer,
        CallSignalType::IceCandidate => calls::CallSignalKind::IceCandidate,
        CallSignalType::End => calls::CallSignalKind::End,
        CallSignalType::Reject => calls::CallSignalKind::Reject,
        CallSignalType::Busy => calls::CallSignalKind::Busy,
    }
}

fn from_call_signal_kind(kind: calls::CallSignalKind) -> CallSignalType {
    match kind {
        calls::CallSignalKind::Ring => CallSignalType::Ring,
        calls::CallSignalKind::Offer => CallSignalType::Offer,
        calls::CallSignalKind::Answer => CallSignalType::Answer,
        calls::CallSignalKind::IceCandidate => CallSignalType::IceCandidate,
        calls::CallSignalKind::End => CallSignalType::End,
        calls::CallSignalKind::Reject => CallSignalType::Reject,
        calls::CallSignalKind::Busy => CallSignalType::Busy,
    }
}

fn to_call_session_state_record(state: call_state::CallSessionState) -> CallSessionStateRecord {
    match state {
        call_state::CallSessionState::RingingOutgoing => CallSessionStateRecord::RingingOutgoing,
        call_state::CallSessionState::RingingIncoming => CallSessionStateRecord::RingingIncoming,
        call_state::CallSessionState::Connecting => CallSessionStateRecord::Connecting,
        call_state::CallSessionState::Active => CallSessionStateRecord::Active,
        call_state::CallSessionState::Reconnecting => CallSessionStateRecord::Reconnecting,
        call_state::CallSessionState::Ended => CallSessionStateRecord::Ended,
        call_state::CallSessionState::Rejected => CallSessionStateRecord::Rejected,
        call_state::CallSessionState::Busy => CallSessionStateRecord::Busy,
        call_state::CallSessionState::Failed => CallSessionStateRecord::Failed,
    }
}

fn to_call_session_record(session: call_state::CallSession) -> CallSessionRecord {
    CallSessionRecord {
        call_id: session.call_id,
        local_peer_id: session.local_peer_id,
        remote_peer_id: session.remote_peer_id,
        is_outgoing: session.is_outgoing,
        state: to_call_session_state_record(session.state),
        created_at: session.created_at,
        last_updated_at: session.last_updated_at,
        last_error: session.last_error,
    }
}

// ── Типы для персистентного журнала сигналов ─────────────────────────────────

/// Направление сохранённого call сигнала.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CallSignalDirection {
    Outgoing,
    Incoming,
}

/// Сохранённая запись call сигнала (из персистентного журнала).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SavedCallSignalRecord {
    pub signal_id: String,
    pub call_id: String,
    pub peer_id: String,
    pub direction: CallSignalDirection,
    pub signal_type: CallSignalType,
    pub payload: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallSignalPruneReport {
    pub pruned_count: u64,
}

#[uniffi::export]
impl PlexNode {
    /// Сохраняет call сигнал в персистентный журнал.
    ///
    /// Android-слой должен вызывать это после каждого успешного `send_call_signal`
    /// и после каждого полученного и обработанного сигнала, чтобы на случай
    /// перезапуска процесса можно было восстановить ICE-сессию.
    pub fn persist_call_signal(
        &self,
        call_id: String,
        peer_id: String,
        direction: CallSignalDirection,
        signal_type: CallSignalType,
        payload: String,
        created_at: i64,
    ) -> Result<String, PlexError> {
        let kind = call_signal_kind_str(to_call_signal_kind(signal_type));
        match direction {
            CallSignalDirection::Outgoing => self
                .db
                .save_outgoing_call_signal(&call_id, &peer_id, kind, &payload, created_at),
            CallSignalDirection::Incoming => self
                .db
                .save_incoming_call_signal(&call_id, &peer_id, kind, &payload, created_at),
        }
    }

    /// Возвращает все персистентные сигналы для `call_id` в хронологическом порядке.
    ///
    /// Используется при реконнекте для восстановления ICE-состояния без нового Ring.
    pub fn load_persisted_call_signals(
        &self,
        call_id: String,
    ) -> Result<Vec<SavedCallSignalRecord>, PlexError> {
        self.db
            .load_call_signals_for_call(&call_id)?
            .into_iter()
            .map(|s| {
                let direction = if s.direction == "outgoing" {
                    CallSignalDirection::Outgoing
                } else {
                    CallSignalDirection::Incoming
                };
                let signal_type = parse_call_signal_kind(&s.kind)?;
                Ok(SavedCallSignalRecord {
                    signal_id: s.signal_id,
                    call_id: s.call_id,
                    peer_id: s.peer_id,
                    direction,
                    signal_type,
                    payload: s.payload,
                    created_at: s.created_at,
                })
            })
            .collect()
    }

    /// Удаляет все персистентные сигналы для завершённого звонка.
    ///
    /// Вызывайте когда звонок переходит в состояние Ended / Rejected / Busy.
    pub fn prune_call_signals_for_call(
        &self,
        call_id: String,
    ) -> Result<CallSignalPruneReport, PlexError> {
        let pruned_count = self.db.prune_call_signals_for_call(&call_id)?;
        Ok(CallSignalPruneReport { pruned_count })
    }
}

fn call_signal_kind_str(kind: calls::CallSignalKind) -> &'static str {
    match kind {
        calls::CallSignalKind::Ring => "ring",
        calls::CallSignalKind::Offer => "offer",
        calls::CallSignalKind::Answer => "answer",
        calls::CallSignalKind::IceCandidate => "ice_candidate",
        calls::CallSignalKind::End => "end",
        calls::CallSignalKind::Reject => "reject",
        calls::CallSignalKind::Busy => "busy",
    }
}

fn parse_call_signal_kind(kind: &str) -> Result<CallSignalType, PlexError> {
    match kind {
        "ring" => Ok(CallSignalType::Ring),
        "offer" => Ok(CallSignalType::Offer),
        "answer" => Ok(CallSignalType::Answer),
        "ice_candidate" => Ok(CallSignalType::IceCandidate),
        "end" => Ok(CallSignalType::End),
        "reject" => Ok(CallSignalType::Reject),
        "busy" => Ok(CallSignalType::Busy),
        other => Err(PlexError::Internal {
            msg: format!("Unknown call signal kind in storage: {other}"),
        }),
    }
}
