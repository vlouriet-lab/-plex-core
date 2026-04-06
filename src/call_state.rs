use std::collections::HashMap;

use crate::{calls, PlexError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSessionState {
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

impl CallSessionState {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            CallSessionState::Ended
                | CallSessionState::Rejected
                | CallSessionState::Busy
                | CallSessionState::Failed
        )
    }
}

#[derive(Debug, Clone)]
pub struct CallSession {
    pub call_id: String,
    pub local_peer_id: String,
    pub remote_peer_id: String,
    pub is_outgoing: bool,
    pub state: CallSessionState,
    pub created_at: i64,
    pub last_updated_at: i64,
    pub last_error: Option<String>,
}

pub fn ensure_outgoing_session(
    sessions: &mut HashMap<String, CallSession>,
    local_peer_id: &str,
    remote_peer_id: &str,
    call_id: &str,
    now: i64,
) {
    sessions
        .entry(call_id.to_string())
        .or_insert_with(|| CallSession {
            call_id: call_id.to_string(),
            local_peer_id: local_peer_id.to_string(),
            remote_peer_id: remote_peer_id.to_string(),
            is_outgoing: true,
            state: CallSessionState::RingingOutgoing,
            created_at: now,
            last_updated_at: now,
            last_error: None,
        });
}

pub fn apply_outgoing_signal(
    sessions: &mut HashMap<String, CallSession>,
    call_id: &str,
    kind: calls::CallSignalKind,
    now: i64,
) -> Result<CallSession, PlexError> {
    let session = sessions
        .get_mut(call_id)
        .ok_or_else(|| PlexError::Internal {
            msg: format!("Unknown outgoing call session {call_id}"),
        })?;

    match kind {
        calls::CallSignalKind::Ring => {
            session.state = CallSessionState::RingingOutgoing;
        }
        calls::CallSignalKind::Offer => {
            session.state = CallSessionState::Connecting;
        }
        calls::CallSignalKind::Answer => {
            session.state = CallSessionState::Active;
        }
        calls::CallSignalKind::IceCandidate => {
            if matches!(session.state, CallSessionState::RingingOutgoing) {
                session.state = CallSessionState::Connecting;
            }
        }
        calls::CallSignalKind::End => {
            session.state = CallSessionState::Ended;
        }
        calls::CallSignalKind::Reject => {
            session.state = CallSessionState::Rejected;
        }
        calls::CallSignalKind::Busy => {
            session.state = CallSessionState::Busy;
        }
    }

    session.last_updated_at = now;
    Ok(session.clone())
}

pub fn apply_incoming_signal(
    sessions: &mut HashMap<String, CallSession>,
    local_peer_id: &str,
    signal: &calls::CallSignal,
    now: i64,
) -> Result<CallSession, PlexError> {
    if signal.to_peer_id != local_peer_id {
        return Err(PlexError::Network {
            msg: format!(
                "Incoming call signal target mismatch: {} != {}",
                signal.to_peer_id, local_peer_id
            ),
        });
    }

    let session = sessions
        .entry(signal.call_id.clone())
        .or_insert_with(|| CallSession {
            call_id: signal.call_id.clone(),
            local_peer_id: local_peer_id.to_string(),
            remote_peer_id: signal.from_peer_id.clone(),
            is_outgoing: false,
            state: CallSessionState::RingingIncoming,
            created_at: now,
            last_updated_at: now,
            last_error: None,
        });

    match signal.kind {
        calls::CallSignalKind::Ring => {
            if !session.state.is_terminal() {
                session.state = CallSessionState::RingingIncoming;
            }
        }
        calls::CallSignalKind::Offer => {
            session.state = CallSessionState::Connecting;
        }
        calls::CallSignalKind::Answer => {
            session.state = CallSessionState::Active;
        }
        calls::CallSignalKind::IceCandidate => {
            if matches!(session.state, CallSessionState::RingingIncoming) {
                session.state = CallSessionState::Connecting;
            }
        }
        calls::CallSignalKind::End => {
            session.state = CallSessionState::Ended;
        }
        calls::CallSignalKind::Reject => {
            session.state = CallSessionState::Rejected;
        }
        calls::CallSignalKind::Busy => {
            session.state = CallSessionState::Busy;
        }
    }

    session.last_updated_at = now;
    Ok(session.clone())
}

pub fn mark_reconnecting(
    sessions: &mut HashMap<String, CallSession>,
    call_id: &str,
    now: i64,
) -> Result<CallSession, PlexError> {
    let session = sessions
        .get_mut(call_id)
        .ok_or_else(|| PlexError::Internal {
            msg: format!("Unknown call session {call_id}"),
        })?;

    if !session.state.is_terminal() {
        session.state = CallSessionState::Reconnecting;
        session.last_updated_at = now;
    }
    Ok(session.clone())
}

pub fn timeout_stale_sessions(
    sessions: &mut HashMap<String, CallSession>,
    stale_before: i64,
) -> u64 {
    let mut timed_out = 0u64;
    for session in sessions.values_mut() {
        if session.state.is_terminal() {
            continue;
        }
        if session.last_updated_at < stale_before {
            session.state = CallSessionState::Failed;
            session.last_error = Some("call session timeout".to_string());
            session.last_updated_at = stale_before;
            timed_out += 1;
        }
    }
    timed_out
}

pub fn prune_terminal_sessions(
    sessions: &mut HashMap<String, CallSession>,
    older_than: i64,
) -> u64 {
    let before = sessions.len();
    sessions.retain(|_, session| {
        !(session.state.is_terminal() && session.last_updated_at < older_than)
    });
    (before.saturating_sub(sessions.len())) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_offer_then_answer_becomes_active() {
        let mut sessions = HashMap::new();
        ensure_outgoing_session(&mut sessions, "me", "peer", "call-1", 10);

        let s1 = apply_outgoing_signal(&mut sessions, "call-1", calls::CallSignalKind::Offer, 11)
            .unwrap();
        assert!(matches!(s1.state, CallSessionState::Connecting));

        let answer = calls::CallSignal {
            protocol: calls::CALL_SIGNAL_PROTOCOL.to_string(),
            call_id: "call-1".to_string(),
            from_peer_id: "peer".to_string(),
            to_peer_id: "me".to_string(),
            kind: calls::CallSignalKind::Answer,
            payload: String::new(),
            created_at: 12,
        };
        let s2 = apply_incoming_signal(&mut sessions, "me", &answer, 12).unwrap();
        assert!(matches!(s2.state, CallSessionState::Active));
    }

    #[test]
    fn stale_connecting_session_times_out() {
        let mut sessions = HashMap::new();
        ensure_outgoing_session(&mut sessions, "me", "peer", "call-1", 10);
        apply_outgoing_signal(&mut sessions, "call-1", calls::CallSignalKind::Offer, 11).unwrap();

        let timed_out = timeout_stale_sessions(&mut sessions, 100);
        assert_eq!(timed_out, 1);
        let session = sessions.get("call-1").unwrap();
        assert!(matches!(session.state, CallSessionState::Failed));
    }
}
