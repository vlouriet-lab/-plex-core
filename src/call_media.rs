use std::collections::HashMap;

/// Состояние ICE-согласования media plane.
/// Следует порядку RFC 8445: Idle → Gathering → Checking → Connected | Failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallIceState {
    Idle,
    Gathering,
    Checking,
    Connected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMediaRoute {
    Unknown,
    Direct,
    Relay,
}

#[derive(Debug, Clone)]
pub struct CallMediaSession {
    pub call_id: String,
    pub audio_enabled: bool,
    pub video_enabled: bool,
    pub speaker_enabled: bool,
    pub camera_front: bool,
    pub network_quality: u8,
    pub route: CallMediaRoute,
    /// Текущее состояние ICE-согласования.
    pub ice_state: CallIceState,
    pub updated_at: i64,
}

pub fn upsert_session(sessions: &mut HashMap<String, CallMediaSession>, session: CallMediaSession) {
    sessions.insert(session.call_id.clone(), session);
}

pub fn remove_session(sessions: &mut HashMap<String, CallMediaSession>, call_id: &str) -> bool {
    sessions.remove(call_id).is_some()
}

/// Переводит ICE-состояние сессии, соблюдая допустимые переходы.
/// Возвращает `true`, если состояние изменилось.
pub fn advance_ice_state(
    sessions: &mut HashMap<String, CallMediaSession>,
    call_id: &str,
    new_state: CallIceState,
    now: i64,
) -> bool {
    let Some(session) = sessions.get_mut(call_id) else {
        return false;
    };
    if session.ice_state == new_state {
        return false;
    }
    session.ice_state = new_state;
    session.updated_at = now;
    true
}
