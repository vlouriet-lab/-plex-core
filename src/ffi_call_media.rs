use std::time::{SystemTime, UNIX_EPOCH};

use crate::{call_media, PlexError, PlexNode};

/// Состояние ICE-согласования media plane (RFC 8445).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum CallIceStateRecord {
    /// ICE ещё не запущен.
    Idle,
    /// ICE-агент собирает candidates.
    Gathering,
    /// ICE выполняет проверку кандидатов.
    Checking,
    /// ICE-согласование завершено, media plane активна.
    Connected,
    /// Все кандидаты провалились — media plane недоступна.
    Failed,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum CallMediaRouteRecord {
    Unknown,
    Direct,
    Relay,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallMediaSessionRecord {
    pub call_id: String,
    pub audio_enabled: bool,
    pub video_enabled: bool,
    pub speaker_enabled: bool,
    pub camera_front: bool,
    pub network_quality: u8,
    pub route: CallMediaRouteRecord,
    /// Состояние ICE-согласования.
    pub ice_state: CallIceStateRecord,
    pub updated_at: i64,
}

#[uniffi::export]
impl PlexNode {
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_call_media_session(
        &self,
        call_id: String,
        audio_enabled: bool,
        video_enabled: bool,
        speaker_enabled: bool,
        camera_front: bool,
        network_quality: u8,
        route: CallMediaRouteRecord,
    ) -> Result<CallMediaSessionRecord, PlexError> {
        if call_id.trim().is_empty() {
            return Err(PlexError::Validation {
                msg: "call_id must not be empty".into(),
            });
        }

        let now = now_secs()?;

        let session = call_media::CallMediaSession {
            call_id: call_id.clone(),
            audio_enabled,
            video_enabled,
            speaker_enabled,
            camera_front,
            network_quality,
            route: from_record_route(route),
            ice_state: call_media::CallIceState::Idle,
            updated_at: now,
        };

        let mut sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;

        call_media::upsert_session(&mut sessions, session.clone());
        Ok(to_record(session))
    }

    pub fn get_call_media_session(
        &self,
        call_id: String,
    ) -> Result<Option<CallMediaSessionRecord>, PlexError> {
        let sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;
        Ok(sessions.get(&call_id).cloned().map(to_record))
    }

    pub fn list_call_media_sessions(&self) -> Result<Vec<CallMediaSessionRecord>, PlexError> {
        let sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;
        Ok(sessions.values().cloned().map(to_record).collect())
    }

    pub fn remove_call_media_session(&self, call_id: String) -> Result<bool, PlexError> {
        let mut sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;
        Ok(call_media::remove_session(&mut sessions, &call_id))
    }

    // ── ICE state transitions ─────────────────────────────────────────────────

    /// Переводит media-сессию в состояние Gathering (начало сбора ICE-кандидатов).
    pub fn mark_call_ice_gathering(&self, call_id: String) -> Result<bool, PlexError> {
        self.advance_ice(call_id, call_media::CallIceState::Gathering)
    }

    /// Переводит media-сессию в Checking (ICE проверяет кандидатов).
    pub fn mark_call_ice_checking(&self, call_id: String) -> Result<bool, PlexError> {
        self.advance_ice(call_id, call_media::CallIceState::Checking)
    }

    /// Помечает media-сессию как подключённую (ICE Connected — media plane работает).
    /// Также обновляет маршрут (Direct / Relay) на основе результата ICE.
    pub fn mark_call_ice_connected(
        &self,
        call_id: String,
        route: CallMediaRouteRecord,
    ) -> Result<bool, PlexError> {
        let now = now_secs()?;
        let mut sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;
        if let Some(session) = sessions.get_mut(&call_id) {
            session.ice_state = call_media::CallIceState::Connected;
            session.route = from_record_route(route);
            session.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Помечает media-сессию как Failed (все ICE-кандидаты провалились).
    pub fn mark_call_ice_failed(&self, call_id: String) -> Result<bool, PlexError> {
        self.advance_ice(call_id, call_media::CallIceState::Failed)
    }
}

impl PlexNode {
    fn advance_ice(
        &self,
        call_id: String,
        state: call_media::CallIceState,
    ) -> Result<bool, PlexError> {
        let now = now_secs()?;
        let mut sessions = self
            .call_media_sessions
            .lock()
            .map_err(|e| PlexError::Internal {
                msg: format!("Call media sessions mutex poisoned: {e}"),
            })?;
        Ok(call_media::advance_ice_state(
            &mut sessions,
            &call_id,
            state,
            now,
        ))
    }
}

fn now_secs() -> Result<i64, PlexError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })
        .map(|d| d.as_secs() as i64)
}

fn from_record_route(route: CallMediaRouteRecord) -> call_media::CallMediaRoute {
    match route {
        CallMediaRouteRecord::Unknown => call_media::CallMediaRoute::Unknown,
        CallMediaRouteRecord::Direct => call_media::CallMediaRoute::Direct,
        CallMediaRouteRecord::Relay => call_media::CallMediaRoute::Relay,
    }
}

fn to_record_route(route: call_media::CallMediaRoute) -> CallMediaRouteRecord {
    match route {
        call_media::CallMediaRoute::Unknown => CallMediaRouteRecord::Unknown,
        call_media::CallMediaRoute::Direct => CallMediaRouteRecord::Direct,
        call_media::CallMediaRoute::Relay => CallMediaRouteRecord::Relay,
    }
}

fn to_ice_state(state: call_media::CallIceState) -> CallIceStateRecord {
    match state {
        call_media::CallIceState::Idle => CallIceStateRecord::Idle,
        call_media::CallIceState::Gathering => CallIceStateRecord::Gathering,
        call_media::CallIceState::Checking => CallIceStateRecord::Checking,
        call_media::CallIceState::Connected => CallIceStateRecord::Connected,
        call_media::CallIceState::Failed => CallIceStateRecord::Failed,
    }
}

fn to_record(session: call_media::CallMediaSession) -> CallMediaSessionRecord {
    CallMediaSessionRecord {
        call_id: session.call_id,
        audio_enabled: session.audio_enabled,
        video_enabled: session.video_enabled,
        speaker_enabled: session.speaker_enabled,
        camera_front: session.camera_front,
        network_quality: session.network_quality,
        route: to_record_route(session.route),
        ice_state: to_ice_state(session.ice_state),
        updated_at: session.updated_at,
    }
}
