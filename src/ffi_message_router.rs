//! FFI-слой для Message Router
//!
//! Экспортирует методы для работы с retry-очередью сообщений через UniFFI.

use crate::message_router::{DeliveryRecord, OutboundMessageEnvelope, RoutingDecision};
use serde::{Deserialize, Serialize};

/// Record для FFI-передачи решения о маршруте
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct RoutingDecisionRecord {
    pub route_type: String, // "direct", "group_broadcast", "local_mdns"
    pub peer_id: Option<String>,
    pub group_id: Option<Vec<u8>>, // 16 bytes
    pub via_relay: bool,
}

impl From<&RoutingDecision> for RoutingDecisionRecord {
    fn from(rd: &RoutingDecision) -> Self {
        match rd {
            RoutingDecision::Direct { peer_id, via_relay } => RoutingDecisionRecord {
                route_type: "direct".to_string(),
                peer_id: Some(peer_id.clone()),
                group_id: None,
                via_relay: *via_relay,
            },
            RoutingDecision::GroupBroadcast { group_id } => RoutingDecisionRecord {
                route_type: "group_broadcast".to_string(),
                peer_id: None,
                group_id: Some(group_id.to_vec()),
                via_relay: false,
            },
            RoutingDecision::LocalMdns { peer_id } => RoutingDecisionRecord {
                route_type: "local_mdns".to_string(),
                peer_id: Some(peer_id.clone()),
                group_id: None,
                via_relay: false,
            },
        }
    }
}

/// Record для FFI-передачи исходящего сообщения
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct OutboundMessageRecord {
    pub message_id: String,
    pub payload_size: u32,
    pub routing: RoutingDecisionRecord,
    pub attempt: u32,
    pub max_attempts: u32,
    pub created_at: u64,
    pub backoff_until: Option<u64>,
}

impl From<&OutboundMessageEnvelope> for OutboundMessageRecord {
    fn from(env: &OutboundMessageEnvelope) -> Self {
        OutboundMessageRecord {
            message_id: env.message_id.clone(),
            payload_size: env.payload.len() as u32,
            routing: (&env.routing).into(),
            attempt: env.attempt,
            max_attempts: env.max_attempts,
            created_at: env.created_at,
            backoff_until: env.backoff_until,
        }
    }
}

/// Record для FFI-передачи статуса доставки
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DeliveryStatusRecord {
    pub message_id: String,
    pub status: String, // "pending", "sending", "delivered", "failed", "cancelled"
    pub attempt: u32,
    pub max_attempts: u32,
    pub created_at: u64,
    pub last_attempt_at: Option<u64>,
    pub delivered_at: Option<u64>,
    pub failed_reason: Option<String>,
}

impl From<&DeliveryRecord> for DeliveryStatusRecord {
    fn from(record: &DeliveryRecord) -> Self {
        DeliveryStatusRecord {
            message_id: record.message_id.clone(),
            status: record.status.as_str().to_string(),
            attempt: record.attempt,
            max_attempts: record.max_attempts,
            created_at: record.created_at,
            last_attempt_at: record.last_attempt_at,
            delivered_at: record.delivered_at,
            failed_reason: record.failed_reason.clone(),
        }
    }
}
