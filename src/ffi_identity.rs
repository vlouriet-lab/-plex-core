use std::time::{SystemTime, UNIX_EPOCH};

use iroh_base::Signature;
use tracing::warn;

use crate::{storage, PlexError, PlexNode};

const IDENTITY_REGISTRATION_WINDOW_SECS: i64 = 60;
const MAX_IDENTITY_REGISTRATIONS_PER_WINDOW: u64 = 200;
const VERIFICATION_ANCHOR_WINDOW_SECS: i64 = 60;
const MAX_ANCHORS_PER_PEER_PER_WINDOW: u64 = 120;

#[derive(Debug, Clone, uniffi::Record)]
pub struct PeerVerificationStatus {
    pub peer_id: String,
    pub has_identity_registration: bool,
    pub registrar_node_id: Option<String>,
    pub latest_anchor_chain: Option<String>,
    pub latest_anchor_tx_id: Option<String>,
    pub latest_anchor_event_hash: Option<String>,
    pub latest_anchor_confirmations: Option<u64>,
    pub anchor_count: u64,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum PeerTrustLevel {
    Unverified,
    Registered,
    Anchored,
    Trusted,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VerificationPolicy {
    pub min_confirmations: u64,
    pub min_anchor_count: u64,
    pub max_anchor_age_seconds: u64,
    pub allowed_chains: Vec<String>,
}

#[uniffi::export]
impl PlexNode {
    /// Регистрирует identity commitment пира, подписывая запись локальным NodeID.
    pub fn register_peer_identity(
        &self,
        peer_id: String,
        identity_commitment: Vec<u8>,
    ) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let window_start = now - IDENTITY_REGISTRATION_WINDOW_SECS;
        let registrations_in_window = self.db.identity_registration_count_since(window_start)?;
        if registrations_in_window >= MAX_IDENTITY_REGISTRATIONS_PER_WINDOW {
            warn!(
                registrations_in_window,
                limit = MAX_IDENTITY_REGISTRATIONS_PER_WINDOW,
                window_secs = IDENTITY_REGISTRATION_WINDOW_SECS,
                "[security] identity registration rate limit exceeded"
            );
            return Err(PlexError::RateLimit {
                msg: format!(
                    "Identity registration rate limit exceeded: {} in {}s",
                    registrations_in_window, IDENTITY_REGISTRATION_WINDOW_SECS,
                ),
            });
        }

        let registrar_node_id = self.iroh.secret_key().public().to_string();
        let signing_payload =
            storage::identity_registration_signing_payload(&peer_id, &identity_commitment, now);
        let registrar_signature = self
            .iroh
            .secret_key()
            .sign(&signing_payload)
            .to_bytes()
            .to_vec();

        let record = storage::IdentityRegistration {
            peer_id,
            identity_commitment,
            registrar_node_id,
            registrar_signature,
            registered_at: now,
            updated_at: now,
        };

        self.db.save_identity_registration(&record)
    }

    /// Проверяет identity commitment пира против сохраненной записи.
    pub fn verify_peer_identity(
        &self,
        peer_id: String,
        expected_commitment: Vec<u8>,
    ) -> Result<bool, PlexError> {
        let Some(record) = self.db.load_identity_registration(&peer_id)? else {
            return Ok(false);
        };

        if record.identity_commitment != expected_commitment {
            return Ok(false);
        }

        let registrar_key: iroh_base::PublicKey =
            record
                .registrar_node_id
                .parse()
                .map_err(|e| PlexError::Crypto {
                    msg: format!("Invalid registrar public key: {e}"),
                })?;

        let signature =
            Signature::from_slice(&record.registrar_signature).map_err(|e| PlexError::Crypto {
                msg: format!("Invalid registrar signature: {e}"),
            })?;

        let signing_payload = storage::identity_registration_signing_payload(
            &record.peer_id,
            &record.identity_commitment,
            record.registered_at,
        );

        Ok(registrar_key.verify(&signing_payload, &signature).is_ok())
    }

    /// Сохраняет blockchain anchor для пира (tx в выбранной сети).
    pub fn record_verification_anchor(
        &self,
        peer_id: String,
        event_hash: String,
        chain: String,
        tx_id: String,
        confirmations: u64,
    ) -> Result<(), PlexError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        let window_start = now - VERIFICATION_ANCHOR_WINDOW_SECS;
        let anchors_in_window = self
            .db
            .verification_anchor_count_since(&peer_id, window_start)?;
        if anchors_in_window >= MAX_ANCHORS_PER_PEER_PER_WINDOW {
            return Err(PlexError::RateLimit {
                msg: format!(
                    "Verification anchor rate limit exceeded for peer {}: {} in {}s",
                    peer_id, anchors_in_window, VERIFICATION_ANCHOR_WINDOW_SECS,
                ),
            });
        }

        let anchor = storage::VerificationAnchor {
            peer_id,
            event_hash,
            chain,
            tx_id,
            confirmations: confirmations as i64,
            anchored_at: now,
        };

        self.db.save_verification_anchor(&anchor)
    }

    /// Возвращает агрегированный статус регистрации и anchor-верификации пира.
    pub fn peer_verification_status(
        &self,
        peer_id: String,
    ) -> Result<PeerVerificationStatus, PlexError> {
        let identity = self.db.load_identity_registration(&peer_id)?;
        let latest_anchor = self.db.latest_verification_anchor(&peer_id)?;
        let anchor_count = self.db.verification_anchor_count(&peer_id)?;

        Ok(PeerVerificationStatus {
            peer_id,
            has_identity_registration: identity.is_some(),
            registrar_node_id: identity.as_ref().map(|r| r.registrar_node_id.clone()),
            latest_anchor_chain: latest_anchor.as_ref().map(|a| a.chain.clone()),
            latest_anchor_tx_id: latest_anchor.as_ref().map(|a| a.tx_id.clone()),
            latest_anchor_event_hash: latest_anchor.as_ref().map(|a| a.event_hash.clone()),
            latest_anchor_confirmations: latest_anchor
                .as_ref()
                .map(|a| a.confirmations.max(0) as u64),
            anchor_count,
        })
    }

    /// Возвращает true, если пир считается верифицированным по правилам фазы 0.2.
    ///
    /// Критерии:
    /// 1) Есть identity registration.
    /// 2) Есть хотя бы один blockchain anchor.
    /// 3) Число подтверждений >= min_confirmations.
    /// 4) Если allowed_chains не пуст, chain anchor-а должна входить в allow-list.
    pub fn is_peer_verified(
        &self,
        peer_id: String,
        min_confirmations: u64,
        allowed_chains: Vec<String>,
    ) -> Result<bool, PlexError> {
        let status = self.peer_verification_status(peer_id)?;
        if !status.has_identity_registration {
            return Ok(false);
        }

        let Some(confirmations) = status.latest_anchor_confirmations else {
            return Ok(false);
        };

        if confirmations < min_confirmations {
            return Ok(false);
        }

        if allowed_chains.is_empty() {
            return Ok(true);
        }

        let Some(chain) = status.latest_anchor_chain else {
            return Ok(false);
        };

        Ok(allowed_chains.iter().any(|allowed| allowed == &chain))
    }

    /// Вычисляет trust-level пира по заданной policy.
    pub fn peer_trust_level(
        &self,
        peer_id: String,
        policy: VerificationPolicy,
    ) -> Result<PeerTrustLevel, PlexError> {
        let status = self.peer_verification_status(peer_id)?;
        let latest_anchor = self
            .db
            .latest_verification_anchor(status.peer_id.as_str())?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PlexError::Internal { msg: e.to_string() })?
            .as_secs() as i64;

        Ok(evaluate_trust_level(
            &status,
            latest_anchor.as_ref(),
            &policy,
            now,
        ))
    }
}

fn evaluate_trust_level(
    status: &PeerVerificationStatus,
    latest_anchor: Option<&storage::VerificationAnchor>,
    policy: &VerificationPolicy,
    now_unix_secs: i64,
) -> PeerTrustLevel {
    if !status.has_identity_registration {
        return PeerTrustLevel::Unverified;
    }

    let Some(confirmations) = status.latest_anchor_confirmations else {
        return PeerTrustLevel::Registered;
    };

    let Some(chain) = status.latest_anchor_chain.as_ref() else {
        return PeerTrustLevel::Registered;
    };

    let chain_allowed = policy.allowed_chains.is_empty()
        || policy.allowed_chains.iter().any(|allowed| allowed == chain);
    if !chain_allowed {
        return PeerTrustLevel::Anchored;
    }

    if confirmations < policy.min_confirmations {
        return PeerTrustLevel::Anchored;
    }

    if status.anchor_count < policy.min_anchor_count {
        return PeerTrustLevel::Anchored;
    }

    if policy.max_anchor_age_seconds > 0 {
        let Some(anchor) = latest_anchor else {
            return PeerTrustLevel::Anchored;
        };

        let age_secs = now_unix_secs.saturating_sub(anchor.anchored_at) as u64;
        if age_secs > policy.max_anchor_age_seconds {
            return PeerTrustLevel::Anchored;
        }
    }

    PeerTrustLevel::Trusted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_status() -> PeerVerificationStatus {
        PeerVerificationStatus {
            peer_id: "peer-test".to_string(),
            has_identity_registration: true,
            registrar_node_id: Some("registrar".to_string()),
            latest_anchor_chain: Some("eth-sepolia".to_string()),
            latest_anchor_tx_id: Some("tx".to_string()),
            latest_anchor_event_hash: Some("event".to_string()),
            latest_anchor_confirmations: Some(10),
            anchor_count: 3,
        }
    }

    fn mk_policy() -> VerificationPolicy {
        VerificationPolicy {
            min_confirmations: 5,
            min_anchor_count: 2,
            max_anchor_age_seconds: 3600,
            allowed_chains: vec!["eth-sepolia".to_string()],
        }
    }

    #[test]
    fn trust_level_unverified_without_identity() {
        let mut status = mk_status();
        status.has_identity_registration = false;

        let level = evaluate_trust_level(&status, None, &mk_policy(), 10_000);
        assert!(matches!(level, PeerTrustLevel::Unverified));
    }

    #[test]
    fn trust_level_anchored_when_chain_not_allowed() {
        let mut status = mk_status();
        status.latest_anchor_chain = Some("unknown-chain".to_string());

        let anchor = storage::VerificationAnchor {
            peer_id: status.peer_id.clone(),
            event_hash: "e".to_string(),
            chain: "unknown-chain".to_string(),
            tx_id: "t".to_string(),
            confirmations: 10,
            anchored_at: 9_500,
        };

        let level = evaluate_trust_level(&status, Some(&anchor), &mk_policy(), 10_000);
        assert!(matches!(level, PeerTrustLevel::Anchored));
    }

    #[test]
    fn trust_level_trusted_when_all_policy_constraints_pass() {
        let status = mk_status();
        let anchor = storage::VerificationAnchor {
            peer_id: status.peer_id.clone(),
            event_hash: "e".to_string(),
            chain: "eth-sepolia".to_string(),
            tx_id: "t".to_string(),
            confirmations: 10,
            anchored_at: 9_500,
        };

        let level = evaluate_trust_level(&status, Some(&anchor), &mk_policy(), 10_000);
        assert!(matches!(level, PeerTrustLevel::Trusted));
    }
}
