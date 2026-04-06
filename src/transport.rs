#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransportKind {
    IrohQuic,
    LocalMesh,
    EphemeralBridge,
    DeadDrop,
}

impl TransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::IrohQuic => "iroh-quic",
            TransportKind::LocalMesh => "local-mesh",
            TransportKind::EphemeralBridge => "ephemeral-bridge",
            TransportKind::DeadDrop => "dead-drop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransportCapabilities {
    pub lan_discovery: bool,
    pub internet_required: bool,
    pub store_and_forward: bool,
    pub dpi_masquerade_ready: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransportRoute {
    pub kind: TransportKind,
    pub peer_id: String,
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<String>,
    pub is_available: bool,
    pub core_connect_supported: bool,
    pub priority: u8,
    pub capabilities: TransportCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportSelectionPolicy {
    pub prefer_lan: bool,
    pub prefer_direct: bool,
    pub allow_internet: bool,
}

impl TransportSelectionPolicy {
    pub fn interactive_sync() -> Self {
        Self {
            prefer_lan: true,
            prefer_direct: true,
            allow_internet: true,
        }
    }
}

pub fn capabilities_for(kind: TransportKind) -> TransportCapabilities {
    match kind {
        TransportKind::IrohQuic => TransportCapabilities {
            lan_discovery: true,
            internet_required: false,
            store_and_forward: false,
            dpi_masquerade_ready: false,
        },
        TransportKind::LocalMesh => TransportCapabilities {
            lan_discovery: true,
            internet_required: false,
            store_and_forward: true,
            // Не реализован на уровне ядра — не анонсировать как DPI-безопасный.
            dpi_masquerade_ready: false,
        },
        TransportKind::EphemeralBridge => TransportCapabilities {
            lan_discovery: false,
            internet_required: true,
            store_and_forward: true,
            // Не реализован — зарезервировано.
            dpi_masquerade_ready: false,
        },
        TransportKind::DeadDrop => TransportCapabilities {
            lan_discovery: false,
            internet_required: true,
            store_and_forward: true,
            dpi_masquerade_ready: true,
        },
    }
}

pub fn choose_best_route(
    candidates: &[TransportRoute],
    policy: TransportSelectionPolicy,
) -> Option<TransportRoute> {
    candidates
        .iter()
        .filter(|route| route.is_available)
        .filter(|route| policy.allow_internet || !route.capabilities.internet_required)
        .max_by_key(|route| route_score(route, policy))
        .cloned()
}

fn route_score(route: &TransportRoute, policy: TransportSelectionPolicy) -> i64 {
    let mut score = i64::from(route.priority) * 100;

    if route.is_available {
        score += 10_000;
    }

    if route.core_connect_supported {
        score += 5_000;
    }

    if policy.prefer_lan && route.capabilities.lan_discovery {
        score += 1_000;
    }

    if policy.prefer_direct && !route.direct_addresses.is_empty() {
        score += 500;
    }

    if route.capabilities.store_and_forward {
        score += 100;
    }

    if route.capabilities.dpi_masquerade_ready {
        score += 50;
    }

    if route.capabilities.internet_required {
        score -= 25;
    }

    score += route.direct_addresses.len() as i64;
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(
        kind: TransportKind,
        is_available: bool,
        priority: u8,
        direct_addresses: Vec<&str>,
    ) -> TransportRoute {
        TransportRoute {
            kind,
            peer_id: "peer".into(),
            relay_url: None,
            direct_addresses: direct_addresses.into_iter().map(str::to_string).collect(),
            is_available,
            core_connect_supported: kind == TransportKind::IrohQuic,
            priority,
            capabilities: capabilities_for(kind),
        }
    }

    #[test]
    fn chooses_available_route_over_unavailable() {
        let selected = choose_best_route(
            &[
                route(TransportKind::DeadDrop, false, 10, vec![]),
                route(TransportKind::IrohQuic, true, 5, vec!["127.0.0.1:7777"]),
            ],
            TransportSelectionPolicy::interactive_sync(),
        )
        .expect("route");

        assert_eq!(selected.kind, TransportKind::IrohQuic);
    }

    #[test]
    fn prefers_lan_direct_route_for_interactive_sync() {
        let selected = choose_best_route(
            &[
                route(TransportKind::EphemeralBridge, true, 9, vec![]),
                route(TransportKind::IrohQuic, true, 5, vec!["10.0.0.2:7777"]),
            ],
            TransportSelectionPolicy::interactive_sync(),
        )
        .expect("route");

        assert_eq!(selected.kind, TransportKind::IrohQuic);
    }

    #[test]
    fn filters_out_internet_routes_when_policy_forbids_them() {
        let selected = choose_best_route(
            &[
                route(TransportKind::EphemeralBridge, true, 9, vec![]),
                route(TransportKind::LocalMesh, true, 1, vec!["ble://peer"]),
            ],
            TransportSelectionPolicy {
                prefer_lan: true,
                prefer_direct: true,
                allow_internet: false,
            },
        )
        .expect("route");

        assert_eq!(selected.kind, TransportKind::LocalMesh);
    }
}
