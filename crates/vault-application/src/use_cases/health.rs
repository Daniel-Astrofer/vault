//! Health query workflow combining directory, online quorum, attestation, and tier signals.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::ports::{AttestationPort, PeerDirectoryPort};
use crate::OnlineStatusPort;
use vault_domain::{DomainError, HealthStatus, NodeHealth, NodeId, PeerReachability, VaultNodeTier};

/// Query use case that builds a node health snapshot without conflating directory presence and reachability.
pub struct GetHealth {
    /// Identity reported in the authenticated node detail response.
    node_id: NodeId,
    /// Directory source for configured peers.
    peers: Arc<dyn PeerDirectoryPort>,
    /// Source of the adapter's configured attestation mode.
    attestation: Arc<dyn AttestationPort>,
    /// Configured trust tier displayed in the health response.
    node_tier: VaultNodeTier,
    /// Whether the host reports a TEE capability.
    tee_available: bool,
    /// Genesis/wire-DKG roster displayed only in detailed health output.
    genesis_roster: Vec<String>,
    /// When true, attempt cheap clearnet TCP connects (not Tor-complete).
    probe_peers: bool,
    /// Membership size configured by the constitution, independent of discovered peers.
    configured_members: usize,
    /// Minimum online participant count required for financial readiness.
    required_threshold: usize,
    /// Optional authoritative online counter, including local node when present.
    online: Option<Arc<dyn OnlineStatusPort>>,
    /// Whether local signing/storage material has completed its readiness checks.
    financial_material_ready: bool,
}

impl GetHealth {
    /// Create a health query with an empty explicit genesis roster.
    pub fn new(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        node_tier: VaultNodeTier,
        tee_available: bool,
    ) -> Self {
        Self::with_roster(node_id, peers, attestation, node_tier, tee_available, vec![])
    }

    /// Create a query with a supplied genesis roster while retaining lab-sized defaults.
    pub fn with_roster(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        node_tier: VaultNodeTier,
        tee_available: bool,
        genesis_roster: Vec<String>,
    ) -> Self {
        Self {
            node_id,
            peers,
            attestation,
            node_tier,
            tee_available,
            genesis_roster,
            probe_peers: false,
            configured_members: 1,
            required_threshold: 1,
            online: None,
            financial_material_ready: true,
        }
    }

    /// Enable a cheap clearnet TCP probe when no authoritative online counter is configured.
    ///
    /// Onion addresses are treated as unprobed/unreachable; this option never
    /// claims to establish Tor mesh reachability.
    pub fn with_peer_probe(mut self, enabled: bool) -> Self {
        self.probe_peers = enabled;
        self
    }

    /// Configure constitution membership and signing threshold, clamped to valid positive bounds.
    pub fn with_constitution(mut self, configured_members: usize, required_threshold: usize) -> Self {
        self.configured_members = configured_members.max(1);
        self.required_threshold = required_threshold.clamp(1, self.configured_members);
        self
    }

    /// Supply a mesh-backed online counter for financial readiness and peer counts.
    pub fn with_online_status(mut self, online: Arc<dyn OnlineStatusPort>) -> Self {
        self.online = Some(online);
        self
    }

    /// Set whether local key and storage material is ready for financial operations.
    pub fn with_financial_material_ready(mut self, ready: bool) -> Self {
        self.financial_material_ready = ready;
        self
    }

    /// Assemble the current health view from directory peers and configured readiness signals.
    ///
    /// Empty peer directories report `Starting`. Directory-only mode reports
    /// reachability as unknown and may still report `Ready`; `financial_ready`
    /// separately requires local material and the configured online threshold.
    pub fn execute(&self) -> Result<NodeHealth, DomainError> {
        let peers = self.peers.list_peers()?;
        let online_count = self.online.as_ref().map(|online| online.online_count());
        let (peer_reachability, peers_reachable, status) = if peers.is_empty() {
            (PeerReachability::None, None, HealthStatus::Starting)
        } else if self.probe_peers {
            let reachable = online_count
                .map(|count| count.saturating_sub(1).min(peers.len()))
                .unwrap_or_else(|| peers.iter().filter(|p| cheap_tcp_reachable(&p.endpoint.address)).count());
            let configured = peers.len();
            let reach = PeerReachability::Probed { reachable, configured };
            let status = if reachable == 0 { HealthStatus::Degraded } else { HealthStatus::Ready };
            (reach, Some(reachable), status)
        } else {
            (PeerReachability::DirectoryOnly, None, HealthStatus::Ready)
        };
        let financial_ready =
            self.financial_material_ready && online_count.is_some_and(|count| count >= self.required_threshold);
        Ok(NodeHealth {
            node_id: self.node_id.clone(),
            status,
            node_tier: self.node_tier.as_str().to_string(),
            attestation_mode: self.attestation.mode().as_str().to_string(),
            tee_available: self.tee_available,
            peer_count: peers.len(),
            genesis_roster: self.genesis_roster.clone(),
            peer_reachability,
            peers_reachable,
            configured_members: self.configured_members,
            required_threshold: self.required_threshold,
            local_ready: true,
            financial_ready,
        })
    }
}

/// Best-effort clearnet TCP dial. Onion / non-socket addresses return false
/// without claiming Tor reachability.
fn cheap_tcp_reachable(addr: &str) -> bool {
    let trimmed = addr.trim();
    if trimmed.is_empty() || trimmed.contains(".onion") {
        return false;
    }
    let candidate = if trimmed.contains(':') { trimmed.to_string() } else { format!("{trimmed}:7701") };
    let Ok(mut iter) = candidate.to_socket_addrs() else {
        return false;
    };
    let Some(sa) = iter.next() else {
        return false;
    };
    TcpStream::connect_timeout(&sa, Duration::from_millis(80)).is_ok()
}
