use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::ports::{AttestationPort, PeerDirectoryPort};
use crate::OnlineStatusPort;
use vault_domain::{DomainError, HealthStatus, NodeHealth, NodeId, PeerReachability, VaultNodeTier};

pub struct GetHealth {
    node_id: NodeId,
    peers: Arc<dyn PeerDirectoryPort>,
    attestation: Arc<dyn AttestationPort>,
    node_tier: VaultNodeTier,
    tee_available: bool,
    genesis_roster: Vec<String>,
    /// When true, attempt cheap clearnet TCP connects (not Tor-complete).
    probe_peers: bool,
    configured_members: usize,
    required_threshold: usize,
    online: Option<Arc<dyn OnlineStatusPort>>,
}

impl GetHealth {
    pub fn new(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        node_tier: VaultNodeTier,
        tee_available: bool,
    ) -> Self {
        Self::with_roster(node_id, peers, attestation, node_tier, tee_available, vec![])
    }

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
        }
    }

    pub fn with_peer_probe(mut self, enabled: bool) -> Self {
        self.probe_peers = enabled;
        self
    }

    pub fn with_constitution(mut self, configured_members: usize, required_threshold: usize) -> Self {
        self.configured_members = configured_members.max(1);
        self.required_threshold = required_threshold.clamp(1, self.configured_members);
        self
    }

    pub fn with_online_status(mut self, online: Arc<dyn OnlineStatusPort>) -> Self {
        self.online = Some(online);
        self
    }

    pub fn execute(&self) -> Result<NodeHealth, DomainError> {
        let peers = self.peers.list_peers()?;
        let (peer_reachability, peers_reachable, status) = if peers.is_empty() {
            (PeerReachability::None, None, HealthStatus::Starting)
        } else if self.probe_peers {
            let reachable = peers.iter().filter(|p| cheap_tcp_reachable(&p.endpoint.address)).count();
            let configured = peers.len();
            let reach = PeerReachability::Probed { reachable, configured };
            let status = if reachable == 0 { HealthStatus::Degraded } else { HealthStatus::Ready };
            (reach, Some(reachable), status)
        } else {
            (PeerReachability::DirectoryOnly, None, HealthStatus::Ready)
        };
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
            financial_ready: self
                .online
                .as_ref()
                .is_some_and(|online| online.online_count() >= self.required_threshold),
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
    TcpStream::connect_timeout(&SocketAddr::from(sa), Duration::from_millis(80)).is_ok()
}
