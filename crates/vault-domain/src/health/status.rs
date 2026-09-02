use crate::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Starting,
    Ready,
    Degraded,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
        }
    }
}

/// Honesty signal for peer liveness — directory presence ≠ probed reachability.
/// Does not claim Tor mesh health; Tor probing is a separate Gate item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// No peers configured.
    None,
    /// Peers listed in directory only; TCP/Tor not probed.
    DirectoryOnly,
    /// Clearnet TCP probe attempted (optional cheap signal).
    Probed { reachable: usize, configured: usize },
}

impl PeerReachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DirectoryOnly => "directory_only",
            Self::Probed { .. } => "probed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub node_id: NodeId,
    pub status: HealthStatus,
    pub node_tier: String,
    pub attestation_mode: String,
    pub tee_available: bool,
    pub peer_count: usize,
    /// Seated genesis / wire-DKG roster (SEV-priority); empty if unknown.
    pub genesis_roster: Vec<String>,
    /// Peer reachability honesty (not Tor-complete).
    pub peer_reachability: PeerReachability,
    /// When probed: how many peers accepted a cheap TCP connect (None if not probed).
    pub peers_reachable: Option<usize>,
    /// Constitution size is independent from currently discovered peers.
    pub configured_members: usize,
    pub required_threshold: usize,
    /// Local process/storage readiness. Does not imply membership or signing readiness.
    pub local_ready: bool,
    /// True only after enough peers are live; directory entries alone never grant readiness.
    pub financial_ready: bool,
}

impl NodeHealth {
    /// Public unauthenticated probe — status only (no node_id / roster / tier).
    pub fn to_public_json(&self) -> String {
        format!(
            r#"{{"status":"{}","local_ready":{},"financial_ready":{},"peer_count":{},"configured_members":{},"required_threshold":{},"peer_reachability":"{}"}}"#,
            self.status.as_str(),
            self.local_ready,
            self.financial_ready,
            self.peer_count,
            self.configured_members,
            self.required_threshold,
            self.peer_reachability.as_str()
        )
    }

    /// Authenticated detail (ops / ceremony checklist) — includes roster and tier.
    pub fn to_json(&self) -> String {
        let roster = self
            .genesis_roster
            .iter()
            .map(|id| serde_json::to_string(id).unwrap_or_else(|_| "\"\"".into()))
            .collect::<Vec<_>>()
            .join(",");
        let reachable = match self.peers_reachable {
            Some(n) => n.to_string(),
            None => "null".into(),
        };
        format!(
            r#"{{"node_id":{},"status":"{}","local_ready":{},"financial_ready":{},"node_tier":{},"attestation_mode":{},"tee_available":{},"peer_count":{},"configured_members":{},"required_threshold":{},"genesis_roster":[{}],"peer_reachability":"{}","peers_reachable":{}}}"#,
            serde_json::to_string(self.node_id.as_str()).unwrap_or_else(|_| "\"\"".into()),
            self.status.as_str(),
            self.local_ready,
            self.financial_ready,
            serde_json::to_string(&self.node_tier).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(&self.attestation_mode).unwrap_or_else(|_| "\"\"".into()),
            self.tee_available,
            self.peer_count,
            self.configured_members,
            self.required_threshold,
            roster,
            self.peer_reachability.as_str(),
            reachable
        )
    }
}
