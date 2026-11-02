use crate::NodeId;

/// Coarse lifecycle/readiness classification exposed by a node health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Process is initializing and has not completed its local readiness checks.
    Starting,
    /// The node's configured health checks report the requested readiness level.
    Ready,
    /// The node is running but one or more health checks are not satisfied.
    Degraded,
}

impl HealthStatus {
    /// Return the stable lowercase health label used in JSON responses.
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
    Probed {
        /// Number of configured peers that accepted the probe.
        reachable: usize,
        /// Total number of peers included in the probe set.
        configured: usize,
    },
}

impl PeerReachability {
    /// Return the stable lowercase reachability label, omitting probe counts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DirectoryOnly => "directory_only",
            Self::Probed { .. } => "probed",
        }
    }
}

/// Snapshot of local node, membership, attestation, and peer readiness signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    /// Identifier of the node reporting this health snapshot.
    pub node_id: NodeId,
    /// Coarse lifecycle status derived by the health service.
    pub status: HealthStatus,
    /// Configured membership tier label for this node.
    pub node_tier: String,
    /// Attestation mechanism currently selected by this node.
    pub attestation_mode: String,
    /// Whether the local environment exposes the required TEE capability.
    pub tee_available: bool,
    /// Number of peers known to discovery; this does not prove they are reachable.
    pub peer_count: usize,
    /// Seated genesis / wire-DKG roster (SEV-priority); empty if unknown.
    pub genesis_roster: Vec<String>,
    /// Peer reachability honesty (not Tor-complete).
    pub peer_reachability: PeerReachability,
    /// When probed: how many peers accepted a cheap TCP connect (None if not probed).
    pub peers_reachable: Option<usize>,
    /// Constitution size is independent from currently discovered peers.
    pub configured_members: usize,
    /// Minimum signing participant count required by the configured constitution.
    pub required_threshold: usize,
    /// Local process/storage readiness. Does not imply membership or signing readiness.
    pub local_ready: bool,
    /// True only after enough peers are live; directory entries alone never grant readiness.
    pub financial_ready: bool,
}

impl NodeHealth {
    /// Render the unauthenticated health response without node identity or roster details.
    ///
    /// The public view contains status and readiness/count signals only, limiting
    /// disclosure of membership and attestation configuration.
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

    /// Render the authenticated operational health view, including identity and roster.
    ///
    /// Optional probe counts are emitted as JSON `null` when no reachability probe
    /// was attempted. String values are serialized with `serde_json` escaping.
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
