use std::sync::Arc;

use crate::ports::{AttestationPort, ClockPort, PeerDirectoryPort};
use vault_domain::{DomainError, Measurement, NodeId};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of a peer-presence check and local attestation verification.
pub struct PingReport {
    /// Node ID requested by the caller.
    pub peer_id: NodeId,
    /// True when the peer-directory port confirmed that the node is known/reachable.
    pub ok: bool,
    /// True when issuing and verifying the local measurement quote both succeeded.
    pub verified_attestation: bool,
    /// Local clock timestamp captured after the peer and quote checks succeeded.
    pub at_unix_secs: u64,
}

/// Use case that checks peer presence and verifies this node's attestation quote.
pub struct PingPeer {
    peers: Arc<dyn PeerDirectoryPort>,
    attestation: Arc<dyn AttestationPort>,
    clock: Arc<dyn ClockPort>,
    local_measurement: Measurement,
}

impl PingPeer {
    /// Creates the use case with peer, attestation, clock, and local measurement dependencies.
    pub fn new(
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        clock: Arc<dyn ClockPort>,
        local_measurement: Measurement,
    ) -> Self {
        Self { peers, attestation, clock, local_measurement }
    }

    /// Confirms the peer through the directory port and verifies a quote for the local measurement.
    ///
    /// The report's `verified_attestation` describes the local quote; it does not
    /// prove that the remote peer supplied or verified an attestation quote.
    pub fn execute(&self, peer_id: &NodeId) -> Result<PingReport, DomainError> {
        self.peers.ping(peer_id)?;
        let quote = self.attestation.issue_quote(&self.local_measurement)?;
        self.attestation.verify_quote(&quote)?;
        Ok(PingReport {
            peer_id: peer_id.clone(),
            ok: true,
            verified_attestation: true,
            at_unix_secs: self.clock.unix_now_secs(),
        })
    }
}
