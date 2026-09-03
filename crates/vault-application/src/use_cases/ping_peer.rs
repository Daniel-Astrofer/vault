use std::sync::Arc;

use crate::ports::{AttestationPort, ClockPort, PeerDirectoryPort};
use vault_domain::{DomainError, Measurement, NodeId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingReport {
    pub peer_id: NodeId,
    pub ok: bool,
    pub verified_attestation: bool,
    pub at_unix_secs: u64,
}

pub struct PingPeer {
    peers: Arc<dyn PeerDirectoryPort>,
    attestation: Arc<dyn AttestationPort>,
    clock: Arc<dyn ClockPort>,
    local_measurement: Measurement,
}

impl PingPeer {
    pub fn new(
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        clock: Arc<dyn ClockPort>,
        local_measurement: Measurement,
    ) -> Self {
        Self { peers, attestation, clock, local_measurement }
    }

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
