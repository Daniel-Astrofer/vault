use std::collections::HashMap;
use std::sync::Mutex;

use crate::application::PeerDirectoryPort;
use crate::domain::{DomainError, NodeId, PeerInfo};

/// Mutex-protected peer directory for local and test use.
pub struct InMemoryPeerDirectory {
    peers: Mutex<HashMap<String, PeerInfo>>,
}

impl InMemoryPeerDirectory {
    /// Creates an empty in-memory peer directory.
    pub fn new() -> Self {
        Self { peers: Mutex::new(HashMap::new()) }
    }

    /// Inserts or replaces a peer using its node ID as the map key.
    pub fn upsert_sync(&self, peer: PeerInfo) -> Result<(), DomainError> {
        let mut guard = self.peers.lock().expect("peer directory lock");
        guard.insert(peer.id.as_str().to_string(), peer);
        Ok(())
    }
}

impl Default for InMemoryPeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerDirectoryPort for InMemoryPeerDirectory {
    /// Returns a snapshot of all known peers in unspecified map order.
    fn list_peers(&self) -> Result<Vec<PeerInfo>, DomainError> {
        let guard = self.peers.lock().expect("peer directory lock");
        Ok(guard.values().cloned().collect())
    }

    /// Delegates peer insertion to [`Self::upsert_sync`].
    fn upsert_peer(&self, peer: PeerInfo) -> Result<(), DomainError> {
        self.upsert_sync(peer)
    }

    /// Confirms that the peer ID exists; this in-memory adapter does not perform network I/O.
    fn ping(&self, peer_id: &NodeId) -> Result<(), DomainError> {
        let guard = self.peers.lock().expect("peer directory lock");
        if guard.contains_key(peer_id.as_str()) {
            Ok(())
        } else {
            Err(DomainError::PeerNotFound(peer_id.as_str().to_string()))
        }
    }
}
