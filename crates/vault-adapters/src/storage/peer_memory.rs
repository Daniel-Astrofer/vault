use std::collections::HashMap;
use std::sync::Mutex;

use crate::application::PeerDirectoryPort;
use crate::domain::{DomainError, NodeId, PeerInfo};

pub struct InMemoryPeerDirectory {
    peers: Mutex<HashMap<String, PeerInfo>>,
}

impl InMemoryPeerDirectory {
    pub fn new() -> Self {
        Self { peers: Mutex::new(HashMap::new()) }
    }

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
    fn list_peers(&self) -> Result<Vec<PeerInfo>, DomainError> {
        let guard = self.peers.lock().expect("peer directory lock");
        Ok(guard.values().cloned().collect())
    }

    fn upsert_peer(&self, peer: PeerInfo) -> Result<(), DomainError> {
        self.upsert_sync(peer)
    }

    fn ping(&self, peer_id: &NodeId) -> Result<(), DomainError> {
        let guard = self.peers.lock().expect("peer directory lock");
        if guard.contains_key(peer_id.as_str()) {
            Ok(())
        } else {
            Err(DomainError::PeerNotFound(peer_id.as_str().to_string()))
        }
    }
}
