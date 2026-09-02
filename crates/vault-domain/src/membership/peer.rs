use std::fmt;

use crate::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let id = raw.into().trim().to_string();
        if id.is_empty() || id.len() > 128 {
            return Err(DomainError::InvalidNodeId);
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: NodeId,
    pub endpoint: PeerEndpoint,
}

/// Cryptographic identity of a vault peer in the mesh roster.
/// Contains only public keys (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub node_id: NodeId,
    /// Ed25519 verification key (classical signing, 32 bytes).
    pub ed25519_public: [u8; 32],
    /// ML-DSA-65 verification key (PQ signing, variable length).
    pub ml_dsa65_public: Vec<u8>,
    /// X25519 public key (classical KEM transport, 32 bytes).
    pub x25519_public: [u8; 32],
    /// ML-KEM-768 encapsulation key (PQ KEM transport, variable length).
    pub ml_kem768_public: Vec<u8>,
    /// Unix epoch seconds when this identity was created.
    pub created_at: u64,
}
