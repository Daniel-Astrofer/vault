use std::fmt;

use crate::DomainError;

/// Stable mesh identifier for a vault node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Create an identifier by trimming surrounding whitespace and enforcing a nonempty
    /// value of at most 128 UTF-8 bytes.
    ///
    /// This constructor does not impose a character allowlist beyond those bounds.
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let id = raw.into().trim().to_string();
        if id.is_empty() || id.len() > 128 {
            return Err(DomainError::InvalidNodeId);
        }
        Ok(Self(id))
    }

    /// Borrow the canonical trimmed identifier value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    /// Write the identifier without adding formatting or escaping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Network address associated with a peer in the directory or mesh roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    /// Endpoint string; parsing and transport reachability are handled by adapters.
    pub address: String,
}

/// Directory-level mapping from a stable peer id to its advertised endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Stable identity used to correlate this peer across membership records.
    pub id: NodeId,
    /// Advertised network endpoint for the peer.
    pub endpoint: PeerEndpoint,
}

/// Cryptographic identity of a vault peer in the mesh roster.
/// Contains only public keys (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Stable identity associated with these verification and encapsulation keys.
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
