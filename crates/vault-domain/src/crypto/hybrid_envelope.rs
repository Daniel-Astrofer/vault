//! Hybrid envelope domain types: X25519 + ML-KEM-768 combiner via HKDF.
//!
//! Pure domain types — no crypto I/O here.

use crate::{DayEpoch, DomainError, NodeId};

/// Context bound to every hybrid envelope for anti-replay and domain separation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridContext {
    pub domain_separator: String,
    pub transcript_hash: [u8; 48],
    pub suite_id: String,
    pub sender_id: NodeId,
    pub receiver_id: NodeId,
    pub epoch: DayEpoch,
}

/// Material derived from the two shared secrets before key derivation.
/// Zeroized on drop.
#[derive(Clone)]
pub struct HybridKeyMaterial {
    pub ss_classical: [u8; 32],
    pub ss_pq: [u8; 32],
    pub kdf_salt: [u8; 32],
    pub confirmation_tag: [u8; 32],
}

impl Drop for HybridKeyMaterial {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.ss_classical);
        zeroize::Zeroize::zeroize(&mut self.ss_pq);
        zeroize::Zeroize::zeroize(&mut self.kdf_salt);
        zeroize::Zeroize::zeroize(&mut self.confirmation_tag);
    }
}

/// Wire-format hybrid envelope.
///
/// Contains dual KEM (X25519 + ML-KEM-768), dual signature (Ed25519 + ML-DSA-65),
/// and AES-256-GCM ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HybridEnvelope {
    pub format_version: u16,
    pub suite_id: String,
    pub key_epoch: DayEpoch,
    pub sender_id: NodeId,
    pub receiver_id: NodeId,
    pub sender_eph_pk: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub classical_signature: Vec<u8>,
    pub pq_signature: Vec<u8>,
}

impl HybridEnvelope {
    pub const CURRENT_FORMAT_VERSION: u16 = 1;
    pub const SUITE_ID: &'static str = "hybrid-x25519-mlkem768-aes256gcm";
    pub const DOMAIN_SEPARATOR: &'static str = "KEROSENE-VAULT-MESH-HYBRID-V1";

    pub fn validate_header(&self) -> Result<(), DomainError> {
        if self.format_version != Self::CURRENT_FORMAT_VERSION {
            return Err(DomainError::InvalidIntent(format!(
                "unknown envelope format_version: {}",
                self.format_version
            )));
        }
        if self.suite_id != Self::SUITE_ID {
            return Err(DomainError::InvalidIntent(format!("unknown suite_id: {}", self.suite_id)));
        }
        if self.sender_eph_pk == [0u8; 32] {
            return Err(DomainError::InvalidIntent("sender_eph_pk is all-zero".into()));
        }
        if self.kem_ciphertext.is_empty() {
            return Err(DomainError::InvalidIntent("kem_ciphertext is empty".into()));
        }
        if self.ciphertext.is_empty() {
            return Err(DomainError::InvalidIntent("ciphertext is empty".into()));
        }
        if self.classical_signature.is_empty() {
            return Err(DomainError::InvalidIntent("classical_signature missing".into()));
        }
        if self.pq_signature.is_empty() {
            return Err(DomainError::InvalidIntent("pq_signature missing".into()));
        }
        Ok(())
    }
}
