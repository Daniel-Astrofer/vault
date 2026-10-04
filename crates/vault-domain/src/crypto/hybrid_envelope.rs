//! Hybrid envelope domain types: X25519 + ML-KEM-768 combiner via HKDF.
//!
//! Pure domain types — no crypto I/O here.

use crate::{DayEpoch, DomainError, NodeId};

/// Context bound to every hybrid envelope for anti-replay and domain separation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridContext {
    /// Protocol-specific label included in derivation to separate key purposes.
    pub domain_separator: String,
    /// SHA-384 digest of the authenticated handshake transcript.
    pub transcript_hash: [u8; 48],
    /// Negotiated cryptographic suite identifier bound to this context.
    pub suite_id: String,
    /// Identity asserting ownership of the sending ephemeral key.
    pub sender_id: NodeId,
    /// Intended peer identity; binding it prevents cross-recipient key confusion.
    pub receiver_id: NodeId,
    /// Daily key epoch used to reject stale or replayed envelopes.
    pub epoch: DayEpoch,
}

/// Material derived from the two shared secrets before key derivation.
/// Zeroized on drop.
#[derive(Clone)]
pub struct HybridKeyMaterial {
    /// Shared secret produced by the classical X25519 key agreement.
    pub ss_classical: [u8; 32],
    /// Shared secret produced by the post-quantum ML-KEM-768 decapsulation.
    pub ss_pq: [u8; 32],
    /// Per-envelope salt supplied to the key derivation function.
    pub kdf_salt: [u8; 32],
    /// Key confirmation value used to detect peer derivation mismatch.
    pub confirmation_tag: [u8; 32],
}

impl Drop for HybridKeyMaterial {
    /// Erase both shared secrets and their associated derivation material on drop.
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
    /// Version of the serialized envelope schema.
    pub format_version: u16,
    /// Identifier of the cryptographic suite used for this envelope.
    pub suite_id: String,
    /// Key epoch under which the envelope was created.
    pub key_epoch: DayEpoch,
    /// Authenticated sender identity.
    pub sender_id: NodeId,
    /// Intended authenticated recipient identity.
    pub receiver_id: NodeId,
    /// Sender's ephemeral X25519 public key used for classical encapsulation.
    pub sender_eph_pk: [u8; 32],
    /// ML-KEM-768 encapsulation ciphertext consumed by the recipient's decapsulation key.
    pub kem_ciphertext: Vec<u8>,
    /// 96-bit AES-GCM nonce; uniqueness requirements apply per derived key.
    pub nonce: [u8; 12],
    /// AES-256-GCM encrypted payload, including its authentication tag as encoded by the adapter.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature bytes authenticating the canonical envelope transcript.
    pub classical_signature: Vec<u8>,
    /// ML-DSA-65 signature bytes authenticating the same canonical envelope transcript.
    pub pq_signature: Vec<u8>,
}

impl HybridEnvelope {
    /// Current supported envelope serialization schema version.
    pub const CURRENT_FORMAT_VERSION: u16 = 1;
    /// Canonical suite name for X25519, ML-KEM-768, HKDF, and AES-256-GCM.
    pub const SUITE_ID: &'static str = "hybrid-x25519-mlkem768-aes256gcm";
    /// Protocol domain-separation label for Vault Mesh hybrid envelopes.
    pub const DOMAIN_SEPARATOR: &'static str = "KEROSENE-VAULT-MESH-HYBRID-V1";

    /// Validate supported header metadata and require all cryptographic payload fields.
    ///
    /// This structural gate rejects unknown versions/suites and empty or
    /// all-zero required fields. It does not verify signatures, decrypt the
    /// ciphertext, validate peer identities, or check the nonce against prior use.
    /// Those checks must be performed by the cryptographic adapter and protocol state.
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
