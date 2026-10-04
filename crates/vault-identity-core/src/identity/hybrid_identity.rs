//! Hybrid identity combining Ed25519 (classical) + ML-DSA-65 (PQ) signing.
//!
//! Hybrid signatures apply both schemes and require both to verify (AND logic).
//! This ensures security even if one scheme is broken.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ed25519_identity::Ed25519Identity;
use crate::error::IdentityError;
use crate::ml_dsa_identity::MlDsa65Identity;
use crate::VaultIdentity;

/// A combined Ed25519 + ML-DSA-65 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 signature bytes over the original message.
    pub ed25519: Vec<u8>,
    /// ML-DSA-65 signature bytes over the same original message.
    pub ml_dsa65: Vec<u8>,
}

impl AsRef<[u8]> for HybridSignature {
    fn as_ref(&self) -> &[u8] {
        // For the trait bound — not typically used directly.
        self.ed25519.as_slice()
    }
}

/// Combined Ed25519 + ML-DSA-65 keypair for hybrid cryptographic identity.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    /// Classical Ed25519 keypair, used as one half of the mandatory signature.
    pub ed25519: Ed25519Identity,
    /// Post-quantum ML-DSA-65 keypair, used as the other mandatory half.
    pub ml_dsa65: MlDsa65Identity,
    /// Human-readable node identifier.
    pub node_id: String,
    /// Unix epoch seconds when this keypair was created.
    pub created_at: u64,
    /// Unix epoch seconds when this keypair expires (0 = never).
    pub expires_at: u64,
}

impl HybridKeyPair {
    /// Generate a fresh hybrid keypair.
    pub fn generate(node_id: impl Into<String>) -> Result<Self, IdentityError> {
        let ed25519 = Ed25519Identity::generate()?;
        let ml_dsa65 = MlDsa65Identity::generate()?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Ok(Self { ed25519, ml_dsa65, node_id: node_id.into(), created_at: now, expires_at: 0 })
    }

    /// Sign a message with both keys, producing a hybrid signature.
    pub fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignature, IdentityError> {
        let ed_sig = self.ed25519.sign(message)?;
        let ml_sig = self.ml_dsa65.sign(message)?;
        Ok(HybridSignature { ed25519: ed_sig, ml_dsa65: ml_sig })
    }

    /// Verify a hybrid signature (both components must verify).
    pub fn verify_hybrid(
        ed25519_pub: &<Ed25519Identity as VaultIdentity>::PublicKey,
        ml_dsa65_pub: &<MlDsa65Identity as VaultIdentity>::PublicKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, IdentityError> {
        let ed_ok = Ed25519Identity::verify(ed25519_pub, message, &signature.ed25519)?;
        if !ed_ok {
            return Ok(false);
        }
        MlDsa65Identity::verify(ml_dsa65_pub, message, &signature.ml_dsa65)
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ed_bytes = self.ed25519.to_bytes();
        let ml_bytes = self.ml_dsa65.to_bytes();
        let node_bytes = self.node_id.as_bytes();
        let mut buf = Vec::with_capacity(ed_bytes.len() + ml_bytes.len() + node_bytes.len() + 24);
        // Format: [ed25519_secret||ed25519_pub||ml_dsa65_secret||ml_dsa65_pub||node_id_len:4||node_id||created_at:8||expires_at:8]
        buf.extend_from_slice(&ed_bytes);
        buf.extend_from_slice(&ml_bytes);
        buf.extend_from_slice(&(node_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(node_bytes);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let ed_len = 64; // 32 secret + 32 public
        let ml_len = 4032 + 1952; // ML-DSA-65 secret + public
        let min_len = ed_len + ml_len + 4;
        if bytes.len() < min_len {
            return Err(IdentityError::DeserializationFailed("hybrid key material too short".into()));
        }

        let ed25519 = Ed25519Identity::from_bytes(&bytes[..ed_len])?;
        let ml_dsa65 = MlDsa65Identity::from_bytes(&bytes[ed_len..ed_len + ml_len])?;

        let offset = ed_len + ml_len;
        let name_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| IdentityError::DeserializationFailed("invalid node_id length".into()))?,
        ) as usize;
        let offset = offset + 4;
        if offset + name_len + 16 > bytes.len() {
            return Err(IdentityError::DeserializationFailed("hybrid key material truncated".into()));
        }
        let node_id = String::from_utf8(bytes[offset..offset + name_len].to_vec())
            .map_err(|e| IdentityError::DeserializationFailed(format!("invalid node_id utf8: {e}")))?;
        let offset = offset + name_len;
        let created_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| IdentityError::DeserializationFailed("invalid created_at".into()))?,
        );
        let expires_at = u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| IdentityError::DeserializationFailed("invalid expires_at".into()))?,
        );

        Ok(Self { ed25519, ml_dsa65, node_id, created_at, expires_at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hybrid_keypair() {
        let kp = HybridKeyPair::generate("vault-test-1").unwrap();
        assert_eq!(kp.node_id, "vault-test-1");
        assert!(kp.created_at > 0);
        assert_eq!(kp.expires_at, 0);
    }

    #[test]
    fn hybrid_sign_and_verify() {
        let kp = HybridKeyPair::generate("vault-1").unwrap();
        let msg = b"hybrid signing test message";
        let sig = kp.sign_hybrid(msg).unwrap();
        let ed_pk = kp.ed25519.verifying_key_bytes();
        assert!(HybridKeyPair::verify_hybrid(&ed_pk, kp.ml_dsa65.public_key(), msg, &sig).unwrap());
    }

    #[test]
    fn hybrid_verify_rejects_bad_message() {
        let kp = HybridKeyPair::generate("vault-2").unwrap();
        let sig = kp.sign_hybrid(b"real message").unwrap();
        let ed_pk = kp.ed25519.verifying_key_bytes();
        assert!(!HybridKeyPair::verify_hybrid(&ed_pk, kp.ml_dsa65.public_key(), b"fake message", &sig).unwrap());
    }

    #[test]
    fn hybrid_to_from_bytes_roundtrip() {
        let kp = HybridKeyPair::generate("vault-roundtrip-42").unwrap();
        let bytes = kp.to_bytes();
        let restored = HybridKeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(restored.node_id, kp.node_id);
        assert_eq!(restored.created_at, kp.created_at);
        assert_eq!(restored.expires_at, kp.expires_at);
        // Verify the restored keypair can sign and verify
        let sig = restored.sign_hybrid(b"roundtrip test").unwrap();
        let ed_pk = restored.ed25519.verifying_key_bytes();
        assert!(HybridKeyPair::verify_hybrid(&ed_pk, restored.ml_dsa65.public_key(), b"roundtrip test", &sig).unwrap());
    }

    #[test]
    fn hybrid_from_bytes_short_input_fails() {
        assert!(HybridKeyPair::from_bytes(&[0u8; 10]).is_err());
    }
}
