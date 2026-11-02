//! Ed25519 identity implementation using ed25519-dalek.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::IdentityError;
use crate::VaultIdentity;

/// Ed25519 identity keypair (classical signing).
///
/// Stores raw key bytes to support trait-based access via reference.
/// The underlying dalek types are reconstructed on-demand.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Identity {
    /// Raw 32-byte secret key (seed).
    secret_bytes: [u8; 32],
    /// Raw 32-byte public key (verifying key).
    public_bytes: [u8; 32],
}

impl Ed25519Identity {
    /// Create a new Ed25519 identity from raw bytes.
    pub fn from_raw(secret: &[u8; 32], public: &[u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = VerifyingKey::from_bytes(public)
            .map_err(|e| IdentityError::InvalidKeyMaterial(format!("invalid ed25519 public key: {e}")))?;
        if signing_key.verifying_key() != verifying_key {
            return Err(IdentityError::InvalidKeyMaterial("ed25519 secret/public key mismatch".into()));
        }
        Ok(Self { secret_bytes: *secret, public_bytes: *public })
    }

    /// Get the raw verifying key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.public_bytes
    }

    /// Get the signing key bytes (secret).
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.secret_bytes
    }
}

impl VaultIdentity for Ed25519Identity {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Signature = Vec<u8>;

    fn generate() -> Result<Self, IdentityError> {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { secret_bytes: signing_key.to_bytes(), public_bytes: verifying_key.to_bytes() })
    }

    fn from_secret(secret: &Self::SecretKey) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { secret_bytes: *secret, public_bytes: verifying_key.to_bytes() })
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_bytes
    }

    fn secret_key(&self) -> &Self::SecretKey {
        &self.secret_bytes
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, IdentityError> {
        let signing_key = SigningKey::from_bytes(&self.secret_bytes);
        let signature = signing_key.sign(message).to_bytes().to_vec();
        Ok(signature)
    }

    fn verify(public: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool, IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(public)
            .map_err(|e| IdentityError::InvalidKeyMaterial(format!("invalid ed25519 public key: {e}")))?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| IdentityError::InvalidKeyMaterial(format!("invalid ed25519 signature: {e}")))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.secret_bytes);
        bytes.extend_from_slice(&self.public_bytes);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < 64 {
            return Err(IdentityError::InvalidKeyMaterial("ed25519 key material too short".into()));
        }
        let secret: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyMaterial("invalid ed25519 secret key length".into()))?;
        let public: [u8; 32] = bytes[32..64]
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyMaterial("invalid ed25519 public key length".into()))?;
        // Validate keypair consistency
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = VerifyingKey::from_bytes(&public)
            .map_err(|_| IdentityError::InvalidKeyMaterial("invalid ed25519 public key bytes".into()))?;
        if signing_key.verifying_key() != verifying_key {
            return Err(IdentityError::InvalidKeyMaterial("ed25519 key material mismatch".into()));
        }
        Ok(Self { secret_bytes: secret, public_bytes: public })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultIdentity;

    #[test]
    fn generate_ed25519_identity() {
        let id = Ed25519Identity::generate().unwrap();
        let pk = id.verifying_key_bytes();
        assert_ne!(pk, [0u8; 32]);
    }

    #[test]
    fn sign_and_verify_ed25519() {
        let id = Ed25519Identity::generate().unwrap();
        let pk = id.verifying_key_bytes();
        let msg = b"hello vault identity";
        let sig = id.sign(msg).unwrap();
        assert!(Ed25519Identity::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn sign_verify_wrong_message_fails() {
        let id = Ed25519Identity::generate().unwrap();
        let pk = id.verifying_key_bytes();
        let sig = id.sign(b"message a").unwrap();
        assert!(!Ed25519Identity::verify(&pk, b"message b", &sig).unwrap());
    }

    #[test]
    fn roundtrip_bytes() {
        let id = Ed25519Identity::generate().unwrap();
        let pk = id.verifying_key_bytes();
        let bytes = id.to_bytes();
        let restored = Ed25519Identity::from_bytes(&bytes).unwrap();
        assert_eq!(restored.verifying_key_bytes(), pk);
        let sig = restored.sign(b"roundtrip").unwrap();
        assert!(Ed25519Identity::verify(&pk, b"roundtrip", &sig).unwrap());
    }

    #[test]
    fn from_secret_derives_correct_public() {
        let id = Ed25519Identity::generate().unwrap();
        let sk = id.signing_key_bytes();
        let pk = id.verifying_key_bytes();
        let restored = Ed25519Identity::from_secret(&sk).unwrap();
        assert_eq!(restored.verifying_key_bytes(), pk);
    }

    #[test]
    fn trait_public_key_returns_bytes() {
        let id = Ed25519Identity::generate().unwrap();
        let pk = *id.public_key();
        assert_ne!(pk, [0u8; 32]);
        assert_eq!(pk, id.verifying_key_bytes());
    }

    #[test]
    fn trait_secret_key_returns_bytes() {
        let id = Ed25519Identity::generate().unwrap();
        let sk = *id.secret_key();
        assert_ne!(sk, [0u8; 32]);
        assert_eq!(sk, id.signing_key_bytes());
    }

    #[test]
    fn from_raw_roundtrip() {
        let id = Ed25519Identity::generate().unwrap();
        let sk = id.signing_key_bytes();
        let pk = id.verifying_key_bytes();
        let restored = Ed25519Identity::from_raw(&sk, &pk).unwrap();
        assert_eq!(restored.verifying_key_bytes(), pk);
        let sig = restored.sign(b"raw roundtrip").unwrap();
        assert!(Ed25519Identity::verify(&pk, b"raw roundtrip", &sig).unwrap());
    }
}
