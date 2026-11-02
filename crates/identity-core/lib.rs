//! Vault identity core — shared identity traits and types.
//!
//! Provides the `VaultIdentity` trait and implementations for:
//! - Ed25519 (classical signing)
//! - ML-DSA-65 (post-quantum signing)
//! - Hybrid (Ed25519 + ML-DSA-65 combined)

pub mod error;
pub mod identity;

/// Compatibility module for callers using the pre-organized path.
pub mod ed25519_identity {
    pub use crate::identity::ed25519_identity::*;
}

/// Compatibility module for callers using the pre-organized path.
pub mod hybrid_identity {
    pub use crate::identity::hybrid_identity::*;
}

/// Compatibility module for callers using the pre-organized path.
pub mod ml_dsa_identity {
    pub use crate::identity::ml_dsa_identity::*;
}

pub use error::IdentityError;
pub use identity::ed25519_identity::Ed25519Identity;
pub use identity::hybrid_identity::HybridKeyPair;
pub use identity::ml_dsa_identity::MlDsa65Identity;

use zeroize::Zeroize;

/// The primary identity trait for vault key material.
///
/// Each identity implementation provides key generation, signing, and
/// verification for a specific cryptographic scheme.
pub trait VaultIdentity: Zeroize {
    /// The type representing the public key.
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    /// The type representing the secret key material.
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    /// The type representing a signature.
    type Signature: AsRef<[u8]> + Clone + Send + Sync;

    /// Generate a fresh identity keypair.
    fn generate() -> Result<Self, IdentityError>
    where
        Self: Sized;

    /// Create an identity from existing secret key material.
    fn from_secret(secret: &Self::SecretKey) -> Result<Self, IdentityError>
    where
        Self: Sized;

    /// Return the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Return the secret key (for internal use only — never expose to IPC).
    fn secret_key(&self) -> &Self::SecretKey;

    /// Sign a message with the identity key.
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, IdentityError>;

    /// Verify a signature against the public key.
    fn verify(public: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool, IdentityError>;

    /// Serialize the full identity (public + secret) to bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize an identity from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError>
    where
        Self: Sized;
}
