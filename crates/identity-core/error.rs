//! Identity errors for vault key material operations.

use std::fmt;

/// Errors that can occur during identity operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Signing operation failed.
    SigningFailed(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// Key material has invalid length or format.
    InvalidKeyMaterial(String),
    /// Identity not found (not yet generated).
    IdentityNotFound,
    /// Identity rotation failed.
    RotationFailed(String),
    /// Serialization error.
    SerializationFailed(String),
    /// Deserialization error.
    DeserializationFailed(String),
    /// SPIFFE SVID issuance failed.
    SpiffeIssuanceFailed(String),
    /// Certificate parsing error.
    CertificateError(String),
    /// Internal crypto error.
    InternalError(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGenerationFailed(msg) => write!(f, "key generation failed: {msg}"),
            Self::SigningFailed(msg) => write!(f, "signing failed: {msg}"),
            Self::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::InvalidKeyMaterial(msg) => write!(f, "invalid key material: {msg}"),
            Self::IdentityNotFound => write!(f, "identity not found"),
            Self::RotationFailed(msg) => write!(f, "identity rotation failed: {msg}"),
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::SpiffeIssuanceFailed(msg) => write!(f, "SPIFFE SVID issuance failed: {msg}"),
            Self::CertificateError(msg) => write!(f, "certificate error: {msg}"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {}
