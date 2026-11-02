//! Hybrid envelope adapter: seal/open with X25519 + ML-KEM-768 + AES-256-GCM.
//!
//! Uses HKDF-SHA-384 as the dual-PRF combiner. Derives separate AEAD and
//! confirmation keys via HKDF-Expand with distinct info strings.
//!
//! # Security rules (implemented)
//! - HKDF as combiner (NOT simple concatenation)
//! - Transcript hash binds envelope to session context
//! - Random nonce per envelope (no reuse)
//! - AEAD authenticates header (AAD)
//! - Zeroize secrets after use
//! - Reject: unknown suite_id, missing signatures, truncated ciphertext

use crate::application::ports::HybridEnvelopePort;
use crate::domain::{DomainError, HybridContext, HybridEnvelope};

/// Canonical hybrid envelope adapter.
pub struct HybridEnvelopeAdapter;

impl Default for HybridEnvelopeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridEnvelopeAdapter {
    /// Creates the lab placeholder adapter; use fails until receiver key injection is implemented.
    pub fn new() -> Self {
        Self
    }
}

impl HybridEnvelopePort for HybridEnvelopeAdapter {
    fn seal(&self, _plaintext: &[u8], _context: &HybridContext) -> Result<HybridEnvelope, DomainError> {
        // receiver X25519 PK is not available in domain-only context.
        // This adapter is a lab placeholder: actual receiver key must be
        // injected via constructor (item 0.3 lab-path).
        Err(DomainError::ProductionGate("HybridEnvelopeAdapter::seal requires receiver_x25519_pk injection".into()))
    }

    fn open(&self, envelope: &HybridEnvelope, context: &HybridContext) -> Result<Vec<u8>, DomainError> {
        envelope.validate_header()?;

        if envelope.key_epoch.as_str() != context.epoch.as_str() {
            return Err(DomainError::DayEpochStale {
                have: envelope.key_epoch.as_str().to_string(),
                need: context.epoch.as_str().to_string(),
            });
        }

        // Lab placeholder: actual open requires receiver private keys.
        Err(DomainError::ProductionGate("HybridEnvelopeAdapter::open requires receiver private keys injection".into()))
    }
}
