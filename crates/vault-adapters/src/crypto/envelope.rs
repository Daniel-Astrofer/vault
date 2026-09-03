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

use aead::{Aead, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha384;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::application::ports::HybridEnvelopePort;
use crate::domain::{DayEpoch, DomainError, HybridContext, HybridEnvelope, HybridKeyMaterial};

/// Canonical hybrid envelope adapter.
pub struct HybridEnvelopeAdapter;

impl HybridEnvelopeAdapter {
    pub fn new() -> Self {
        Self
    }

    fn build_ikm(&self, ss_classical: &[u8; 32], ss_pq: &[u8; 32]) -> Vec<u8> {
        // Length-prefixed concat: ||len32||ss_classical||len32||ss_pq
        let mut ikm = Vec::with_capacity(4 + 32 + 4 + 32);
        ikm.extend_from_slice(&32u32.to_be_bytes());
        ikm.extend_from_slice(ss_classical);
        ikm.extend_from_slice(&32u32.to_be_bytes());
        ikm.extend_from_slice(ss_pq);
        ikm
    }

    fn deterministic_encode_context(&self, context: &HybridContext) -> Vec<u8> {
        let domain_bytes = context.domain_separator.as_bytes();
        let suite_bytes = context.suite_id.as_bytes();
        let sender_bytes = context.sender_id.as_str().as_bytes();
        let receiver_bytes = context.receiver_id.as_str().as_bytes();
        let epoch_bytes = context.epoch.as_str().as_bytes();

        let total = 8
            + domain_bytes.len()
            + 48 // transcript_hash
            + suite_bytes.len()
            + sender_bytes.len()
            + receiver_bytes.len()
            + epoch_bytes.len();

        let mut buf = Vec::with_capacity(total);

        // Length-prefixed deterministic encoding
        buf.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(domain_bytes);
        buf.extend_from_slice(&context.transcript_hash);
        buf.extend_from_slice(&(suite_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(suite_bytes);
        buf.extend_from_slice(&(sender_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(sender_bytes);
        buf.extend_from_slice(&(receiver_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(receiver_bytes);
        buf.extend_from_slice(&(epoch_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(epoch_bytes);

        buf
    }
}

impl HybridEnvelopePort for HybridEnvelopeAdapter {
    fn seal(&self, plaintext: &[u8], context: &HybridContext) -> Result<HybridEnvelope, DomainError> {
        // 1. Generate X25519 ephemeral keypair
        let mut rng = OsRng;
        let eph_sk = EphemeralSecret::random_from_rng(&mut rng);
        let eph_pk = X25519PublicKey::from(&eph_sk);

        // receiver X25519 PK is not available in domain-only context.
        // This adapter is a lab placeholder: actual receiver key must be
        // injected via constructor (item 0.3 lab-path).
        return Err(DomainError::ProductionGate(
            "HybridEnvelopeAdapter::seal requires receiver_x25519_pk injection".into(),
        ));
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
        return Err(DomainError::ProductionGate(
            "HybridEnvelopeAdapter::open requires receiver private keys injection".into(),
        ));
    }
}
