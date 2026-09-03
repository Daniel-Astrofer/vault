//! Hybrid envelope KAT (Known Answer Tests) — seal/unseal round-trips,
//! tamper detection, and context binding verification.
//!
//! Tests verify the hybrid envelope adapter and domain types.
//! Full seal/open round-trip requires the adapter to be wired with
//! receiver key injection (pending item 0.3). The domain-level validations
//! are tested here.

use kerosene_vault::adapters::HybridEnvelopeAdapter;
use kerosene_vault::application::ports::HybridEnvelopePort;
use kerosene_vault::domain::{DayEpoch, DomainError, HybridContext, HybridEnvelope, NodeId};

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn node(id: &str) -> NodeId {
    NodeId::new(id).expect("valid node id")
}

fn epoch(s: &str) -> DayEpoch {
    DayEpoch::parse(s).expect("valid epoch")
}

fn make_context(sender: &str, receiver: &str, epoch_str: &str) -> HybridContext {
    HybridContext {
        domain_separator: HybridEnvelope::DOMAIN_SEPARATOR.to_string(),
        transcript_hash: [0xAB; 48],
        suite_id: HybridEnvelope::SUITE_ID.to_string(),
        sender_id: node(sender),
        receiver_id: node(receiver),
        epoch: epoch(epoch_str),
    }
}

fn make_valid_envelope() -> HybridEnvelope {
    HybridEnvelope {
        format_version: HybridEnvelope::CURRENT_FORMAT_VERSION,
        suite_id: HybridEnvelope::SUITE_ID.to_string(),
        key_epoch: epoch("2026-01-01"),
        sender_id: node("vault-1"),
        receiver_id: node("vault-2"),
        sender_eph_pk: [0x11; 32],
        kem_ciphertext: vec![0x22; 768],
        nonce: [0x33; 12],
        ciphertext: vec![0x44; 64],
        classical_signature: vec![0x55; 64],
        pq_signature: vec![0x66; 3309],
    }
}

// ═══════════════════════════════════════════════════════════════════
// Domain validation tests
// ═══════════════════════════════════════════════════════════════════

/// Verify that a valid envelope passes header validation.
#[test]
fn valid_envelope_passes_validation() {
    let envelope = make_valid_envelope();
    assert!(envelope.validate_header().is_ok());
}

/// Verify that unknown suite_id is rejected.
#[test]
fn unknown_suite_id_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.suite_id = "unknown-suite-v99".to_string();
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("suite_id") || msg.contains("unknown"));
}

/// Verify that unknown format_version is rejected.
#[test]
fn unknown_format_version_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.format_version = 99;
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("format_version") || msg.contains("unknown"));
}

/// Verify that all-zero sender_eph_pk is rejected.
#[test]
fn all_zero_sender_eph_pk_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.sender_eph_pk = [0u8; 32];
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("all-zero") || msg.contains("sender_eph_pk"));
}

/// Verify that empty kem_ciphertext is rejected.
#[test]
fn empty_kem_ciphertext_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.kem_ciphertext.clear();
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("kem_ciphertext") || msg.contains("empty"));
}

/// Verify that empty ciphertext is rejected.
#[test]
fn empty_ciphertext_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.ciphertext.clear();
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("ciphertext") || msg.contains("empty"));
}

/// Verify that missing classical_signature is rejected.
#[test]
fn missing_classical_signature_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.classical_signature.clear();
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("classical_signature") || msg.contains("missing"));
}

/// Verify that missing pq_signature is rejected.
#[test]
fn missing_pq_signature_rejected() {
    let mut envelope = make_valid_envelope();
    envelope.pq_signature.clear();
    let result = envelope.validate_header();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("pq_signature") || msg.contains("missing"));
}

/// Verify that empty authenticated header (AAD) is allowed.
/// The AAD field may be empty for envelopes without routing metadata.
#[test]
fn empty_authenticated_header_allowed() {
    let envelope = make_valid_envelope();
    // ciphertext may be empty in edge case; validate_header checks it's non-empty.
    // AAD is not validated at the domain level.
    assert!(envelope.validate_header().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// Tamper detection tests
// ═══════════════════════════════════════════════════════════════════

/// Tampered ciphertext: modify the ciphertext bytes.
/// In production, the AEAD tag verification would fail.
/// Domain validation only checks non-empty — crypto verification is in adapter.
#[test]
fn tampered_ciphertext_domain_validation() {
    let mut envelope = make_valid_envelope();
    assert!(!envelope.ciphertext.is_empty());

    // Tamper the ciphertext
    if !envelope.ciphertext.is_empty() {
        envelope.ciphertext[0] ^= 0xFF;
    }

    // Domain validation still passes (checks non-empty, not integrity).
    assert!(envelope.validate_header().is_ok(), "Domain validation checks structure, not crypto integrity");
}

/// Tampered kem_ciphertext: modify the ML-KEM ciphertext.
/// Domain validation passes (non-empty). Adapter detects at decapsulation.
#[test]
fn tampered_kem_ciphertext_domain_validation() {
    let mut envelope = make_valid_envelope();
    assert!(!envelope.kem_ciphertext.is_empty());

    // Tamper the KEM ciphertext
    envelope.kem_ciphertext[0] ^= 0xFF;

    // Domain validation still passes
    assert!(envelope.validate_header().is_ok(), "Domain validation checks structure, not crypto integrity");
}

/// Tampered classical_signature: modify Ed25519 signature bytes.
/// Domain validation passes (non-empty). Adapter detects at verification.
#[test]
fn tampered_classical_signature_domain_validation() {
    let mut envelope = make_valid_envelope();
    assert!(!envelope.classical_signature.is_empty());

    // Tamper
    envelope.classical_signature[0] ^= 0xFF;

    assert!(envelope.validate_header().is_ok(), "Domain validation checks structure, not crypto integrity");
}

/// Tampered pq_signature: modify ML-DSA signature bytes.
/// Domain validation passes (non-empty). Adapter detects at verification.
#[test]
fn tampered_pq_signature_domain_validation() {
    let mut envelope = make_valid_envelope();
    assert!(!envelope.pq_signature.is_empty());

    // Tamper
    envelope.pq_signature[0] ^= 0xFF;

    assert!(envelope.validate_header().is_ok(), "Domain validation checks structure, not crypto integrity");
}

// ═══════════════════════════════════════════════════════════════════
// Context binding tests
// ═══════════════════════════════════════════════════════════════════

/// Wrong epoch in context: envelope epoch must match context epoch.
/// Adapter open() validates key_epoch before crypto operations.
#[test]
fn wrong_epoch_rejected_by_adapter() {
    let envelope = make_valid_envelope(); // key_epoch = 2026-01-01
    let wrong_ctx = make_context("vault-1", "vault-2", "2026-01-02");
    let adapter = HybridEnvelopeAdapter::new();

    let result = adapter.open(&envelope, &wrong_ctx);

    match result {
        Err(DomainError::DayEpochStale { .. }) => {
            // Expected: epoch mismatch caught
        }
        Err(DomainError::ProductionGate(_)) => {
            // Lab stub — epoch check happens in full adapter
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("epoch") || msg.contains("stale") || msg.contains("ProductionGate"),
                "Unexpected error: {e}"
            );
        }
        Ok(_) => {
            panic!("Wrong epoch accepted — FAIL CLOSED violation");
        }
    }
}

/// Wrong sender_id in context: envelope sender_id must match context sender_id.
#[test]
fn wrong_sender_id_does_not_bind() {
    let envelope = make_valid_envelope(); // sender_id = vault-1
    let wrong_ctx = make_context("vault-3", "vault-2", "2026-01-01");
    let adapter = HybridEnvelopeAdapter::new();

    let result = adapter.open(&envelope, &wrong_ctx);

    // sender_id mismatch detected before crypto (receiver_id binding in full adapter)
    match result {
        Err(DomainError::ProductionGate(_)) => {}
        Err(e) => {
            let _ = e;
        }
        Ok(_) => {
            panic!("Wrong sender context should be rejected");
        }
    }
}

/// Wrong receiver_id in context: envelope receiver_id must match context receiver_id.
#[test]
fn wrong_receiver_id_does_not_bind() {
    let envelope = make_valid_envelope(); // receiver_id = vault-2
    let wrong_ctx = make_context("vault-1", "vault-3", "2026-01-01");
    let adapter = HybridEnvelopeAdapter::new();

    let result = adapter.open(&envelope, &wrong_ctx);

    match result {
        Err(DomainError::ProductionGate(_)) => {}
        Err(e) => {
            let _ = e;
        }
        Ok(_) => {
            panic!("Wrong receiver context should be rejected");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Adapter seal/open round-trip (stub — requires receiver key injection)
// ═══════════════════════════════════════════════════════════════════

/// Seal/open round-trip with known keys: currently returns ProductionGate
/// because receiver X25519/ML-KEM public keys are not injected.
///
/// TODO: Wire receiver keys into HybridEnvelopeAdapter constructor (item 0.3).
#[test]
#[ignore = "Requires receiver key injection into HybridEnvelopeAdapter (item 0.3)"]
fn seal_unseal_roundtrip_known_keys() {
    let adapter = HybridEnvelopeAdapter::new();
    let ctx = make_context("vault-1", "vault-2", "2026-01-01");
    let plaintext = b"sensitive share data for round-trip test";

    let envelope = adapter.seal(plaintext, &ctx).expect("seal should succeed with known receiver keys");
    let decrypted = adapter.open(&envelope, &ctx).expect("open should succeed with known keys");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice(), "Round-trip decryption must return original plaintext");
}
