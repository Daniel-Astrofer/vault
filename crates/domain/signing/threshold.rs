//! Lab threshold primitives (Shamir over a small prime field).
//!
//! **Not** Bitcoin/secp256k1 FROST. F3 wires the state machine, quorum `⌈2n/3⌉`,
//! fail-stop, and anti-nonce-reuse. Replace field/ops with audited FROST in a
//! later milestone when crates can be vendored.

use crate::{DomainError, NodeId};

/// 31-bit Mersenne prime defining the arithmetic field used by lab primitives.
///
/// This simulation-only field is not a production cryptographic group and is
/// not a substitute for an audited FROST implementation.
pub const LAB_PRIME: u64 = 2_147_483_647;

/// One-based participant coordinate for a Shamir share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareIndex(pub u8);

impl ShareIndex {
    /// Create a share coordinate, rejecting zero because it is not a participant index.
    pub fn new(v: u8) -> Result<Self, DomainError> {
        if v == 0 {
            return Err(DomainError::InvalidShare("share index must be >= 1".into()));
        }
        Ok(Self(v))
    }
}

/// Lab representation of a participant's Shamir secret share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    /// Participant coordinate associated with this share.
    pub index: ShareIndex,
    /// Secret share value in the lab field. Never log this.
    pub value: u64,
    /// Node responsible for holding this share.
    pub node_id: NodeId,
}

impl KeyShare {
    /// Return a deterministic lab commitment derived from this index and share value.
    ///
    /// This helper is for state-machine exercises only; it is not a production
    /// commitment scheme and must not be used to protect a key.
    pub fn public_commitment(&self) -> String {
        crate::Measurement::from_bytes(format!("share-commit:{}:{}", self.index.0, self.value).as_bytes())
            .as_hex()
            .to_string()
    }
}

/// Public lab metadata describing the group threshold configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKey {
    /// Total number of shares in the configured group.
    pub n: usize,
    /// Minimum number of shares required to reconstruct the group secret.
    pub t: usize,
    /// Commitment to the joint secret (hash of dealer commitments) — not the secret.
    pub commitment: String,
}

/// Lifecycle phase of a lab signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPhase {
    /// Session exists and has not bound nonce commitments.
    Open,
    /// Nonce commitments are fixed and partial signatures may be collected.
    NoncesBound,
    /// A combined signature value has been produced.
    Combined,
    /// Session material has been consumed and cannot be used again.
    Consumed,
}

/// Mutable protocol state for one threshold signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningSession {
    /// Unique identifier binding all protocol messages to this session.
    pub session_id: String,
    /// Digest of the message every participant is expected to sign.
    pub message_hash: String,
    /// Current state-machine phase controlling accepted operations.
    pub phase: SigningPhase,
    /// Nonce commitments fixed before partials are accepted.
    pub bound_nonce_commitments: Vec<String>,
    /// Participant partial signatures collected for this session.
    pub partials: Vec<PartialSignature>,
}

/// One participant's lab partial signature and the commitment it used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature {
    /// Shamir coordinate of the participant that produced this partial.
    pub index: ShareIndex,
    /// Identity of the participant that produced the partial.
    pub node_id: NodeId,
    /// Commitment to the one-time nonce used for this partial.
    pub nonce_commitment: String,
    /// Partial scalar in the lab field, not production signature material.
    pub partial_value: u64,
}

/// Combined result of the lab threshold-signing procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedSignature {
    /// Session whose partials were combined.
    pub session_id: String,
    /// Digest of the signed message.
    pub message_hash: String,
    /// Combined scalar in the lab field, not a Bitcoin or FROST signature.
    pub value: u64,
    /// Share coordinates whose partials contributed to the result.
    pub participants: Vec<u8>,
}

impl CombinedSignature {
    /// Serialize the result to the stable lab protocol JSON representation.
    pub fn to_json(&self) -> String {
        let parts = self.participants.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"session_id":"{}","message_hash":"{}","value":{},"participants":[{}],"scheme":"lab-shamir-threshold-v1"}}"#,
            self.session_id, self.message_hash, self.value, parts
        )
    }
}

/// Add two values modulo [`LAB_PRIME`].
pub fn field_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % LAB_PRIME as u128) as u64
}

/// Multiply values modulo [`LAB_PRIME`], widening first to avoid `u64` overflow.
pub fn field_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % LAB_PRIME as u128) as u64
}

/// Subtract `b` from `a` modulo [`LAB_PRIME`], normalizing both inputs first.
pub fn field_sub(a: u64, b: u64) -> u64 {
    let a = a % LAB_PRIME;
    let b = b % LAB_PRIME;
    if a >= b {
        a - b
    } else {
        LAB_PRIME - (b - a)
    }
}

/// Compute the multiplicative inverse modulo [`LAB_PRIME`].
///
/// Returns [`DomainError::ThresholdError`] if the normalized input is zero.
pub fn mod_inv(a: u64) -> Result<u64, DomainError> {
    let a = a % LAB_PRIME;
    if a == 0 {
        return Err(DomainError::ThresholdError("inverse of 0".into()));
    }
    // Fermat: a^(p-2) mod p
    Ok(mod_pow(a, LAB_PRIME - 2))
}

/// Compute `base^exp` modulo [`LAB_PRIME`] using square-and-multiply.
fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result: u64 = 1;
    base %= LAB_PRIME;
    while exp > 0 {
        if exp & 1 == 1 {
            result = field_mul(result, base);
        }
        base = field_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Evaluate a polynomial over the lab field using ascending-degree coefficients.
///
/// `coeffs[0]` is the constant term; an empty slice evaluates to zero.
pub fn eval_poly(coeffs: &[u64], x: u64) -> u64 {
    let mut y = 0u64;
    let mut pow = 1u64;
    for &c in coeffs {
        y = field_add(y, field_mul(c, pow));
        pow = field_mul(pow, x);
    }
    y
}

/// Deterministically derive a lab field element from seed bytes.
///
/// The output is reproducible and unsuitable for secrets or production nonces;
/// this helper exists only to make protocol simulations deterministic.
pub fn lab_random_u64(seed: &[u8]) -> u64 {
    let measurement = crate::Measurement::from_bytes(seed);
    let hex = measurement.as_hex();
    let mut v = 0u64;
    for (i, c) in hex.chars().take(16).enumerate() {
        let nibble = c.to_digit(16).unwrap_or(0) as u64;
        v |= nibble << (4 * (15 - i));
    }
    (v % (LAB_PRIME - 1)) + 1
}

/// Deterministic nonce for session — must never be reused across different messages.
///
/// This is lab scaffolding, not a safe production nonce generator. Session and
/// message identifiers are included to make simulated sessions message-bound.
pub fn derive_nonce(session_id: &str, message_hash: &str, share_value: u64) -> u64 {
    lab_random_u64(format!("nonce|{session_id}|{message_hash}|{share_value}").as_bytes())
}

/// Hash a lab nonce and participant coordinate into its commitment string.
pub fn nonce_commitment(nonce: u64, index: u8) -> String {
    crate::Measurement::from_bytes(format!("nonce-commit:{index}:{nonce}").as_bytes()).as_hex().to_string()
}

/// Lagrange interpolate secret at x=0 from `t` shares.
///
/// Coordinates must be distinct and nonzero. Duplicate coordinates make a
/// denominator non-invertible and return a threshold error.
pub fn interpolate_secret(shares: &[(u8, u64)]) -> Result<u64, DomainError> {
    if shares.is_empty() {
        return Err(DomainError::ThresholdError("no shares".into()));
    }
    let mut secret = 0u64;
    for (i, &(xi, yi)) in shares.iter().enumerate() {
        let mut num = 1u64;
        let mut den = 1u64;
        for (j, &(xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            num = field_mul(num, field_sub(0, xj as u64)); // (0 - xj)
            den = field_mul(den, field_sub(xi as u64, xj as u64));
        }
        let li = field_mul(num, mod_inv(den)?);
        secret = field_add(secret, field_mul(yi, li));
    }
    Ok(secret)
}
