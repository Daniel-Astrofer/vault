//! Lab threshold primitives (Shamir over a small prime field).
//!
//! **Not** Bitcoin/secp256k1 FROST. F3 wires the state machine, quorum `⌈2n/3⌉`,
//! fail-stop, and anti-nonce-reuse. Replace field/ops with audited FROST in a
//! later milestone when crates can be vendored.

use crate::{DomainError, NodeId};

/// 31-bit Mersenne prime — lab only.
pub const LAB_PRIME: u64 = 2_147_483_647;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareIndex(pub u8);

impl ShareIndex {
    pub fn new(v: u8) -> Result<Self, DomainError> {
        if v == 0 {
            return Err(DomainError::InvalidShare("share index must be >= 1".into()));
        }
        Ok(Self(v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    pub index: ShareIndex,
    /// Secret share value in the lab field. Never log this.
    pub value: u64,
    pub node_id: NodeId,
}

impl KeyShare {
    pub fn public_commitment(&self) -> String {
        crate::Measurement::from_bytes(format!("share-commit:{}:{}", self.index.0, self.value).as_bytes())
            .as_hex()
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKey {
    pub n: usize,
    pub t: usize,
    /// Commitment to the joint secret (hash of dealer commitments) — not the secret.
    pub commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPhase {
    Open,
    NoncesBound,
    Combined,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningSession {
    pub session_id: String,
    pub message_hash: String,
    pub phase: SigningPhase,
    pub bound_nonce_commitments: Vec<String>,
    pub partials: Vec<PartialSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature {
    pub index: ShareIndex,
    pub node_id: NodeId,
    pub nonce_commitment: String,
    pub partial_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedSignature {
    pub session_id: String,
    pub message_hash: String,
    pub value: u64,
    pub participants: Vec<u8>,
}

impl CombinedSignature {
    pub fn to_json(&self) -> String {
        let parts = self.participants.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"session_id":"{}","message_hash":"{}","value":{},"participants":[{}],"scheme":"lab-shamir-threshold-v1"}}"#,
            self.session_id, self.message_hash, self.value, parts
        )
    }
}

pub fn field_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % LAB_PRIME as u128) as u64
}

pub fn field_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % LAB_PRIME as u128) as u64
}

pub fn field_sub(a: u64, b: u64) -> u64 {
    let a = a % LAB_PRIME;
    let b = b % LAB_PRIME;
    if a >= b {
        a - b
    } else {
        LAB_PRIME - (b - a)
    }
}

pub fn mod_inv(a: u64) -> Result<u64, DomainError> {
    let a = a % LAB_PRIME;
    if a == 0 {
        return Err(DomainError::ThresholdError("inverse of 0".into()));
    }
    // Fermat: a^(p-2) mod p
    Ok(mod_pow(a, LAB_PRIME - 2))
}

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

pub fn eval_poly(coeffs: &[u64], x: u64) -> u64 {
    let mut y = 0u64;
    let mut pow = 1u64;
    for &c in coeffs {
        y = field_add(y, field_mul(c, pow));
        pow = field_mul(pow, x);
    }
    y
}

/// Deterministic lab RNG from seed bytes.
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
pub fn derive_nonce(session_id: &str, message_hash: &str, share_value: u64) -> u64 {
    lab_random_u64(format!("nonce|{session_id}|{message_hash}|{share_value}").as_bytes())
}

pub fn nonce_commitment(nonce: u64, index: u8) -> String {
    crate::Measurement::from_bytes(format!("nonce-commit:{index}:{nonce}").as_bytes()).as_hex().to_string()
}

/// Lagrange interpolate secret at x=0 from `t` shares.
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
