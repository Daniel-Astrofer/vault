//! Joint Shamir-style DKG for the **lab field** (no single dealer holds the secret).
//!
//! # Honesty (#17)
//! Entropy is **deterministic** from the caller-supplied seed (typically
//! `LAB_ATTESTATION_ROOT` + genesis roster). This is **not** FROST Bitcoin keygen
//! and must never be treated as production wallet material. Prefer
//! `VAULT_DKG_MODE=distributed_wire` for real shares.

use crate::{eval_poly, field_add, lab_random_u64, DomainError, GroupKey, KeyShare, NodeId, ShareIndex};

/// Each participant contributes a random degree-(t-1) polynomial; final share_j is
/// the sum of evaluations at j. The joint secret is never assembled here.
///
/// Deterministic given `entropy` — lab visualize only.
pub fn run_dkg(active_set: &[NodeId], t: usize, entropy: &[u8]) -> Result<(GroupKey, Vec<KeyShare>), DomainError> {
    let n = active_set.len();
    if n < 2 || t == 0 || t > n {
        return Err(DomainError::ThresholdError(format!("bad n/t: n={n} t={t}")));
    }

    // polynomials[i] = coeffs for participant i (constant term = contribution)
    let mut polynomials: Vec<Vec<u64>> = Vec::with_capacity(n);
    let mut commitments = Vec::new();
    for (i, node) in active_set.iter().enumerate() {
        let mut coeffs = Vec::with_capacity(t);
        for k in 0..t {
            let seed = format!("dkg|{}|{}|{k}", bytes_to_hex(entropy), node.as_str());
            coeffs.push(lab_random_u64(seed.as_bytes()));
        }
        commitments.push(format!(
            "{}:{}",
            node.as_str(),
            crate::Measurement::from_bytes(format!("commit:{}", coeffs[0]).as_bytes(),).as_hex()
        ));
        polynomials.push(coeffs);
        let _ = i;
    }

    let mut shares = Vec::with_capacity(n);
    for (j, node) in active_set.iter().enumerate() {
        let x = (j as u64) + 1;
        let mut value = 0u64;
        for poly in &polynomials {
            value = field_add(value, eval_poly(poly, x));
        }
        shares.push(KeyShare { index: ShareIndex::new((j as u8) + 1)?, value, node_id: node.clone() });
    }

    let commitment = crate::Measurement::from_bytes(commitments.join("|").as_bytes()).as_hex().to_string();

    Ok((GroupKey { n, t, commitment }, shares))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify that `t` shares reconstruct consistently (lab self-check; reveals secret —
/// only for tests / never call with production shares in logs).
#[cfg(test)]
#[allow(dead_code)]
pub fn debug_reconstruct(shares: &[(u8, u64)]) -> Result<u64, DomainError> {
    crate::interpolate_secret(shares)
}
