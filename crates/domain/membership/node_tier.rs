//! Vault node tiers: domestic (home PC / TPM) vs SEV/SGX (preferred TEE).
//!
//! Honest labeling: TPM ≠ SEV. Domestic is first-class; TEE gets seating priority.

use crate::{DomainError, NodeId};

/// Hardware / trust tier of a vault node.
///
/// - [`Domestic`](Self::Domestic): home/miner PC; software measurement (+ optional TPM seal).
/// - [`Sev`](Self::Sev) / [`Sgx`](Self::Sgx): real confidential-compute upgrade when HW is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultNodeTier {
    /// Domestic operator hardware; may use software measurement or optional TPM sealing.
    Domestic,
    /// Intel SGX enclave-backed node.
    Sgx,
    /// AMD SEV-SNP confidential-computing node.
    Sev,
}

impl VaultNodeTier {
    /// Parse a tier name or supported alias, trimming whitespace and ignoring ASCII case.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "domestic" | "home" | "tpm" => Some(Self::Domestic),
            "sgx" => Some(Self::Sgx),
            "sev" | "sev-snp" | "sev_snp" => Some(Self::Sev),
            _ => None,
        }
    }

    /// Return the canonical lowercase tier name used by configuration and health output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domestic => "domestic",
            Self::Sgx => "sgx",
            Self::Sev => "sev",
        }
    }

    /// Seating / admission rank: higher fills genesis seats first (`sev` > `sgx` > `domestic`).
    pub fn seating_priority(self) -> u8 {
        match self {
            Self::Sev => 3,
            Self::Sgx => 2,
            Self::Domestic => 1,
        }
    }

    /// Soft governance weight (basis points of a 1.0x domestic baseline).
    /// Hard policy for genesis is seating priority; weight is for docs / future accrual.
    pub fn governance_weight_bps(self) -> u32 {
        match self {
            Self::Sev => 15_000,
            Self::Sgx => 12_500,
            Self::Domestic => 10_000,
        }
    }

    /// Return whether this tier represents a hardware trusted execution environment.
    pub fn is_tee(self) -> bool {
        matches!(self, Self::Sev | Self::Sgx)
    }

    /// Return whether this tier represents the domestic, non-TEE operating mode.
    pub fn is_domestic(self) -> bool {
        matches!(self, Self::Domestic)
    }
}

/// Candidate for genesis / signing seating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatingCandidate {
    /// Stable mesh node identifier used for deduplication and deterministic tie-breaking.
    pub id: NodeId,
    /// Trust tier whose priority determines seat ordering.
    pub tier: VaultNodeTier,
}

/// Fill up to `n` seats preferring highest tier, then stable `node_id` order.
///
/// Algorithm:
/// 1. Deduplicate by `node_id` (first occurrence wins).
/// 2. Sort by `tier.seating_priority()` descending, then `node_id` ascending.
/// 3. Take the first `n` ids.
///
/// A mixed roster (domestic + SEV) therefore seats SEV/SGX first; an all-domestic
/// set of size `n` seats normally. Pads are **not** invented here — callers add
/// lab pads before calling if desired.
pub fn seat_genesis_by_tier(candidates: &[SeatingCandidate], n: usize) -> Vec<NodeId> {
    let mut seen = std::collections::BTreeSet::new();
    let mut unique: Vec<SeatingCandidate> = Vec::new();
    for c in candidates {
        if seen.insert(c.id.as_str().to_string()) {
            unique.push(c.clone());
        }
    }
    unique.sort_by(|a, b| {
        b.tier.seating_priority().cmp(&a.tier.seating_priority()).then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
    unique.into_iter().map(|c| c.id).take(n).collect()
}

/// Resolve a configured tier (`auto` → detected tier, else domestic).
///
/// Device probing and environment reads belong to outer layers; this function
/// receives their already-resolved result so the domain remains deterministic.
/// Returns the resolved tier and whether detection reported a TEE. The `auto`
/// keyword is recognized exactly after trimming; explicit tier names are parsed
/// case-insensitively by [`VaultNodeTier::parse`].
pub fn resolve_node_tier(
    raw: Option<&str>,
    detected: Option<VaultNodeTier>,
) -> Result<(VaultNodeTier, bool), DomainError> {
    let tee_available = detected.is_some();
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("auto") => Ok((detected.unwrap_or(VaultNodeTier::Domestic), tee_available)),
        Some(other) => {
            let tier = VaultNodeTier::parse(other)
                .ok_or_else(|| DomainError::AttestationRejected(format!("unknown VAULT_NODE_TIER={other}")))?;
            Ok((tier, tee_available))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_parse_and_priority() {
        assert_eq!(VaultNodeTier::parse("domestic"), Some(VaultNodeTier::Domestic));
        assert_eq!(VaultNodeTier::parse("SEV"), Some(VaultNodeTier::Sev));
        assert_eq!(VaultNodeTier::parse("sgx"), Some(VaultNodeTier::Sgx));
        assert!(VaultNodeTier::parse("epyc").is_none());
        assert!(VaultNodeTier::Sev.seating_priority() > VaultNodeTier::Sgx.seating_priority());
        assert!(VaultNodeTier::Sgx.seating_priority() > VaultNodeTier::Domestic.seating_priority());
    }

    #[test]
    fn seating_prefers_sev_then_sgx_then_domestic() {
        let cands = vec![
            SeatingCandidate { id: NodeId::new("vault-d2").unwrap(), tier: VaultNodeTier::Domestic },
            SeatingCandidate { id: NodeId::new("vault-s1").unwrap(), tier: VaultNodeTier::Sgx },
            SeatingCandidate { id: NodeId::new("vault-e1").unwrap(), tier: VaultNodeTier::Sev },
            SeatingCandidate { id: NodeId::new("vault-d1").unwrap(), tier: VaultNodeTier::Domestic },
        ];
        let seats = seat_genesis_by_tier(&cands, 3);
        assert_eq!(seats.iter().map(|n| n.as_str()).collect::<Vec<_>>(), vec!["vault-e1", "vault-s1", "vault-d1"]);
    }

    #[test]
    fn seating_all_domestic_ok() {
        let cands: Vec<_> = (1..=3)
            .map(|i| SeatingCandidate { id: NodeId::new(format!("vault-{i}")).unwrap(), tier: VaultNodeTier::Domestic })
            .collect();
        let seats = seat_genesis_by_tier(&cands, 3);
        assert_eq!(seats.len(), 3);
        assert_eq!(seats[0].as_str(), "vault-1");
    }

    #[test]
    fn auto_uses_outer_layer_detection() {
        assert_eq!(resolve_node_tier(Some("auto"), Some(VaultNodeTier::Sev)).unwrap(), (VaultNodeTier::Sev, true));
        assert_eq!(resolve_node_tier(Some("auto"), None).unwrap(), (VaultNodeTier::Domestic, false));
    }
}

/// Post-genesis admission seating for a new vault node.
///
/// Priority: SEV > SGX > domestic (same as `seating_priority`).
/// Timeout: if TEE node does not complete admission within `timeout_hours`,
/// a domestic node may be admitted as fallback.
///
/// Returns the tier to admit: domestic immediately, or the requested TEE tier
/// until its attestation has exceeded the timeout, after which it falls back to domestic.
/// A missing attestation timestamp leaves the TEE candidate pending at its requested tier.
pub fn admission_seating(
    tier: VaultNodeTier,
    attested_at_secs: Option<u64>,
    now_secs: u64,
    timeout_hours: u64,
) -> Result<VaultNodeTier, DomainError> {
    match tier {
        VaultNodeTier::Domestic => Ok(VaultNodeTier::Domestic),
        VaultNodeTier::Sgx | VaultNodeTier::Sev => {
            if let Some(attested) = attested_at_secs {
                let elapsed = now_secs.saturating_sub(attested);
                let timeout = timeout_hours * 3600;
                if elapsed > timeout {
                    return Ok(VaultNodeTier::Domestic);
                }
            }
            Ok(tier)
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn domestic_admitted_immediately() {
        assert_eq!(admission_seating(VaultNodeTier::Domestic, None, 1000, 24).unwrap(), VaultNodeTier::Domestic);
    }

    #[test]
    fn sev_admitted_within_timeout() {
        assert_eq!(admission_seating(VaultNodeTier::Sev, Some(100), 500, 24).unwrap(), VaultNodeTier::Sev);
    }

    #[test]
    fn sev_falls_back_to_domestic_after_timeout() {
        assert_eq!(
            admission_seating(VaultNodeTier::Sev, Some(100), 100 + 25 * 3600, 24).unwrap(),
            VaultNodeTier::Domestic
        );
    }

    #[test]
    fn sev_no_attestation_yet_admitted() {
        assert_eq!(admission_seating(VaultNodeTier::Sev, None, 1000, 24).unwrap(), VaultNodeTier::Sev);
    }
}
