//! Content-addressed release candidates, rebuild attestations, and allowlist (F5 lab).

use std::collections::{BTreeMap, BTreeSet};

use crate::Measurement;
use crate::{quorum_two_thirds, DomainError, NodeId};

/// Content-addressed blob id (`Hs` source or `Hb` binary).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(String);

impl ContentHash {
    /// Hash arbitrary content bytes into the canonical hexadecimal content identifier.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Measurement::from_bytes(bytes).as_hex().to_string())
    }

    /// Parse a hexadecimal measurement and normalize it to canonical lowercase form.
    ///
    /// Returns the domain measurement error if the input is malformed.
    pub fn parse(raw: impl Into<String>) -> Result<Self, DomainError> {
        let m = Measurement::from_hex(raw.into())?;
        Ok(Self(m.as_hex().to_string()))
    }

    /// Borrow the canonical hexadecimal representation used in persistence and comparisons.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lab-deterministic "rebuild": binary fingerprint derived from source bytes.
pub fn lab_rebuild_binary_hash(source: &[u8]) -> ContentHash {
    let mut material = b"lab-rebuild-v1|".to_vec();
    material.extend_from_slice(source);
    ContentHash::from_bytes(&material)
}

/// Lifecycle state of a proposed software release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePhase {
    /// Candidate has been proposed and awaits required predicates/cosigns.
    Proposed,
    /// At least one vault has recorded a cosign.
    Cosigning,
    /// Candidate passed activation checks and is admitted by the allowlist.
    Allowlisted,
    /// Candidate was explicitly rejected and can no longer be changed.
    Rejected,
}

impl ReleasePhase {
    /// Return the stable lowercase phase name used in serialized candidate data.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Cosigning => "cosigning",
            Self::Allowlisted => "allowlisted",
            Self::Rejected => "rejected",
        }
    }
}

/// Policy knobs for NORMAL path (lab-scaled timelock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    /// Number of council members in the policy's voting set.
    pub council_n: usize,
    /// Minimum number of independent vault rebuild attestations required.
    pub min_rebuilds: usize,
    /// Vault cosign quorum: majority `⌈n/2⌉+` of active set size.
    pub vault_n: usize,
    /// Base timelock seconds before cosign/activate (prod 14d); scaled by `lab_timelock_scale`.
    pub timelock_secs: u64,
    /// Lab only: `0` → immediate; `1` → real seconds; `>1` stretches.
    pub lab_timelock_scale: u64,
}

impl ReleasePolicy {
    /// Build the lab policy with a three-member council, three rebuilds, and no effective wait.
    pub fn lab_default(vault_n: usize) -> Self {
        Self {
            council_n: 3,
            min_rebuilds: 3,
            vault_n,
            timelock_secs: 14 * 24 * 3600,
            lab_timelock_scale: 0, // lab default: no wait
        }
    }

    /// Apply the lab scale to the configured base delay using saturating multiplication.
    pub fn effective_timelock_secs(&self) -> u64 {
        self.timelock_secs.saturating_mul(self.lab_timelock_scale)
    }

    /// Calculate the two-thirds council threshold for the configured council size.
    pub fn council_quorum(&self) -> usize {
        quorum_two_thirds(self.council_n)
    }

    /// Calculate the strict-majority vault cosign threshold for the active vault set.
    pub fn vault_cosign_quorum(&self) -> usize {
        // ⌈n/2⌉ + 0 for odd majority-ish: plan says ⌈n/2⌉+ → (n/2)+1
        (self.vault_n / 2) + 1
    }
}

/// Release proposal and its council, rebuild, cosign, and timing evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCandidate {
    /// Stable identifier of this proposed release.
    pub id: String,
    /// Content hash of the source artifact (`Hs`).
    pub hs: ContentHash,
    /// Content hash of the expected rebuilt binary (`Hb`).
    pub hb: ContentHash,
    /// Constitution hash under which the candidate was proposed.
    pub constitution_hash: String,
    /// Unique council signer identifiers recorded for the proposal.
    pub council_sigs: BTreeSet<String>,
    /// Rebuild attestations keyed by vault identifier; values are the rebuilt binary hashes.
    pub rebuilds: BTreeMap<String, ContentHash>,
    /// Unique vault identifiers that have cosigned this release.
    pub cosigns: BTreeSet<String>,
    /// Unix timestamp when the candidate was proposed.
    pub created_at_secs: u64,
    /// Current lifecycle phase controlling whether the candidate may change.
    pub phase: ReleasePhase,
    /// Optional explanation attached to an explicit rejection.
    pub reject_reason: Option<String>,
}

impl ReleaseCandidate {
    /// Create a proposed release candidate with nonempty id and at least one council signer.
    ///
    /// This constructor records the supplied signatures but quorum sufficiency is
    /// checked later by [`Self::predicates_ok`].
    pub fn new(
        id: String,
        hs: ContentHash,
        hb: ContentHash,
        constitution_hash: String,
        council_sigs: BTreeSet<String>,
        created_at_secs: u64,
    ) -> Result<Self, DomainError> {
        if id.trim().is_empty() {
            return Err(DomainError::InvalidRelease("empty release id".into()));
        }
        if council_sigs.is_empty() {
            return Err(DomainError::InvalidRelease("no council signatures".into()));
        }
        Ok(Self {
            id,
            hs,
            hb,
            constitution_hash,
            council_sigs,
            rebuilds: BTreeMap::new(),
            cosigns: BTreeSet::new(),
            created_at_secs,
            phase: ReleasePhase::Proposed,
            reject_reason: None,
        })
    }

    /// Record a vault's successful rebuild attestation after matching the expected binary hash.
    ///
    /// Rejected and allowlisted candidates are closed. Repeating a vault identifier
    /// replaces its prior map entry and does not increase the distinct rebuild count.
    pub fn record_rebuild(&mut self, vault_id: &NodeId, rebuilt_hb: ContentHash) -> Result<(), DomainError> {
        if matches!(self.phase, ReleasePhase::Allowlisted | ReleasePhase::Rejected) {
            return Err(DomainError::ReleaseClosed(self.id.clone()));
        }
        if rebuilt_hb != self.hb {
            return Err(DomainError::RebuildMismatch {
                expected: self.hb.as_str().to_string(),
                got: rebuilt_hb.as_str().to_string(),
            });
        }
        self.rebuilds.insert(vault_id.as_str().to_string(), rebuilt_hb);
        Ok(())
    }

    /// Check constitution, council quorum, rebuild count, and elapsed timelock predicates.
    ///
    /// `now_secs` is compared with the proposal timestamp using saturating subtraction.
    /// Returns a specific domain error for the first failed predicate.
    pub fn predicates_ok(
        &self,
        policy: &ReleasePolicy,
        now_secs: u64,
        active_constitution_hash: &str,
    ) -> Result<(), DomainError> {
        if self.constitution_hash != active_constitution_hash {
            return Err(DomainError::ReleasePredicate("constitution_hash mismatch".into()));
        }
        if self.council_sigs.len() < policy.council_quorum() {
            return Err(DomainError::QuorumNotMet { have: self.council_sigs.len(), need: policy.council_quorum() });
        }
        if self.rebuilds.len() < policy.min_rebuilds {
            return Err(DomainError::QuorumNotMet { have: self.rebuilds.len(), need: policy.min_rebuilds });
        }
        let age = now_secs.saturating_sub(self.created_at_secs);
        let need_age = policy.effective_timelock_secs();
        if age < need_age {
            return Err(DomainError::TimelockNotElapsed { age_secs: age, need_secs: need_age });
        }
        Ok(())
    }

    /// Add a vault cosign and move the candidate into the cosigning phase.
    ///
    /// Closed candidates reject updates. Repeated cosigns by the same vault are
    /// idempotent because signers are stored in a set.
    pub fn add_cosign(&mut self, vault_id: &NodeId) -> Result<(), DomainError> {
        if matches!(self.phase, ReleasePhase::Allowlisted | ReleasePhase::Rejected) {
            return Err(DomainError::ReleaseClosed(self.id.clone()));
        }
        self.cosigns.insert(vault_id.as_str().to_string());
        self.phase = ReleasePhase::Cosigning;
        Ok(())
    }

    /// Serialize candidate fields to the crate's JSON wire representation.
    ///
    /// Set-backed signer collections are emitted in sorted order. String values
    /// are interpolated directly, so callers must not treat this helper as a
    /// general-purpose JSON escaping boundary for untrusted strings.
    pub fn to_json(&self) -> String {
        let council: Vec<_> = self.council_sigs.iter().cloned().collect();
        let rebuilds: Vec<_> =
            self.rebuilds.iter().map(|(k, v)| format!(r#"{{"vault":"{k}","hb":"{}"}}"#, v.as_str())).collect();
        let cosigns: Vec<_> = self.cosigns.iter().cloned().collect();
        format!(
            r#"{{"id":"{}","hs":"{}","hb":"{}","constitution_hash":"{}","council_sigs":[{}],"rebuilds":[{}],"cosigns":[{}],"created_at_secs":{},"phase":"{}","reject_reason":{}}}"#,
            self.id,
            self.hs.as_str(),
            self.hb.as_str(),
            self.constitution_hash,
            council.iter().map(|s| format!(r#""{s}""#)).collect::<Vec<_>>().join(","),
            rebuilds.join(","),
            cosigns.iter().map(|s| format!(r#""{s}""#)).collect::<Vec<_>>().join(","),
            self.created_at_secs,
            self.phase.as_str(),
            match &self.reject_reason {
                Some(r) => format!(r#""{r}""#),
                None => "null".into(),
            }
        )
    }
}

/// Activated release record used to admit matching binary measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// Release candidate identifier admitted by this entry.
    pub release_id: String,
    /// Source content hash associated with the admitted release.
    pub hs: ContentHash,
    /// Expected binary measurement admitted for execution.
    pub hb: ContentHash,
    /// Unix timestamp when the release was activated.
    pub activated_at_secs: u64,
    /// Constitution hash that governed activation.
    pub constitution_hash: String,
}

impl AllowlistEntry {
    /// Release allowlist predicate: quote measurement must equal this entry's Hb.
    pub fn admits_measurement(&self, measurement: &Measurement) -> bool {
        self.hb.as_str() == measurement.as_hex()
    }

    /// Serialize the entry to the crate's JSON wire representation.
    ///
    /// String values are interpolated directly and are not escaped by this helper.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"release_id":"{}","hs":"{}","hb":"{}","activated_at_secs":{},"constitution_hash":"{}"}}"#,
            self.release_id,
            self.hs.as_str(),
            self.hb.as_str(),
            self.activated_at_secs,
            self.constitution_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_mismatch_rejects_tampered_hb() {
        let hs = ContentHash::from_bytes(b"source-v1");
        let good_hb = lab_rebuild_binary_hash(b"source-v1");
        let bad_hb = ContentHash::from_bytes(b"evil-binary");
        let mut c = ReleaseCandidate::new(
            "r1".into(),
            hs,
            good_hb.clone(),
            "const".into(),
            BTreeSet::from(["c1".into(), "c2".into()]),
            0,
        )
        .unwrap();
        let vault = NodeId::new("v1").unwrap();
        assert!(c.record_rebuild(&vault, bad_hb).is_err());
        assert!(c.record_rebuild(&vault, good_hb).is_ok());
    }

    #[test]
    fn lab_timelock_zero_is_immediate() {
        let policy = ReleasePolicy { lab_timelock_scale: 0, ..ReleasePolicy::lab_default(3) };
        assert_eq!(policy.effective_timelock_secs(), 0);
        assert_eq!(policy.council_quorum(), 2);
        assert_eq!(policy.vault_cosign_quorum(), 2);
    }
}
