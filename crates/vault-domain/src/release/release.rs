//! Content-addressed release candidates, rebuild attestations, and allowlist (F5 lab).

use std::collections::{BTreeMap, BTreeSet};

use crate::Measurement;
use crate::{quorum_two_thirds, DomainError, NodeId};

/// Content-addressed blob id (`Hs` source or `Hb` binary).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Measurement::from_bytes(bytes).as_hex().to_string())
    }

    pub fn parse(raw: impl Into<String>) -> Result<Self, DomainError> {
        let m = Measurement::from_hex(raw.into())?;
        Ok(Self(m.as_hex().to_string()))
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePhase {
    Proposed,
    Cosigning,
    Allowlisted,
    Rejected,
}

impl ReleasePhase {
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
    pub council_n: usize,
    pub min_rebuilds: usize,
    /// Vault cosign quorum: majority `⌈n/2⌉+` of active set size.
    pub vault_n: usize,
    /// Base timelock seconds before cosign/activate (prod 14d); scaled by `lab_timelock_scale`.
    pub timelock_secs: u64,
    /// Lab only: `0` → immediate; `1` → real seconds; `>1` stretches.
    pub lab_timelock_scale: u64,
}

impl ReleasePolicy {
    pub fn lab_default(vault_n: usize) -> Self {
        Self {
            council_n: 3,
            min_rebuilds: 3,
            vault_n,
            timelock_secs: 14 * 24 * 3600,
            lab_timelock_scale: 0, // lab default: no wait
        }
    }

    pub fn effective_timelock_secs(&self) -> u64 {
        self.timelock_secs.saturating_mul(self.lab_timelock_scale)
    }

    pub fn council_quorum(&self) -> usize {
        quorum_two_thirds(self.council_n)
    }

    pub fn vault_cosign_quorum(&self) -> usize {
        // ⌈n/2⌉ + 0 for odd majority-ish: plan says ⌈n/2⌉+ → (n/2)+1
        (self.vault_n / 2) + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCandidate {
    pub id: String,
    pub hs: ContentHash,
    pub hb: ContentHash,
    pub constitution_hash: String,
    pub council_sigs: BTreeSet<String>,
    pub rebuilds: BTreeMap<String, ContentHash>,
    pub cosigns: BTreeSet<String>,
    pub created_at_secs: u64,
    pub phase: ReleasePhase,
    pub reject_reason: Option<String>,
}

impl ReleaseCandidate {
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

    pub fn add_cosign(&mut self, vault_id: &NodeId) -> Result<(), DomainError> {
        if matches!(self.phase, ReleasePhase::Allowlisted | ReleasePhase::Rejected) {
            return Err(DomainError::ReleaseClosed(self.id.clone()));
        }
        self.cosigns.insert(vault_id.as_str().to_string());
        self.phase = ReleasePhase::Cosigning;
        Ok(())
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    pub release_id: String,
    pub hs: ContentHash,
    pub hb: ContentHash,
    pub activated_at_secs: u64,
    pub constitution_hash: String,
}

impl AllowlistEntry {
    /// Release allowlist predicate: quote measurement must equal this entry's Hb.
    pub fn admits_measurement(&self, measurement: &Measurement) -> bool {
        self.hb.as_str() == measurement.as_hex()
    }

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
