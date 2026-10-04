//! Application workflows for proposing, rebuilding, cosigning, and activating releases.
//!
//! These use cases coordinate content storage and governance state. Release
//! binaries are only added to the allowlist after quorum, rebuild, constitution,
//! and timelock predicates pass.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::ports::{BlobStorePort, ClockPort, LedgerPort, ReleaseStorePort};
use crate::AccrueGovernanceWork;
use vault_domain::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, DomainError, GovernanceJobKind, NodeId, ReleaseCandidate,
    ReleasePhase,
};

/// Use case for publishing release source/binary artifacts and creating a candidate.
pub struct ProposeRelease {
    releases: Arc<dyn ReleaseStorePort>,
    blobs: Arc<dyn BlobStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
}

impl ProposeRelease {
    /// Create the proposal workflow with blob, release, ledger, and clock ports.
    pub fn new(
        releases: Arc<dyn ReleaseStorePort>,
        blobs: Arc<dyn BlobStorePort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
    ) -> Self {
        Self { releases, blobs, ledger, clock }
    }

    /// Lab: publish source bytes → Hs, derive Hb via lab rebuild, store both blobs + candidate.
    ///
    /// Stores the source and deterministic lab binary before checking council quorum
    /// and persisting the candidate; an error after blob writes can leave unreferenced blobs.
    pub fn execute(
        &self,
        release_id: &str,
        source: &[u8],
        council_sigs: BTreeSet<String>,
    ) -> Result<ReleaseCandidate, DomainError> {
        let hs = ContentHash::from_bytes(source);
        let hb = lab_rebuild_binary_hash(source);
        self.blobs.put(&hs, source)?;
        let binary = format!("lab-bin|{}", hs.as_str());
        self.blobs.put(&hb, binary.as_bytes())?;

        let constitution = self.ledger.constitution()?;
        let policy = self.releases.policy()?;
        if council_sigs.len() < policy.council_quorum() {
            return Err(DomainError::QuorumNotMet { have: council_sigs.len(), need: policy.council_quorum() });
        }
        let candidate = ReleaseCandidate::new(
            release_id.to_string(),
            hs,
            hb,
            constitution.hash,
            council_sigs,
            self.clock.unix_now_secs(),
        )?;
        self.releases.put_candidate(candidate.clone())?;
        Ok(candidate)
    }

    /// Propose with explicit Hs/Hb (tamper tests). Source blob for `hs` must already exist.
    ///
    /// This path verifies source availability and council quorum but intentionally
    /// does not prove that `hb` is the result of rebuilding `hs`.
    pub fn execute_with_hashes(
        &self,
        release_id: &str,
        hs: ContentHash,
        hb: ContentHash,
        council_sigs: BTreeSet<String>,
    ) -> Result<ReleaseCandidate, DomainError> {
        let _ = self.blobs.get(&hs)?;
        let constitution = self.ledger.constitution()?;
        let policy = self.releases.policy()?;
        if council_sigs.len() < policy.council_quorum() {
            return Err(DomainError::QuorumNotMet { have: council_sigs.len(), need: policy.council_quorum() });
        }
        let candidate = ReleaseCandidate::new(
            release_id.to_string(),
            hs,
            hb,
            constitution.hash,
            council_sigs,
            self.clock.unix_now_secs(),
        )?;
        self.releases.put_candidate(candidate.clone())?;
        Ok(candidate)
    }
}

/// Use case for independently rebuilding a candidate and recording a vault attestation.
pub struct RebuildRelease {
    releases: Arc<dyn ReleaseStorePort>,
    blobs: Arc<dyn BlobStorePort>,
}

impl RebuildRelease {
    /// Create the rebuild workflow with candidate storage and content-addressed blobs.
    pub fn new(releases: Arc<dyn ReleaseStorePort>, blobs: Arc<dyn BlobStorePort>) -> Self {
        Self { releases, blobs }
    }

    /// Rehash the stored source, derive its lab binary hash, and record this vault's rebuild.
    ///
    /// A source hash mismatch returns [`DomainError::MeasurementMismatch`]; the
    /// domain candidate rejects rebuilt binary hashes that differ from its expected `Hb`.
    pub fn execute(&self, release_id: &str, vault_id: &NodeId) -> Result<ReleaseCandidate, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let source = self.blobs.get(&candidate.hs)?;
        let recomputed_hs = ContentHash::from_bytes(&source);
        if recomputed_hs != candidate.hs {
            return Err(DomainError::MeasurementMismatch);
        }
        let rebuilt_hb = lab_rebuild_binary_hash(&source);
        candidate.record_rebuild(vault_id, rebuilt_hb)?;
        self.releases.save_candidate(candidate.clone())?;
        Ok(candidate)
    }
}

/// Use case for adding the local vault's cosign after release predicates pass.
pub struct CosignRelease {
    releases: Arc<dyn ReleaseStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
    local_node: NodeId,
    governance: Option<Arc<AccrueGovernanceWork>>,
}

impl CosignRelease {
    /// Create the cosign workflow for the local vault identity.
    pub fn new(
        releases: Arc<dyn ReleaseStorePort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
        local_node: NodeId,
    ) -> Self {
        Self { releases, ledger, clock, local_node, governance: None }
    }

    /// Enable optional governance reward accrual after the candidate is saved.
    pub fn with_governance(mut self, governance: Arc<AccrueGovernanceWork>) -> Self {
        self.governance = Some(governance);
        self
    }

    /// Check release predicates, add the local cosign, persist the candidate, then accrue reward.
    ///
    /// Persistence happens before optional governance accrual; an accrual failure
    /// is returned even though the cosign has already been saved.
    pub fn execute(&self, release_id: &str) -> Result<ReleaseCandidate, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let policy = self.releases.policy()?;
        let constitution = self.ledger.constitution()?;
        candidate.predicates_ok(&policy, self.clock.unix_now_secs(), &constitution.hash)?;
        candidate.add_cosign(&self.local_node)?;
        self.releases.save_candidate(candidate.clone())?;
        if let Some(gov) = &self.governance {
            gov.execute(GovernanceJobKind::ReleaseCosign, std::slice::from_ref(&self.local_node), release_id)?;
        }
        Ok(candidate)
    }
}

/// Use case for promoting a sufficiently cosigned candidate into the release allowlist.
pub struct ActivateRelease {
    releases: Arc<dyn ReleaseStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
    governance: Option<Arc<AccrueGovernanceWork>>,
}

impl ActivateRelease {
    /// Create the activation workflow with release, governance ledger, and clock ports.
    pub fn new(releases: Arc<dyn ReleaseStorePort>, ledger: Arc<dyn LedgerPort>, clock: Arc<dyn ClockPort>) -> Self {
        Self { releases, ledger, clock, governance: None }
    }

    /// Enable optional governance reward accrual for the candidate's cosigners.
    pub fn with_governance(mut self, governance: Arc<AccrueGovernanceWork>) -> Self {
        self.governance = Some(governance);
        self
    }

    /// Require release predicates and vault cosign quorum, then persist candidate and allowlist entry.
    ///
    /// Candidate state is saved before the allowlist entry, and optional reward
    /// accrual runs afterward; these port operations are not wrapped in one transaction.
    pub fn execute(&self, release_id: &str) -> Result<AllowlistEntry, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let policy = self.releases.policy()?;
        let constitution = self.ledger.constitution()?;
        candidate.predicates_ok(&policy, self.clock.unix_now_secs(), &constitution.hash)?;
        if candidate.cosigns.len() < policy.vault_cosign_quorum() {
            return Err(DomainError::QuorumNotMet {
                have: candidate.cosigns.len(),
                need: policy.vault_cosign_quorum(),
            });
        }
        let entry = AllowlistEntry {
            release_id: candidate.id.clone(),
            hs: candidate.hs.clone(),
            hb: candidate.hb.clone(),
            activated_at_secs: self.clock.unix_now_secs(),
            constitution_hash: constitution.hash,
        };
        candidate.phase = ReleasePhase::Allowlisted;
        let cosigners: Vec<NodeId> = candidate.cosigns.iter().filter_map(|id| NodeId::new(id.clone()).ok()).collect();
        self.releases.save_candidate(candidate)?;
        self.releases.put_allowlist(entry.clone())?;
        if let Some(gov) = &self.governance {
            gov.execute(GovernanceJobKind::ReleaseActivate, &cosigners, release_id)?;
        }
        Ok(entry)
    }
}

/// Query use case for listing activated releases and requiring a binary hash to be admitted.
pub struct GetAllowlist {
    releases: Arc<dyn ReleaseStorePort>,
}

impl GetAllowlist {
    /// Create the allowlist query with the release store port.
    pub fn new(releases: Arc<dyn ReleaseStorePort>) -> Self {
        Self { releases }
    }

    /// Return all currently stored allowlist entries.
    pub fn execute(&self) -> Result<Vec<AllowlistEntry>, DomainError> {
        self.releases.allowlist()
    }

    /// Succeed only when `hb` appears in the active allowlist.
    ///
    /// Returns [`DomainError::NotAllowlisted`] with the hash when no entry admits it.
    pub fn require_hb(&self, hb: &ContentHash) -> Result<(), DomainError> {
        if self.releases.is_allowlisted_hb(hb)? {
            Ok(())
        } else {
            Err(DomainError::NotAllowlisted(hb.as_str().to_string()))
        }
    }
}
