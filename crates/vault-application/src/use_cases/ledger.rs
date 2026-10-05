use std::sync::Arc;

use crate::ports::LedgerPort;
use vault_domain::{DomainError, EpochAdvanceProposal, LedgerEntry, LedgerEventKind, NodeId};

/// Use case that creates and records a proposal to advance the governance epoch.
pub struct ProposeEpochAdvance {
    ledger: Arc<dyn LedgerPort>,
    local_node: NodeId,
}

impl ProposeEpochAdvance {
    /// Creates the use case for the ledger and the node submitting proposals.
    pub fn new(ledger: Arc<dyn LedgerPort>, local_node: NodeId) -> Self {
        Self { ledger, local_node }
    }

    /// Creates a proposal for the current epoch and appends its initial vote event.
    ///
    /// The local node must belong to the active set. The proposal is stored before
    /// the ledger event is appended, so an append failure may leave the proposal
    /// persisted without its corresponding event.
    pub fn execute(&self, proposal_id: &str) -> Result<EpochAdvanceProposal, DomainError> {
        let epoch = self.ledger.epoch()?;
        if !epoch.contains(&self.local_node) {
            return Err(DomainError::UnauthorizedWriter(self.local_node.as_str().to_string()));
        }
        let constitution = self.ledger.constitution()?;
        let proposal = EpochAdvanceProposal::new(
            proposal_id.to_string(),
            epoch.number,
            constitution.hash.clone(),
            self.local_node.clone(),
        );
        self.ledger.put_proposal(proposal.clone())?;
        append_vote_event(&self.ledger, &epoch.number, &self.local_node, &proposal)?;
        Ok(proposal)
    }
}

/// Use case that records a node's vote and advances the epoch when quorum is met.
pub struct VoteEpochAdvance {
    ledger: Arc<dyn LedgerPort>,
    local_node: NodeId,
}

impl VoteEpochAdvance {
    /// Creates the voting use case for the ledger and local voter identity.
    pub fn new(ledger: Arc<dyn LedgerPort>, local_node: NodeId) -> Self {
        Self { ledger, local_node }
    }

    /// Adds the local vote after validating epoch and constitution binding.
    ///
    /// When the constitution's governance threshold is reached, closes the
    /// proposal and advances the ledger epoch. Votes and closure are saved before
    /// the epoch transition and its event are appended.
    pub fn execute(&self, proposal_id: &str) -> Result<EpochAdvanceProposal, DomainError> {
        let epoch = self.ledger.epoch()?;
        if !epoch.contains(&self.local_node) {
            return Err(DomainError::UnauthorizedWriter(self.local_node.as_str().to_string()));
        }
        let mut proposal = self.ledger.get_proposal(proposal_id)?;
        if proposal.from_epoch != epoch.number {
            return Err(DomainError::EpochMismatch { expected: epoch.number, got: proposal.from_epoch });
        }
        let constitution = self.ledger.constitution()?;
        if proposal.constitution_hash != constitution.hash {
            return Err(DomainError::LedgerConflict("proposal constitution hash diverges from active".into()));
        }
        proposal.add_vote(self.local_node.clone())?;
        self.ledger.save_proposal(proposal.clone())?;
        append_vote_event(&self.ledger, &epoch.number, &self.local_node, &proposal)?;

        let need = constitution.governance_t;
        let have = proposal.votes.len();
        if have >= need {
            proposal.closed = true;
            self.ledger.save_proposal(proposal.clone())?;
            self.advance_epoch(&proposal)?;
        }
        Ok(proposal)
    }

    /// Updates the epoch state and appends its hash-chained advance event.
    fn advance_epoch(&self, proposal: &EpochAdvanceProposal) -> Result<(), DomainError> {
        let mut epoch = self.ledger.epoch()?;
        epoch.number = proposal.to_epoch;
        self.ledger.set_epoch(epoch)?;
        let prev = self.ledger.head()?.map(|e| e.entry_hash).unwrap_or_else(|| "genesis-prev".into());
        let next_index = self.ledger.entries()?.len() as u64;
        let entry = LedgerEntry::chain(
            next_index,
            proposal.to_epoch,
            LedgerEventKind::EpochAdvanced,
            &format!(r#"{{"to_epoch":{},"constitution_hash":"{}"}}"#, proposal.to_epoch, proposal.constitution_hash),
            self.local_node.clone(),
            &prev,
        );
        self.ledger.append(entry)?;
        Ok(())
    }
}

fn append_vote_event(
    ledger: &Arc<dyn LedgerPort>,
    epoch_number: &u64,
    writer: &NodeId,
    proposal: &EpochAdvanceProposal,
) -> Result<(), DomainError> {
    let prev = ledger.head()?.map(|e| e.entry_hash).unwrap_or_else(|| "genesis-prev".into());
    let next_index = ledger.entries()?.len() as u64;
    let entry = LedgerEntry::chain(
        next_index,
        *epoch_number,
        LedgerEventKind::VoteRecorded,
        &proposal.to_json(),
        writer.clone(),
        &prev,
    );
    ledger.append(entry)
}

/// Read-only use case that collects the constitution, epoch, and ledger entries.
pub struct GetLedgerSnapshot {
    ledger: Arc<dyn LedgerPort>,
}

impl GetLedgerSnapshot {
    /// Creates the snapshot query for the supplied ledger port.
    pub fn new(ledger: Arc<dyn LedgerPort>) -> Self {
        Self { ledger }
    }

    /// Reads the current ledger data into a serializable snapshot value.
    pub fn execute(&self) -> Result<LedgerSnapshot, DomainError> {
        Ok(LedgerSnapshot {
            constitution_json: self.ledger.constitution()?.to_json(),
            epoch_json: self.ledger.epoch()?.to_json(),
            entries: self.ledger.entries()?,
        })
    }
}

#[derive(Debug, Clone)]
/// Serialized ledger components returned by [`GetLedgerSnapshot`].
pub struct LedgerSnapshot {
    /// Constitution JSON produced by the domain type.
    pub constitution_json: String,
    /// Epoch JSON produced by the domain type.
    pub epoch_json: String,
    /// Ordered ledger entries returned by the persistence port.
    pub entries: Vec<vault_domain::LedgerEntry>,
}

impl LedgerSnapshot {
    /// Encodes this snapshot as a JSON object containing constitution, epoch, and entries.
    pub fn to_json(&self) -> String {
        let entries = self.entries.iter().map(|e| e.to_json()).collect::<Vec<_>>().join(",");
        format!(r#"{{"constitution":{},"epoch":{},"entries":[{}]}}"#, self.constitution_json, self.epoch_json, entries)
    }
}
