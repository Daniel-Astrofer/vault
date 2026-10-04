use std::collections::HashMap;
use std::sync::Mutex;

use crate::application::LedgerPort;
use crate::domain::{Constitution, DomainError, Epoch, EpochAdvanceProposal, LedgerEntry, LedgerEventKind, NodeId};

struct LedgerState {
    constitution: Constitution,
    epoch: Epoch,
    entries: Vec<LedgerEntry>,
    proposals: HashMap<String, EpochAdvanceProposal>,
}

/// Mutex-protected, non-persistent implementation of the ledger port.
pub struct InMemoryLedger {
    state: Mutex<LedgerState>,
}

impl InMemoryLedger {
    /// Creates an in-memory ledger with a validated constitution and genesis entry.
    ///
    /// The supplied writer must be part of the epoch active set for later appends.
    pub fn genesis(constitution: Constitution, active_set: Vec<NodeId>, writer: NodeId) -> Result<Self, DomainError> {
        constitution.validate()?;
        let epoch = Epoch::genesis(&constitution, active_set)?;
        let genesis_payload = format!(r#"{{"constitution":{},"epoch":{}}}"#, constitution.to_json(), epoch.to_json());
        let entry = LedgerEntry::chain(0, 0, LedgerEventKind::Genesis, &genesis_payload, writer, "genesis-prev");
        Ok(Self {
            state: Mutex::new(LedgerState { constitution, epoch, entries: vec![entry], proposals: HashMap::new() }),
        })
    }
}

impl LedgerPort for InMemoryLedger {
    /// Returns a clone of the ledger constitution.
    fn constitution(&self) -> Result<Constitution, DomainError> {
        Ok(self.state.lock().expect("ledger").constitution.clone())
    }

    /// Returns a clone of the current epoch state.
    fn epoch(&self) -> Result<Epoch, DomainError> {
        Ok(self.state.lock().expect("ledger").epoch.clone())
    }

    /// Replaces the current epoch state in memory.
    fn set_epoch(&self, epoch: Epoch) -> Result<(), DomainError> {
        self.state.lock().expect("ledger").epoch = epoch;
        Ok(())
    }

    /// Returns the current chain head, if the ledger has any entries.
    fn head(&self) -> Result<Option<LedgerEntry>, DomainError> {
        Ok(self.state.lock().expect("ledger").entries.last().cloned())
    }

    /// Returns a cloned snapshot of all ledger entries.
    fn entries(&self) -> Result<Vec<LedgerEntry>, DomainError> {
        Ok(self.state.lock().expect("ledger").entries.clone())
    }

    /// Appends an entry after validating index, previous hash, and active-set writer.
    fn append(&self, entry: LedgerEntry) -> Result<(), DomainError> {
        let mut guard = self.state.lock().expect("ledger");
        if let Some(prev) = guard.entries.last() {
            if entry.index != prev.index + 1 {
                return Err(DomainError::LedgerConflict(format!(
                    "expected index {}, got {}",
                    prev.index + 1,
                    entry.index
                )));
            }
            if entry.prev_hash != prev.entry_hash {
                return Err(DomainError::LedgerConflict("prev_hash does not match head".into()));
            }
        } else if entry.index != 0 {
            return Err(DomainError::LedgerConflict("first entry must be index 0".into()));
        }
        // Only active-set writers may append.
        if !guard.epoch.contains(&entry.writer) {
            return Err(DomainError::UnauthorizedWriter(entry.writer.as_str().to_string()));
        }
        guard.entries.push(entry);
        Ok(())
    }

    /// Inserts a proposal, rejecting an ID that already exists.
    fn put_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError> {
        let mut guard = self.state.lock().expect("ledger");
        if guard.proposals.contains_key(&proposal.id) {
            return Err(DomainError::LedgerConflict(format!("proposal {} exists", proposal.id)));
        }
        guard.proposals.insert(proposal.id.clone(), proposal);
        Ok(())
    }

    /// Returns the proposal with this ID or an unknown-proposal error.
    fn get_proposal(&self, id: &str) -> Result<EpochAdvanceProposal, DomainError> {
        self.state
            .lock()
            .expect("ledger")
            .proposals
            .get(id)
            .cloned()
            .ok_or_else(|| DomainError::UnknownProposal(id.to_string()))
    }

    /// Inserts or replaces the proposal under its ID.
    fn save_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError> {
        let mut guard = self.state.lock().expect("ledger");
        guard.proposals.insert(proposal.id.clone(), proposal);
        Ok(())
    }
}
