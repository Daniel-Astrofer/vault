use crate::{Constitution, DomainError, NodeId};

/// Network membership and constitution reference for one ledger epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    /// Monotonically increasing epoch number; genesis starts at zero.
    pub number: u64,
    /// Hash of the constitution that defines this epoch's rules.
    pub constitution_hash: String,
    /// Nodes admitted to the active signing set for this epoch.
    pub active_set: Vec<NodeId>,
}

impl Epoch {
    /// Validate the constitution and create epoch zero with the supplied active set.
    ///
    /// The active-set length must equal `constitution.signing_n`; this function
    /// does not independently reject duplicate node identifiers.
    pub fn genesis(constitution: &Constitution, active_set: Vec<NodeId>) -> Result<Self, DomainError> {
        constitution.validate()?;
        if active_set.len() != constitution.signing_n {
            return Err(DomainError::InvalidConstitution(format!(
                "active_set len {} != signing_n {}",
                active_set.len(),
                constitution.signing_n
            )));
        }
        Ok(Self { number: 0, constitution_hash: constitution.hash.clone(), active_set })
    }

    /// Return whether `node` is an active member of this epoch.
    pub fn contains(&self, node: &NodeId) -> bool {
        self.active_set.iter().any(|n| n == node)
    }

    /// Serialize epoch metadata to its JSON wire representation.
    ///
    /// Node identifiers and the constitution hash are interpolated directly;
    /// this method is intended for the crate's controlled domain values.
    pub fn to_json(&self) -> String {
        let set = self.active_set.iter().map(|n| format!("\"{}\"", n.as_str())).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"number":{},"constitution_hash":"{}","active_set":[{}]}}"#,
            self.number, self.constitution_hash, set
        )
    }
}

/// Event category committed to a hash-chained ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerEventKind {
    /// Initial event that establishes the ledger chain.
    Genesis,
    /// Event recording a transition to a later membership epoch.
    EpochAdvanced,
    /// Event recording a participant vote in a governance proposal.
    VoteRecorded,
    /// Quorum day_epoch advanced (constitution rotation event).
    DayAdvanced,
    /// FROST share refresh completed (group verifying key unchanged).
    ReshareCompleted,
    /// Governance job bounty accrued to miner pool (bank Intent later).
    GovernanceRewardAccrued,
    /// PROFIT allocated across MINERS / CHANNELS / INFRA credit pools.
    ProfitAllocated,
}

/// One immutable ledger record linking a domain event to its predecessor hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Zero-based position of this entry in the ledger sequence.
    pub index: u64,
    /// Network epoch in which the event was committed.
    pub epoch: u64,
    /// Semantic event category serialized with this record.
    pub kind: LedgerEventKind,
    /// Measurement digest of the event payload, not the raw payload itself.
    pub payload_hash: String,
    /// Node identity attributed as the event writer.
    pub writer: NodeId,
    /// Hash of the preceding entry, or the genesis sentinel for the first entry.
    pub prev_hash: String,
    /// Digest computed from this entry's ordered metadata and predecessor hash.
    pub entry_hash: String,
}

impl LedgerEntry {
    /// Create a hash-chained entry from its index, epoch, event, payload, writer, and predecessor.
    ///
    /// The payload itself is represented by a measurement hash. The entry hash
    /// commits to the ordered metadata and previous hash, making sequence changes
    /// detectable when the chain is independently verified.
    pub fn chain(
        index: u64,
        epoch: u64,
        kind: LedgerEventKind,
        payload: &str,
        writer: NodeId,
        prev_hash: &str,
    ) -> Self {
        let payload_hash = crate::Measurement::from_bytes(payload.as_bytes()).as_hex().to_string();
        let material = format!("{index}|{epoch}|{kind:?}|{payload_hash}|{writer}|{prev_hash}");
        let entry_hash = crate::Measurement::from_bytes(material.as_bytes()).as_hex().to_string();
        Self { index, epoch, kind, payload_hash, writer, prev_hash: prev_hash.to_string(), entry_hash }
    }

    /// Serialize entry metadata, including both payload and predecessor hashes, to JSON.
    ///
    /// This helper directly interpolates string values and is not a general
    /// JSON escaping boundary for arbitrary untrusted input.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"index":{},"epoch":{},"kind":"{}","payload_hash":"{}","writer":"{}","prev_hash":"{}","entry_hash":"{}"}}"#,
            self.index,
            self.epoch,
            kind_str(&self.kind),
            self.payload_hash,
            self.writer,
            self.prev_hash,
            self.entry_hash
        )
    }
}

/// Map an event kind to the stable wire name used in ledger JSON.
fn kind_str(k: &LedgerEventKind) -> &'static str {
    match k {
        LedgerEventKind::Genesis => "genesis",
        LedgerEventKind::EpochAdvanced => "epoch_advanced",
        LedgerEventKind::VoteRecorded => "vote_recorded",
        LedgerEventKind::DayAdvanced => "day_advanced",
        LedgerEventKind::ReshareCompleted => "reshare_completed",
        LedgerEventKind::GovernanceRewardAccrued => "governance_reward_accrued",
        LedgerEventKind::ProfitAllocated => "profit_allocated",
    }
}

/// Proposed one-step epoch transition and its collected voter identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAdvanceProposal {
    /// Stable identifier used to refer to the proposal.
    pub id: String,
    /// Epoch the proposal expects to advance from.
    pub from_epoch: u64,
    /// Target epoch, initialized to `from_epoch + 1` by [`Self::new`].
    pub to_epoch: u64,
    /// Constitution hash that the proposal binds the transition to.
    pub constitution_hash: String,
    /// Node that created the proposal and is initially included as a voter.
    pub proposer: NodeId,
    /// Distinct voter identifiers that have approved this proposal so far.
    pub votes: Vec<NodeId>,
    /// Whether the proposal has been finalized and no longer accepts votes.
    pub closed: bool,
}

impl EpochAdvanceProposal {
    /// Create an open proposal targeting the next epoch and count the proposer as its first vote.
    ///
    /// The caller is responsible for validating the proposal identifier, epoch
    /// bounds, constitution, and proposer's membership before committing it.
    pub fn new(id: String, from_epoch: u64, constitution_hash: String, proposer: NodeId) -> Self {
        Self {
            id,
            from_epoch,
            to_epoch: from_epoch + 1,
            constitution_hash,
            proposer: proposer.clone(),
            votes: vec![proposer],
            closed: false,
        }
    }

    /// Add a voter once, preserving insertion order and rejecting closed proposals.
    ///
    /// This method deduplicates voters but does not itself check that the voter
    /// belongs to the active set or that quorum has been reached.
    pub fn add_vote(&mut self, voter: NodeId) -> Result<(), DomainError> {
        if self.closed {
            return Err(DomainError::ProposalClosed(self.id.clone()));
        }
        if !self.votes.iter().any(|v| v == &voter) {
            self.votes.push(voter);
        }
        Ok(())
    }

    /// Serialize proposal metadata and its current votes to the wire JSON form.
    ///
    /// String values are interpolated directly and are expected to be controlled
    /// domain identifiers rather than arbitrary untrusted text.
    pub fn to_json(&self) -> String {
        let votes = self.votes.iter().map(|n| format!("\"{}\"", n.as_str())).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"id":"{}","from_epoch":{},"to_epoch":{},"constitution_hash":"{}","proposer":"{}","votes":[{}],"closed":{}}}"#,
            self.id, self.from_epoch, self.to_epoch, self.constitution_hash, self.proposer, votes, self.closed
        )
    }
}
