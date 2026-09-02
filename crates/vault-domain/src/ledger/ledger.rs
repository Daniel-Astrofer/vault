use crate::{Constitution, DomainError, NodeId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    pub number: u64,
    pub constitution_hash: String,
    pub active_set: Vec<NodeId>,
}

impl Epoch {
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

    pub fn contains(&self, node: &NodeId) -> bool {
        self.active_set.iter().any(|n| n == node)
    }

    pub fn to_json(&self) -> String {
        let set = self.active_set.iter().map(|n| format!("\"{}\"", n.as_str())).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"number":{},"constitution_hash":"{}","active_set":[{}]}}"#,
            self.number, self.constitution_hash, set
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerEventKind {
    Genesis,
    EpochAdvanced,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub index: u64,
    pub epoch: u64,
    pub kind: LedgerEventKind,
    pub payload_hash: String,
    pub writer: NodeId,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl LedgerEntry {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAdvanceProposal {
    pub id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub constitution_hash: String,
    pub proposer: NodeId,
    pub votes: Vec<NodeId>,
    pub closed: bool,
}

impl EpochAdvanceProposal {
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

    pub fn add_vote(&mut self, voter: NodeId) -> Result<(), DomainError> {
        if self.closed {
            return Err(DomainError::ProposalClosed(self.id.clone()));
        }
        if !self.votes.iter().any(|v| v == &voter) {
            self.votes.push(voter);
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let votes = self.votes.iter().map(|n| format!("\"{}\"", n.as_str())).collect::<Vec<_>>().join(",");
        format!(
            r#"{{"id":"{}","from_epoch":{},"to_epoch":{},"constitution_hash":"{}","proposer":"{}","votes":[{}],"closed":{}}}"#,
            self.id, self.from_epoch, self.to_epoch, self.constitution_hash, self.proposer, votes, self.closed
        )
    }
}
