//! Miner economy use cases (F9): accrue p%, governance job bounty, propose bank-issued MINERS Intents.

//! Application workflows for miner pools, governance rewards, and payout proposals.
//!
//! These use cases coordinate domain policies with ports; actual payout execution
//! remains with the bank, and ledger entries record the resulting accounting events.

use std::sync::Arc;

use crate::ports::{ClockPort, EconomyPort, LedgerPort};
use vault_domain::{
    assert_bank_issued_miner_payout, AttestationMode, DomainError, EconomyState, GovernanceAccrual, GovernanceJobKind,
    GovernanceRewardConfig, LedgerEntry, LedgerEventKind, MinerOperator, MinerPayoutCadence, MinerPayoutShare, NodeId,
    SettlementIntent, VaultNodeTier,
};

/// Query object that assembles economy, constitution, and node trust information.
pub struct GetEconomyStatus {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
    governance_reward: GovernanceRewardConfig,
    payout_cadence: MinerPayoutCadence,
    node_tier: VaultNodeTier,
    attestation_mode: AttestationMode,
    tee_available: bool,
}

impl GetEconomyStatus {
    /// Create the status query with its repositories and node-local trust metadata.
    pub fn new(
        economy: Arc<dyn EconomyPort>,
        ledger: Arc<dyn LedgerPort>,
        governance_reward: GovernanceRewardConfig,
        payout_cadence: MinerPayoutCadence,
        node_tier: VaultNodeTier,
        attestation_mode: AttestationMode,
        tee_available: bool,
    ) -> Self {
        Self { economy, ledger, governance_reward, payout_cadence, node_tier, attestation_mode, tee_available }
    }

    /// Read the current pools and policy into a presentation view.
    ///
    /// The `online` participant count is currently modeled as the constitution's
    /// signing set size (lab assumption), not measured live peer reachability.
    pub fn execute(&self) -> Result<EconomyStatusView, DomainError> {
        let constitution = self.ledger.constitution()?;
        let eco = self.economy.snapshot()?;
        let eligible = eco.eligible_active().len();
        let waiting = eco.operators.values().filter(|o| o.waiting).count();
        let online = constitution.signing_n; // lab: assume genesis set size
        let survivability_ok = eco.survivability_ok(online, constitution.signing_t);
        Ok(EconomyStatusView {
            miner_pool_sats: eco.miner_pool_sats,
            channels_pool_sats: eco.channels_pool_sats,
            infra_pool_sats: eco.infra_pool_sats,
            accrued_profit_sats: eco.accrued_profit_sats,
            pending_governance_reward_sats: eco.pending_governance_reward_sats,
            governance_reward_sats: self.governance_reward.reward_sats,
            governance_reward_bps: self.governance_reward.reward_bps_of_pool,
            p_reward_bps: constitution.p_reward_bps,
            channels_bps: constitution.profit_splits.channels_bps,
            infra_bps: constitution.profit_splits.infra_bps,
            miner_payout_cadence: self.payout_cadence.as_str().to_string(),
            last_miner_payout_at_secs: eco.last_miner_payout_at_secs,
            eligible_miners: eligible,
            waiting_miners: waiting,
            crypto_suite_id: constitution.crypto_suite_id,
            crypto_suite_id_pq: eco.crypto_suite_id_pq,
            survivability_ok,
            open_economy: constitution.profit_splits.miners_bps > 0,
            node_tier: self.node_tier.as_str().to_string(),
            attestation_mode: self.attestation_mode.as_str().to_string(),
            tee_available: self.tee_available,
            tier_governance_weight_bps: self.node_tier.governance_weight_bps(),
        })
    }
}

/// API view of economy pools, payout configuration, operator counts, and trust status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomyStatusView {
    /// Current miner payout pool balance, in satoshis.
    pub miner_pool_sats: u64,
    /// Current channel operations pool balance, in satoshis.
    pub channels_pool_sats: u64,
    /// Current infrastructure pool balance, in satoshis.
    pub infra_pool_sats: u64,
    /// Cumulative profit accrued across pools, in satoshis.
    pub accrued_profit_sats: u64,
    /// Governance bounty amount accrued but not yet settled by bank intent.
    pub pending_governance_reward_sats: u64,
    /// Fixed configured governance bounty, in satoshis.
    pub governance_reward_sats: u64,
    /// Pool-proportional governance bounty, in basis points.
    pub governance_reward_bps: u32,
    /// Constitution's miner reward share, in basis points.
    pub p_reward_bps: u32,
    /// Constitution's channel allocation share, in basis points.
    pub channels_bps: u32,
    /// Constitution's infrastructure allocation share, in basis points.
    pub infra_bps: u32,
    /// Canonical name of the configured miner payout cadence.
    pub miner_payout_cadence: String,
    /// Timestamp of the last payout, absent when no payout has been recorded.
    pub last_miner_payout_at_secs: Option<u64>,
    /// Number of operators currently eligible for active payouts.
    pub eligible_miners: usize,
    /// Number of registered operators marked as waiting.
    pub waiting_miners: usize,
    /// Active classical/hybrid crypto suite identifier from the constitution.
    pub crypto_suite_id: String,
    /// Optional post-quantum suite identifier tracked by economy state.
    pub crypto_suite_id_pq: String,
    /// Whether the modeled online count meets the signing survivability threshold.
    pub survivability_ok: bool,
    /// Whether the profit split allocates a nonzero share to miners.
    pub open_economy: bool,
    /// Canonical node hardware/trust tier label.
    pub node_tier: String,
    /// Canonical platform attestation mode label.
    pub attestation_mode: String,
    /// Whether local hardware reports TEE availability.
    pub tee_available: bool,
    /// Informational governance weight for the node tier, in basis points.
    pub tier_governance_weight_bps: u32,
}

impl EconomyStatusView {
    /// Serialize the view to the current JSON API representation.
    ///
    /// An absent last-payout timestamp is encoded as JSON `null`.
    pub fn to_json(&self) -> String {
        let last = self.last_miner_payout_at_secs.map(|n| n.to_string()).unwrap_or_else(|| "null".into());
        format!(
            r#"{{"miner_pool_sats":{},"channels_pool_sats":{},"infra_pool_sats":{},"accrued_profit_sats":{},"pending_governance_reward_sats":{},"governance_reward_sats":{},"governance_reward_bps":{},"p_reward_bps":{},"channels_bps":{},"infra_bps":{},"miner_payout_cadence":"{}","last_miner_payout_at_secs":{},"eligible_miners":{},"waiting_miners":{},"crypto_suite_id":"{}","crypto_suite_id_pq":"{}","survivability_ok":{},"open_economy":{},"node_tier":"{}","attestation_mode":"{}","tee_available":{},"tier_governance_weight_bps":{}}}"#,
            self.miner_pool_sats,
            self.channels_pool_sats,
            self.infra_pool_sats,
            self.accrued_profit_sats,
            self.pending_governance_reward_sats,
            self.governance_reward_sats,
            self.governance_reward_bps,
            self.p_reward_bps,
            self.channels_bps,
            self.infra_bps,
            self.miner_payout_cadence,
            last,
            self.eligible_miners,
            self.waiting_miners,
            self.crypto_suite_id,
            self.crypto_suite_id_pq,
            self.survivability_ok,
            self.open_economy,
            self.node_tier,
            self.attestation_mode,
            self.tee_available,
            self.tier_governance_weight_bps
        )
    }
}

/// Use case for registering or updating a miner operator.
pub struct UpsertMiner {
    economy: Arc<dyn EconomyPort>,
}

impl UpsertMiner {
    /// Create the use case with the economy persistence port.
    pub fn new(economy: Arc<dyn EconomyPort>) -> Self {
        Self { economy }
    }

    /// Store the operator record used for eligibility and payout destination checks.
    pub fn execute(&self, op: MinerOperator) -> Result<(), DomainError> {
        self.economy.upsert_operator(op)
    }
}

/// Use case that allocates incoming profit and records a chained ledger event.
pub struct AccrueMinerRewards {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
    writer: NodeId,
}

impl AccrueMinerRewards {
    /// Create the accrual workflow with economy and ledger ports and the event writer.
    pub fn new(economy: Arc<dyn EconomyPort>, ledger: Arc<dyn LedgerPort>, writer: NodeId) -> Self {
        Self { economy, ledger, writer }
    }

    /// Allocate profit using the active constitution, then append a `ProfitAllocated` ledger entry.
    ///
    /// The operation returns an error if constitution lookup, pool accrual, ledger
    /// reads, or append fail. Pool mutation occurs before ledger append.
    pub fn execute(&self, profit_sats: u64) -> Result<AccrueReceipt, DomainError> {
        let constitution = self.ledger.constitution()?;
        let split = self.economy.accrue_profit_splits(profit_sats, &constitution.profit_splits)?;
        let eco = self.economy.snapshot()?;

        let payload = format!(
            r#"{{"profit_sats":{},"miners_sats":{},"channels_sats":{},"infra_sats":{},"miners_bps":{},"channels_bps":{},"infra_bps":{}}}"#,
            split.profit_sats,
            split.miners_sats,
            split.channels_sats,
            split.infra_sats,
            constitution.profit_splits.miners_bps,
            constitution.profit_splits.channels_bps,
            constitution.profit_splits.infra_bps
        );
        let epoch = self.ledger.epoch()?.number;
        let prev = self.ledger.head()?.map(|e| e.entry_hash).unwrap_or_else(|| "genesis-prev".into());
        let next_index = self.ledger.entries()?.len() as u64;
        let entry = LedgerEntry::chain(
            next_index,
            epoch,
            LedgerEventKind::ProfitAllocated,
            &payload,
            self.writer.clone(),
            &prev,
        );
        self.ledger.append(entry)?;

        Ok(AccrueReceipt {
            profit_sats,
            accrued_to_pool_sats: split.miners_sats,
            channels_sats: split.channels_sats,
            infra_sats: split.infra_sats,
            miner_pool_sats: eco.miner_pool_sats,
            channels_pool_sats: eco.channels_pool_sats,
            infra_pool_sats: eco.infra_pool_sats,
            p_reward_bps: constitution.p_reward_bps,
        })
    }
}

/// Result of profit allocation, including the updated pool balances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccrueReceipt {
    /// Gross profit allocated by this operation, in satoshis.
    pub profit_sats: u64,
    /// Amount credited to the miner pool, in satoshis.
    pub accrued_to_pool_sats: u64,
    /// Amount allocated to channel operations, in satoshis.
    pub channels_sats: u64,
    /// Amount allocated to infrastructure, in satoshis.
    pub infra_sats: u64,
    /// Resulting miner pool balance, in satoshis.
    pub miner_pool_sats: u64,
    /// Resulting channels pool balance, in satoshis.
    pub channels_pool_sats: u64,
    /// Resulting infrastructure pool balance, in satoshis.
    pub infra_pool_sats: u64,
    /// Miner reward percentage from the active constitution, in basis points.
    pub p_reward_bps: u32,
}

impl AccrueReceipt {
    /// Serialize the accounting result to its current JSON response representation.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"profit_sats":{},"accrued_to_pool_sats":{},"channels_sats":{},"infra_sats":{},"miner_pool_sats":{},"channels_pool_sats":{},"infra_pool_sats":{},"p_reward_bps":{}}}"#,
            self.profit_sats,
            self.accrued_to_pool_sats,
            self.channels_sats,
            self.infra_sats,
            self.miner_pool_sats,
            self.channels_pool_sats,
            self.infra_pool_sats,
            self.p_reward_bps
        )
    }
}

/// Accrue governance job bounty + append ledger `governance_reward_accrued`.
pub struct AccrueGovernanceWork {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
    writer: NodeId,
    config: GovernanceRewardConfig,
}

impl AccrueGovernanceWork {
    /// Create the governance-reward workflow with repositories, event writer, and bounty policy.
    pub fn new(
        economy: Arc<dyn EconomyPort>,
        ledger: Arc<dyn LedgerPort>,
        writer: NodeId,
        config: GovernanceRewardConfig,
    ) -> Self {
        Self { economy, ledger, writer, config }
    }

    /// Return the immutable bounty configuration used by this use case.
    pub fn config(&self) -> GovernanceRewardConfig {
        self.config
    }

    /// Accrue a bounty for eligible participants and append the accounting ledger event.
    ///
    /// Disabled reward configuration returns a zero accrual without touching the
    /// ledger. Otherwise, the ledger append is skipped when the calculated bounty
    /// and amount accrued to the pool are both zero.
    pub fn execute(
        &self,
        job: GovernanceJobKind,
        participants: &[NodeId],
        context: &str,
    ) -> Result<GovernanceAccrual, DomainError> {
        if !self.config.is_enabled() {
            return Ok(GovernanceAccrual {
                job,
                bounty_sats: 0,
                accrued_to_pool_sats: 0,
                credited: Vec::new(),
                participants: participants.to_vec(),
                eligible_credited: 0,
            });
        }
        let accrual = self.economy.accrue_governance_job(job, participants, &self.config)?;
        if accrual.accrued_to_pool_sats == 0 && accrual.bounty_sats == 0 {
            return Ok(accrual);
        }

        let credited = accrual
            .credited
            .iter()
            .map(|(id, sats)| format!(r#"{{"node_id":"{}","sats":{}}}"#, id.as_str(), sats))
            .collect::<Vec<_>>()
            .join(",");
        let parts = accrual.participants.iter().map(|id| format!("\"{}\"", id.as_str())).collect::<Vec<_>>().join(",");
        let payload = format!(
            r#"{{"job":"{}","context":"{}","bounty_sats":{},"accrued_to_pool_sats":{},"eligible_credited":{},"participants":[{}],"credited":[{}]}}"#,
            job.as_str(),
            escape_json(context),
            accrual.bounty_sats,
            accrual.accrued_to_pool_sats,
            accrual.eligible_credited,
            parts,
            credited
        );
        let epoch = self.ledger.epoch()?.number;
        let prev = self.ledger.head()?.map(|e| e.entry_hash).unwrap_or_else(|| "genesis-prev".into());
        let next_index = self.ledger.entries()?.len() as u64;
        let entry = LedgerEntry::chain(
            next_index,
            epoch,
            LedgerEventKind::GovernanceRewardAccrued,
            &payload,
            self.writer.clone(),
            &prev,
        );
        self.ledger.append(entry)?;
        Ok(accrual)
    }
}

/// Escape backslashes and quotes for the manually assembled governance event payload.
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Propose equal MINERS Intents for the bank to submit — vaults do not broadcast payouts.
/// Use case for reserving miner-pool funds and producing bank-issued payout intents.
pub struct ProposeMinerPayouts {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
    payout_cadence: MinerPayoutCadence,
}

impl ProposeMinerPayouts {
    /// Create the proposal workflow with economy, ledger, clock, and cadence dependencies.
    pub fn new(
        economy: Arc<dyn EconomyPort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
        payout_cadence: MinerPayoutCadence,
    ) -> Self {
        Self { economy, ledger, clock, payout_cadence }
    }

    /// Divide `amount` among eligible miners, build MINERS intents, and debit the pool.
    ///
    /// The cadence is checked before generating intents. Each destination must
    /// still match an eligible registered operator. The returned intents are
    /// proposals for the bank to submit; this use case does not broadcast payments.
    pub fn execute(&self, amount: u64, intent_prefix: &str) -> Result<PayoutProposal, DomainError> {
        let constitution = self.ledger.constitution()?;
        let now = self.clock.unix_now_secs();
        self.economy.snapshot()?.assert_payout_cadence_ok(self.payout_cadence, now, None)?;
        let shares = self.economy.propose_equal_payouts(amount)?;
        let mut intents = Vec::with_capacity(shares.len());
        for (i, share) in shares.iter().enumerate() {
            let id = format!("{intent_prefix}-{i}-{}", share.node_id.as_str());
            let intent = share.to_intent(id, constitution.hash.clone())?;
            assert_bank_issued_miner_payout(&self.economy.snapshot()?, &intent)?;
            intents.push(intent);
        }
        self.economy.debit_pool(amount)?;
        self.economy.record_miner_payout(now, None)?;
        Ok(PayoutProposal { total_sats: amount, shares, intents })
    }
}

/// Bank-submittable payout intents and their aggregate amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutProposal {
    /// Sum of the per-miner allocations, in satoshis.
    pub total_sats: u64,
    /// Per-operator amounts and registered destinations used to build the intents.
    pub shares: Vec<MinerPayoutShare>,
    /// Settlement intents for the bank to submit on behalf of the miners.
    pub intents: Vec<SettlementIntent>,
}

impl PayoutProposal {
    /// Serialize the aggregate amount and intent details into the current JSON response.
    pub fn to_json(&self) -> String {
        let parts: Vec<String> = self
            .intents
            .iter()
            .map(|i| {
                format!(
                    r#"{{"intent_id":"{}","destination":"{}","amount_sats":{}}}"#,
                    i.intent_id, i.destination, i.amount_sats
                )
            })
            .collect();
        format!(
            r#"{{"total_sats":{},"intent_count":{},"intents":[{}]}}"#,
            self.total_sats,
            self.intents.len(),
            parts.join(",")
        )
    }
}

/// Serialize economy balances, operator eligibility, and governance credits to JSON.
///
/// The operator objects expose eligibility and reward metrics but not payout
/// destinations. Identifiers are interpolated directly by the current formatter.
pub fn economy_snapshot_json(eco: &EconomyState) -> String {
    let ops: Vec<String> = eco
        .operators
        .values()
        .map(|o| {
            format!(
                r#"{{"node_id":"{}","waiting":{},"eligible":{},"uptime_bps_30d":{},"streak":{},"governance_credits":{}}}"#,
                o.node_id.as_str(),
                o.waiting,
                o.is_eligible(&eco.policy),
                o.uptime_bps_30d,
                o.attestation_streak_days,
                eco.governance_credits
                    .get(o.node_id.as_str())
                    .copied()
                    .unwrap_or(0)
            )
        })
        .collect();
    format!(
        r#"{{"miner_pool_sats":{},"channels_pool_sats":{},"infra_pool_sats":{},"pending_governance_reward_sats":{},"operators":[{}],"crypto_suite_id_pq":"{}"}}"#,
        eco.miner_pool_sats,
        eco.channels_pool_sats,
        eco.infra_pool_sats,
        eco.pending_governance_reward_sats,
        ops.join(","),
        eco.crypto_suite_id_pq
    )
}

/// Returns true if the given day_epoch is a payout epoch under this frequency.
///
/// - Daily: always true
/// - Weekly: every 7th day (epoch % 7 == 0)
/// - Epoch: true on exact epoch match (caller provides last epoch + 1)
/// - Manual: always false (operator-gated)
pub fn is_payout_epoch(frequency: MinerPayoutCadence, day_epoch: u64) -> bool {
    match frequency {
        MinerPayoutCadence::Manual => false,
        MinerPayoutCadence::Daily => true,
        MinerPayoutCadence::Weekly => day_epoch.is_multiple_of(7),
        MinerPayoutCadence::Epoch => false, // epoch payout gated by explicit epoch-based governance trigger
    }
}

#[cfg(test)]
mod payout_epoch_tests {
    use super::*;

    #[test]
    fn daily_always_payout() {
        assert!(is_payout_epoch(MinerPayoutCadence::Daily, 0));
        assert!(is_payout_epoch(MinerPayoutCadence::Daily, 100));
        assert!(is_payout_epoch(MinerPayoutCadence::Daily, 999));
    }

    #[test]
    fn weekly_payout_on_every_7th() {
        assert!(is_payout_epoch(MinerPayoutCadence::Weekly, 0));
        assert!(is_payout_epoch(MinerPayoutCadence::Weekly, 7));
        assert!(is_payout_epoch(MinerPayoutCadence::Weekly, 14));
        assert!(!is_payout_epoch(MinerPayoutCadence::Weekly, 1));
        assert!(!is_payout_epoch(MinerPayoutCadence::Weekly, 6));
        assert!(!is_payout_epoch(MinerPayoutCadence::Weekly, 8));
    }

    #[test]
    fn manual_never_payout() {
        assert!(!is_payout_epoch(MinerPayoutCadence::Manual, 0));
        assert!(!is_payout_epoch(MinerPayoutCadence::Manual, 100));
    }

    #[test]
    fn epoch_payout_gated_by_governance() {
        assert!(!is_payout_epoch(MinerPayoutCadence::Epoch, 0));
        assert!(!is_payout_epoch(MinerPayoutCadence::Epoch, 100));
    }
}
