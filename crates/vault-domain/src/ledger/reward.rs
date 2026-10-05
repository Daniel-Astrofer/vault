//! Miner rewards, waiting set, and eligibility (F9).
//! Payouts are bank-issued Intents from MINERS — vaults never self-pay.
//! Governance jobs (day rotation / reshare / release cosign) accrue into the same pool.

use std::collections::BTreeMap;

use crate::{BucketKind, DomainError, NodeId, ProfitSplits, SettlementIntent};

/// Miner payout cadence gate (`VAULT_MINER_PAYOUT_CADENCE`).
/// Non-manual values only enforce spacing between proposes — **no auto scheduler**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerPayoutCadence {
    /// No time-based restriction is applied to payout proposals.
    Manual,
    /// Require at least 86,400 seconds since the previous payout.
    Daily,
    /// Require at least seven days since the previous payout.
    Weekly,
    /// Require the current epoch to be greater than the previous payout epoch.
    Epoch,
}

impl MinerPayoutCadence {
    /// Parse a cadence name case-insensitively after trimming surrounding whitespace.
    ///
    /// Returns `None` for values outside `manual`, `daily`, `weekly`, and `epoch`.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "manual" => Some(Self::Manual),
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            "epoch" => Some(Self::Epoch),
            _ => None,
        }
    }

    /// Return the canonical lowercase configuration value for this cadence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Epoch => "epoch",
        }
    }
}

/// Eligibility thresholds and waiting-set allocation rules for miner rewards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardPolicy {
    /// Minimum 30d uptime in bps (9500 = 95%).
    pub min_uptime_bps_30d: u32,
    /// Minimum consecutive daily attestation days.
    pub min_attestation_streak_days: u32,
    /// Minimum bond (sats) to leave waiting set / stay eligible.
    pub min_bond_sats: u64,
    /// Waiting-set share of pool (0 = waiting does not dilute active pool).
    pub waiting_pool_share_bps: u32,
}

impl RewardPolicy {
    /// Return the initial open-set policy: 95% 30-day uptime, one attestation day,
    /// no minimum bond, and no waiting-set share of the reward pool.
    pub fn v1_open() -> Self {
        Self {
            min_uptime_bps_30d: 9_500,
            min_attestation_streak_days: 1,
            min_bond_sats: 0, // permissioned early; raise when opening set
            waiting_pool_share_bps: 0,
        }
    }
}

/// Governance work that earns the same spirit of miner rewards as profit share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceJobKind {
    /// Advancing the network's day epoch.
    DayAdvanced,
    /// Completing a distributed key resharing operation.
    ReshareCompleted,
    /// Participating in a release cosign operation.
    ReleaseCosign,
    /// Activating a previously approved release.
    ReleaseActivate,
}

impl GovernanceJobKind {
    /// Return the stable snake-case identifier used in persisted/reporting data.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DayAdvanced => "day_advanced",
            Self::ReshareCompleted => "reshare_completed",
            Self::ReleaseCosign => "release_cosign",
            Self::ReleaseActivate => "release_activate",
        }
    }
}

/// Fixed sats and/or bps-of-current-pool bounty for a governance job.
/// Env: `VAULT_GOVERNANCE_REWARD_SATS`, `VAULT_GOVERNANCE_REWARD_BPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceRewardConfig {
    /// Fixed bounty component, denominated in satoshis.
    pub reward_sats: u64,
    /// Additional bounty as basis points of the miner pool before accrual.
    pub reward_bps_of_pool: u32,
}

impl GovernanceRewardConfig {
    /// Create a configuration with both fixed and pool-proportional rewards disabled.
    pub fn disabled() -> Self {
        Self { reward_sats: 0, reward_bps_of_pool: 0 }
    }

    /// Return whether either bounty component can produce a nonzero reward.
    pub fn is_enabled(self) -> bool {
        self.reward_sats > 0 || self.reward_bps_of_pool > 0
    }

    /// Calculate the fixed bounty plus its basis-point share of the supplied pool.
    ///
    /// Arithmetic saturates on overflow; basis points use 10,000 as 100%.
    pub fn bounty_sats(self, current_pool_sats: u64) -> u64 {
        let from_bps = current_pool_sats.saturating_mul(self.reward_bps_of_pool as u64) / 10_000;
        self.reward_sats.saturating_add(from_bps)
    }
}

/// Registered operator metrics and destination used for miner reward eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerOperator {
    /// Stable identity of the operator in network membership.
    pub node_id: NodeId,
    /// Registered destination to which the bank may issue miner payout intents.
    pub payout_destination: String,
    /// Measured uptime over the preceding 30 days, expressed in basis points.
    pub uptime_bps_30d: u32,
    /// Number of consecutive days with a valid daily attestation.
    pub attestation_streak_days: u32,
    /// Operator bond held in satoshis.
    pub bond_sats: u64,
    /// Whether the operator is in the waiting set and excluded from active rewards.
    pub waiting: bool,
}

impl MinerOperator {
    /// Check active-set eligibility against uptime, attestation, bond, and destination policy.
    ///
    /// Waiting operators and operators with a blank destination are always ineligible.
    pub fn is_eligible(&self, policy: &RewardPolicy) -> bool {
        if self.waiting {
            return false;
        }
        self.uptime_bps_30d >= policy.min_uptime_bps_30d
            && self.attestation_streak_days >= policy.min_attestation_streak_days
            && self.bond_sats >= policy.min_bond_sats
            && !self.payout_destination.trim().is_empty()
    }
}

/// In-memory accounting state for operator eligibility, pools, credits, and payout cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomyState {
    /// Eligibility thresholds applied to registered operators.
    pub policy: RewardPolicy,
    /// Operators keyed by their canonical node identifier string.
    pub operators: BTreeMap<String, MinerOperator>,
    /// Miner rewards available for payout, in satoshis.
    pub miner_pool_sats: u64,
    /// Profit allocated to channel incentives, in satoshis.
    pub channels_pool_sats: u64,
    /// Profit allocated to infrastructure, in satoshis.
    pub infra_pool_sats: u64,
    /// Cumulative profit recorded by this economy state, in satoshis.
    pub accrued_profit_sats: u64,
    /// Governance job bounty still sitting in the miner pool (pending bank Intent).
    pub pending_governance_reward_sats: u64,
    /// Lifetime governance credits per operator (eligibility / audit hook).
    pub governance_credits: BTreeMap<String, u64>,
    /// Optional PQ suite alongside classical (dual-stack placeholder).
    pub crypto_suite_id_pq: String,
    /// Unix timestamp of the last recorded miner payout, when one exists.
    pub last_miner_payout_at_secs: Option<u64>,
    /// Epoch of the last recorded payout, when epoch cadence was used.
    pub last_miner_payout_epoch: Option<u64>,
}

/// Accounting result for a governance job bounty and participant credit allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceAccrual {
    /// Governance operation that earned the bounty.
    pub job: GovernanceJobKind,
    /// Total configured bounty calculated for this operation.
    pub bounty_sats: u64,
    /// Amount added to the miner pool for later bank-issued payout.
    pub accrued_to_pool_sats: u64,
    /// Per-operator lifetime credit increments applied for eligible participants.
    pub credited: Vec<(NodeId, u64)>,
    /// Deduplicated participant list supplied to the accrual operation.
    pub participants: Vec<NodeId>,
    /// Number of participants that met the active operator policy.
    pub eligible_credited: usize,
}

/// Result of allocating profit across MINERS / CHANNELS / INFRA pools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitSplitAccrual {
    /// Total incoming profit distributed by this operation, in satoshis.
    pub profit_sats: u64,
    /// Amount allocated to MINERS, in satoshis.
    pub miners_sats: u64,
    /// Amount allocated to CHANNELS, in satoshis.
    pub channels_sats: u64,
    /// Amount allocated to INFRA, in satoshis.
    pub infra_sats: u64,
}

impl EconomyState {
    /// Initialize empty reward pools with the default open-set eligibility policy.
    pub fn new_open() -> Self {
        Self {
            policy: RewardPolicy::v1_open(),
            operators: BTreeMap::new(),
            miner_pool_sats: 0,
            channels_pool_sats: 0,
            infra_pool_sats: 0,
            accrued_profit_sats: 0,
            pending_governance_reward_sats: 0,
            governance_credits: BTreeMap::new(),
            crypto_suite_id_pq: "ml-dsa-65-placeholder".into(),
            last_miner_payout_at_secs: None,
            last_miner_payout_epoch: None,
        }
    }

    /// Insert or replace an operator after rejecting path-like payout destinations.
    ///
    /// The destination is later checked against the registered operator when
    /// bank-issued miner intents are validated.
    pub fn upsert_operator(&mut self, op: MinerOperator) -> Result<(), DomainError> {
        if op.payout_destination.contains("..")
            || op.payout_destination.contains('/')
            || op.payout_destination.contains('\\')
        {
            return Err(DomainError::InvalidIntent("miner payout destination illegal".into()));
        }
        self.operators.insert(op.node_id.as_str().to_string(), op);
        Ok(())
    }

    /// Return active operators that satisfy the current reward policy.
    pub fn eligible_active(&self) -> Vec<&MinerOperator> {
        self.operators.values().filter(|o| o.is_eligible(&self.policy)).collect()
    }

    /// Accrue full profit splits into MINERS / CHANNELS / INFRA credit pools.
    pub fn accrue_profit_splits(
        &mut self,
        profit_sats: u64,
        splits: &ProfitSplits,
    ) -> Result<ProfitSplitAccrual, DomainError> {
        splits.validate()?;
        let (miners, channels, infra) = splits.allocate(profit_sats);
        self.miner_pool_sats = self.miner_pool_sats.saturating_add(miners);
        self.channels_pool_sats = self.channels_pool_sats.saturating_add(channels);
        self.infra_pool_sats = self.infra_pool_sats.saturating_add(infra);
        self.accrued_profit_sats = self.accrued_profit_sats.saturating_add(profit_sats);
        Ok(ProfitSplitAccrual { profit_sats, miners_sats: miners, channels_sats: channels, infra_sats: infra })
    }

    /// Accrue `p_reward_bps` of profit into pools via [`ProfitSplits::open_with_reward`].
    /// Waiting set does not dilute. Returns the MINERS leg only (legacy callers).
    pub fn accrue_from_profit(&mut self, profit_sats: u64, p_reward_bps: u32) -> u64 {
        let Ok(splits) = ProfitSplits::open_with_reward(p_reward_bps) else {
            return 0;
        };
        self.accrue_profit_splits(profit_sats, &splits).map(|a| a.miners_sats).unwrap_or(0)
    }

    /// Accrue a governance job bounty for eligible operators who participated.
    /// Full bounty lands in the miner pool (bank-issued payout later); credits split equally.
    pub fn accrue_governance_job(
        &mut self,
        job: GovernanceJobKind,
        participants: &[NodeId],
        config: &GovernanceRewardConfig,
    ) -> GovernanceAccrual {
        let participants: Vec<NodeId> = {
            let mut seen = BTreeMap::new();
            let mut out = Vec::new();
            for p in participants {
                if seen.insert(p.as_str().to_string(), ()).is_none() {
                    out.push(p.clone());
                }
            }
            out
        };
        let bounty = config.bounty_sats(self.miner_pool_sats);
        if bounty == 0 {
            return GovernanceAccrual {
                job,
                bounty_sats: 0,
                accrued_to_pool_sats: 0,
                credited: Vec::new(),
                participants,
                eligible_credited: 0,
            };
        }

        let eligible: Vec<NodeId> = participants
            .iter()
            .filter(|id| self.operators.get(id.as_str()).map(|o| o.is_eligible(&self.policy)).unwrap_or(false))
            .cloned()
            .collect();

        let mut credited = Vec::new();
        if !eligible.is_empty() {
            let n = eligible.len() as u64;
            let each = bounty / n;
            let mut rem = bounty - each * n;
            for id in &eligible {
                let mut share = each;
                if rem > 0 {
                    share += 1;
                    rem -= 1;
                }
                *self.governance_credits.entry(id.as_str().to_string()).or_insert(0) += share;
                credited.push((id.clone(), share));
            }
        }

        self.miner_pool_sats = self.miner_pool_sats.saturating_add(bounty);
        self.pending_governance_reward_sats = self.pending_governance_reward_sats.saturating_add(bounty);

        GovernanceAccrual {
            job,
            bounty_sats: bounty,
            accrued_to_pool_sats: bounty,
            eligible_credited: credited.len(),
            credited,
            participants,
        }
    }

    /// Equal split of `amount` among eligible active miners (bank will issue Intents).
    pub fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<MinerPayoutShare>, DomainError> {
        let eligible = self.eligible_active();
        if eligible.is_empty() {
            return Err(DomainError::NoEligibleMiners);
        }
        if amount == 0 || amount > self.miner_pool_sats {
            return Err(DomainError::InsufficientMinerPool { have: self.miner_pool_sats, want: amount });
        }
        let n = eligible.len() as u64;
        let each = amount / n;
        let mut rem = amount - each * n;
        let mut out = Vec::with_capacity(eligible.len());
        for op in eligible {
            let mut share = each;
            if rem > 0 {
                share += 1;
                rem -= 1;
            }
            out.push(MinerPayoutShare {
                node_id: op.node_id.clone(),
                destination: op.payout_destination.clone(),
                amount_sats: share,
            });
        }
        Ok(out)
    }

    /// Debit the miner pool and consume pending governance rewards first.
    ///
    /// Returns [`DomainError::InsufficientMinerPool`] without changing state if
    /// `amount` exceeds the available pool.
    pub fn debit_pool(&mut self, amount: u64) -> Result<(), DomainError> {
        if amount > self.miner_pool_sats {
            return Err(DomainError::InsufficientMinerPool { have: self.miner_pool_sats, want: amount });
        }
        self.miner_pool_sats -= amount;
        let from_gov = amount.min(self.pending_governance_reward_sats);
        self.pending_governance_reward_sats -= from_gov;
        Ok(())
    }

    /// Gate propose spacing. `current_epoch` is used only for [`MinerPayoutCadence::Epoch`].
    pub fn assert_payout_cadence_ok(
        &self,
        cadence: MinerPayoutCadence,
        now_secs: u64,
        current_epoch: Option<u64>,
    ) -> Result<(), DomainError> {
        match cadence {
            MinerPayoutCadence::Manual => Ok(()),
            MinerPayoutCadence::Daily => {
                if let Some(last) = self.last_miner_payout_at_secs {
                    if now_secs.saturating_sub(last) < 86_400 {
                        return Err(DomainError::RequestRejected(
                            "miner payout cadence daily: wait 86400s since last payout".into(),
                        ));
                    }
                }
                Ok(())
            }
            MinerPayoutCadence::Weekly => {
                if let Some(last) = self.last_miner_payout_at_secs {
                    if now_secs.saturating_sub(last) < 7 * 86_400 {
                        return Err(DomainError::RequestRejected(
                            "miner payout cadence weekly: wait 604800s since last payout".into(),
                        ));
                    }
                }
                Ok(())
            }
            MinerPayoutCadence::Epoch => {
                let Some(cur) = current_epoch else {
                    return Err(DomainError::RequestRejected(
                        "miner payout cadence epoch: current epoch required".into(),
                    ));
                };
                if let Some(last) = self.last_miner_payout_epoch {
                    if cur <= last {
                        return Err(DomainError::RequestRejected(
                            "miner payout cadence epoch: wait for next epoch".into(),
                        ));
                    }
                }
                Ok(())
            }
        }
    }

    /// Record payout time and, when supplied, the epoch used for cadence checks.
    pub fn record_miner_payout(&mut self, at_secs: u64, epoch: Option<u64>) {
        self.last_miner_payout_at_secs = Some(at_secs);
        if let Some(e) = epoch {
            self.last_miner_payout_epoch = Some(e);
        }
    }

    /// Survivability note: losing one vault must not unlock USERS omnibus or full key.
    pub fn survivability_ok(&self, online_vaults: usize, signing_t: usize) -> bool {
        // Bank ledger survives independently; cofre only fails closed when online < t.
        online_vaults >= signing_t || online_vaults == 0
    }
}

/// Portion of a proposed miner payout assigned to one registered operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerPayoutShare {
    /// Operator receiving this share of the proposed payout.
    pub node_id: NodeId,
    /// Registered payout destination for the operator.
    pub destination: String,
    /// Share amount in satoshis.
    pub amount_sats: u64,
}

impl MinerPayoutShare {
    /// Convert this allocation into a bank-issued settlement intent in the MINERS bucket.
    pub fn to_intent(
        &self,
        intent_id: impl Into<String>,
        policy_hash: impl Into<String>,
    ) -> Result<SettlementIntent, DomainError> {
        SettlementIntent::new(intent_id, BucketKind::Miners, self.destination.clone(), self.amount_sats, policy_hash)
    }
}

/// Reject vault self-payment: payout destination must match registered operator, not invented.
///
/// Non-MINERS intents are unaffected. A MINERS intent must target an eligible
/// operator's registered destination or the function returns
/// [`DomainError::MinerSelfPayForbidden`].
pub fn assert_bank_issued_miner_payout(economy: &EconomyState, intent: &SettlementIntent) -> Result<(), DomainError> {
    if intent.bucket != BucketKind::Miners {
        return Ok(());
    }
    let matched = economy
        .operators
        .values()
        .any(|op| op.is_eligible(&economy.policy) && op.payout_destination == intent.destination);
    if !matched {
        return Err(DomainError::MinerSelfPayForbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_miner_not_eligible() {
        let policy = RewardPolicy::v1_open();
        let op = MinerOperator {
            node_id: NodeId::new("m1").unwrap(),
            payout_destination: "tb1q-miner-payout".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 10,
            bond_sats: 0,
            waiting: true,
        };
        assert!(!op.is_eligible(&policy));
    }

    #[test]
    fn accrue_one_percent() {
        let mut eco = EconomyState::new_open();
        let got = eco.accrue_from_profit(1_000_000, 100);
        assert_eq!(got, 10_000);
        assert_eq!(eco.miner_pool_sats, 10_000);
        assert_eq!(eco.channels_pool_sats + eco.infra_pool_sats, 990_000);
        assert_eq!(eco.miner_pool_sats + eco.channels_pool_sats + eco.infra_pool_sats, 1_000_000);
    }

    #[test]
    fn weekly_cadence_blocks_until_week_elapsed() {
        let mut eco = EconomyState::new_open();
        eco.record_miner_payout(1_000_000, None);
        assert!(eco.assert_payout_cadence_ok(MinerPayoutCadence::Weekly, 1_000_000 + 100, None).is_err());
        assert!(eco.assert_payout_cadence_ok(MinerPayoutCadence::Weekly, 1_000_000 + 7 * 86_400, None).is_ok());
        assert!(eco.assert_payout_cadence_ok(MinerPayoutCadence::Manual, 1_000_000 + 1, None).is_ok());
    }

    #[test]
    fn governance_job_splits_among_eligible_participants() {
        let mut eco = EconomyState::new_open();
        let a = NodeId::new("vault-1").unwrap();
        let b = NodeId::new("vault-2").unwrap();
        let wait = NodeId::new("vault-wait").unwrap();
        eco.upsert_operator(MinerOperator {
            node_id: a.clone(),
            payout_destination: "bc1q-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 2,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
        eco.upsert_operator(MinerOperator {
            node_id: b.clone(),
            payout_destination: "bc1q-b".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 2,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
        eco.upsert_operator(MinerOperator {
            node_id: wait.clone(),
            payout_destination: "bc1q-w".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 2,
            bond_sats: 0,
            waiting: true,
        })
        .unwrap();

        let cfg = GovernanceRewardConfig { reward_sats: 1_000, reward_bps_of_pool: 0 };
        let got = eco.accrue_governance_job(GovernanceJobKind::DayAdvanced, &[a.clone(), b.clone(), wait], &cfg);
        assert_eq!(got.accrued_to_pool_sats, 1_000);
        assert_eq!(got.eligible_credited, 2);
        assert_eq!(eco.miner_pool_sats, 1_000);
        assert_eq!(eco.pending_governance_reward_sats, 1_000);
        assert_eq!(eco.governance_credits.get("vault-1"), Some(&500));
        assert_eq!(eco.governance_credits.get("vault-2"), Some(&500));
        assert!(!eco.governance_credits.contains_key("vault-wait"));
    }

    #[test]
    fn governance_bps_of_pool_adds_to_fixed_bounty() {
        let mut eco = EconomyState::new_open();
        eco.miner_pool_sats = 10_000;
        let a = NodeId::new("vault-1").unwrap();
        eco.upsert_operator(MinerOperator {
            node_id: a.clone(),
            payout_destination: "bc1q-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 1,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
        let cfg = GovernanceRewardConfig {
            reward_sats: 100,
            reward_bps_of_pool: 100, // 1% of 10_000 = 100
        };
        let got = eco.accrue_governance_job(GovernanceJobKind::ReleaseCosign, &[a], &cfg);
        assert_eq!(got.bounty_sats, 200);
        assert_eq!(eco.miner_pool_sats, 10_200);
    }
}
