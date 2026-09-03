use std::sync::Arc;

use crate::ports::{BucketLedgerPort, EconomyPort, LedgerPort};
use vault_domain::{assert_bank_issued_miner_payout, evaluate_intent, BucketKind, DomainError, SettlementIntent};

pub struct GateIntent {
    buckets: Arc<dyn BucketLedgerPort>,
    ledger: Arc<dyn LedgerPort>,
    economy: Arc<dyn EconomyPort>,
}

impl GateIntent {
    pub fn new(buckets: Arc<dyn BucketLedgerPort>, ledger: Arc<dyn LedgerPort>, economy: Arc<dyn EconomyPort>) -> Self {
        Self { buckets, ledger, economy }
    }

    /// Soft-reserve Intent (two-phase High #9): evaluate + hold caps; do **not**
    /// durable-burn. Call [`commit`] after successful sign, or [`release`] on failure.
    pub fn reserve(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        self.run(&intent, Phase::Reserve)
    }

    /// Promote reservation → durable mesh consume after successful sign.
    pub fn commit(&self, intent_id: &str) -> Result<(), DomainError> {
        self.buckets.commit_consume(intent_id)
    }

    /// Roll back soft reservation when sign fails.
    pub fn release(&self, intent_id: &str, bucket: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.buckets.release_reservation(intent_id, bucket, amount_sats)
    }

    /// Evaluate + consume intent id (atomic + durable). Prefer [`reserve`]/ [`commit`]
    /// on bitcoin sign paths so a failed sign does not burn the Intent.
    pub fn execute(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        self.run(&intent, Phase::Consume)
    }

    fn run(&self, intent: &SettlementIntent, phase: Phase) -> Result<GateReceipt, DomainError> {
        let constitution = self.ledger.constitution()?;
        let miners_open = constitution.profit_splits.miners_bps > 0 && intent.bucket == BucketKind::Miners;
        let economy = if miners_open {
            let snap = self.economy.snapshot()?;
            assert_bank_issued_miner_payout(&snap, intent)?;
            Some(snap)
        } else {
            None
        };
        let policy_hash = constitution.hash.clone();
        let intent_id = intent.intent_id.clone();
        let bucket = intent.bucket;
        let amount_sats = intent.amount_sats;

        let validate = |policy: &vault_domain::BucketPolicy, spent: u64| {
            let mut policy = policy.clone();
            // Admit only registered eligible operator destinations (#29) — never Intent dest alone.
            if let Some(eco) = economy.as_ref() {
                for op in eco.operators.values() {
                    if op.is_eligible(&eco.policy) {
                        policy.destination_allowlist.insert(op.payout_destination.clone());
                    }
                }
            }
            evaluate_intent(intent, &policy, spent, &policy_hash)
        };

        match phase {
            Phase::Reserve => {
                self.buckets.reserve_spend(&intent_id, bucket, amount_sats, &validate)?;
                Ok(GateReceipt { intent_id, bucket, amount_sats, status: "RESERVED" })
            }
            Phase::Consume => {
                self.buckets.authorize_spend_and_consume(&intent_id, bucket, amount_sats, &validate)?;
                Ok(GateReceipt { intent_id, bucket, amount_sats, status: "ACCEPTED" })
            }
        }
    }
}

enum Phase {
    Reserve,
    Consume,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReceipt {
    pub intent_id: String,
    pub bucket: BucketKind,
    pub amount_sats: u64,
    pub status: &'static str,
}

impl GateReceipt {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"intent_id":"{}","bucket":"{}","amount_sats":{},"status":"{}"}}"#,
            self.intent_id,
            self.bucket.as_str(),
            self.amount_sats,
            self.status
        )
    }
}

pub struct AllocateProfit {
    ledger: Arc<dyn LedgerPort>,
}

impl AllocateProfit {
    pub fn new(ledger: Arc<dyn LedgerPort>) -> Self {
        Self { ledger }
    }

    pub fn execute(&self, profit_sats: u64) -> Result<ProfitAllocation, DomainError> {
        let constitution = self.ledger.constitution()?;
        let (miners, channels, infra) = constitution.profit_splits.allocate(profit_sats);
        Ok(ProfitAllocation {
            profit_sats,
            miners_sats: miners,
            channels_sats: channels,
            infra_sats: infra,
            dry_run_miners: constitution.profit_splits.miners_bps == 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitAllocation {
    pub profit_sats: u64,
    pub miners_sats: u64,
    pub channels_sats: u64,
    pub infra_sats: u64,
    pub dry_run_miners: bool,
}

impl ProfitAllocation {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"profit_sats":{},"miners_sats":{},"channels_sats":{},"infra_sats":{},"dry_run_miners":{}}}"#,
            self.profit_sats, self.miners_sats, self.channels_sats, self.infra_sats, self.dry_run_miners
        )
    }
}
