//! Application gates for validating, reserving, and consuming settlement intents.
//!
//! The two-phase path reserves limits before signing, then commits only after
//! signing succeeds; failure paths release the soft reservation.

use std::sync::Arc;

use crate::ports::{BucketLedgerPort, EconomyPort, LedgerPort};
use vault_domain::{assert_bank_issued_miner_payout, evaluate_intent, BucketKind, DomainError, SettlementIntent};

/// Use case that applies active constitution, bucket limits, and replay protection to intents.
pub struct GateIntent {
    buckets: Arc<dyn BucketLedgerPort>,
    ledger: Arc<dyn LedgerPort>,
    economy: Arc<dyn EconomyPort>,
}

impl GateIntent {
    /// Construct the intent gate with bucket, constitution-ledger, and economy ports.
    pub fn new(buckets: Arc<dyn BucketLedgerPort>, ledger: Arc<dyn LedgerPort>, economy: Arc<dyn EconomyPort>) -> Self {
        Self { buckets, ledger, economy }
    }

    /// Soft-reserve Intent (two-phase High #9): evaluate + hold caps; do **not**
    /// durable-burn. Call [`Self::commit`] after successful sign, or [`Self::release`] on failure.
    /// Miner intents additionally require an eligible operator's registered destination
    /// when the active constitution has opened the miner profit split.
    pub fn reserve(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        self.run(&intent, Phase::Reserve)
    }

    /// Promote reservation → durable mesh consume after successful sign.
    /// The store implementation determines whether this promotion includes mesh quorum.
    pub fn commit(&self, intent_id: &str) -> Result<(), DomainError> {
        self.buckets.commit_consume(intent_id)
    }

    /// Roll back soft reservation when sign fails.
    /// The supplied bucket and amount must match the values used to create the reservation.
    pub fn release(&self, intent_id: &str, bucket: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.buckets.release_reservation(intent_id, bucket, amount_sats)
    }

    /// Evaluate + consume intent id (atomic + durable). Prefer [`Self::reserve`] / [`Self::commit`]
    /// on bitcoin sign paths so a failed sign does not burn the Intent.
    /// This path validates and consumes through the port's single-operation gate.
    pub fn execute(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        self.run(&intent, Phase::Consume)
    }

    /// Load active policy, optionally bind miner destinations to operator records, and run a ledger phase.
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

/// Internal choice between a reversible reservation and durable consumption.
enum Phase {
    /// Validate the intent and hold its spend caps without burning its identifier.
    Reserve,
    /// Validate and durably consume the intent identifier in one guarded operation.
    Consume,
}

/// Result of accepting an intent for reservation or execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReceipt {
    /// Identifier of the accepted intent.
    pub intent_id: String,
    /// Treasury bucket charged by the intent.
    pub bucket: BucketKind,
    /// Accepted amount in satoshis.
    pub amount_sats: u64,
    /// `RESERVED` for the pre-sign phase or `ACCEPTED` for immediate consumption.
    pub status: &'static str,
}

impl GateReceipt {
    /// Serialize the receipt to its compact JSON API representation.
    ///
    /// The current formatter interpolates `intent_id` directly; callers should
    /// use validated identifiers and must not treat this as a general JSON encoder.
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

/// Read-only use case that calculates profit distribution from the active constitution.
pub struct AllocateProfit {
    ledger: Arc<dyn LedgerPort>,
}

impl AllocateProfit {
    /// Construct the allocation query with the constitution ledger port.
    pub fn new(ledger: Arc<dyn LedgerPort>) -> Self {
        Self { ledger }
    }

    /// Split `profit_sats` into configured child pools without mutating economy state.
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

/// Pure result of applying the constitution's configured profit split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitAllocation {
    /// Gross amount being allocated, in satoshis.
    pub profit_sats: u64,
    /// Portion assigned to the miner pool, in satoshis.
    pub miners_sats: u64,
    /// Portion assigned to channel operations, in satoshis.
    pub channels_sats: u64,
    /// Portion assigned to infrastructure, in satoshis.
    pub infra_sats: u64,
    /// True when the active constitution assigns miners a zero basis-point share.
    pub dry_run_miners: bool,
}

impl ProfitAllocation {
    /// Serialize the calculated split and dry-run indicator to JSON.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"profit_sats":{},"miners_sats":{},"channels_sats":{},"infra_sats":{},"dry_run_miners":{}}}"#,
            self.profit_sats, self.miners_sats, self.channels_sats, self.infra_sats, self.dry_run_miners
        )
    }
}
