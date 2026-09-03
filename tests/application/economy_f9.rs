//! F9: open economy p%=1%, eligibility, waiting set, anti-self-pay MINERS gating.

use std::sync::Arc;

use kerosene_vault::adapters::{InMemoryBucketLedger, InMemoryEconomy, InMemoryLedger};
use kerosene_vault::application::{
    AccrueMinerRewards, AllocateProfit, EconomyPort, GateIntent, ProposeMinerPayouts, UpsertMiner,
};
use kerosene_vault::domain::{
    BucketKind, Constitution, DomainError, EconomyState, MinerOperator, NodeId, SettlementIntent,
};

fn three_ids() -> [NodeId; 3] {
    [NodeId::new("vault-1").unwrap(), NodeId::new("vault-2").unwrap(), NodeId::new("vault-3").unwrap()]
}

#[test]
fn open_constitution_splits_one_percent_to_miners() {
    let c = Constitution::v1_open(3).unwrap();
    assert_eq!(c.p_reward_bps, 100);
    assert_eq!(c.profit_splits.miners_bps, 100);
    let (m, ch, inf) = c.profit_splits.allocate(1_000_000);
    assert_eq!(m, 10_000);
    assert_eq!(ch + inf + m, 1_000_000);
}

#[test]
fn allocate_profit_open_not_dry_run() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let alloc = AllocateProfit::new(ledger).execute(1_000_000).unwrap();
    assert!(!alloc.dry_run_miners);
    assert_eq!(alloc.miners_sats, 10_000);
}

#[test]
fn accrue_and_propose_payouts_equal_split() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let economy = Arc::new(InMemoryEconomy::new(EconomyState::new_open()));
    let upsert = UpsertMiner::new(economy.clone());
    upsert
        .execute(MinerOperator {
            node_id: NodeId::new("miner-a").unwrap(),
            payout_destination: "bc1q-miner-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 7,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
    upsert
        .execute(MinerOperator {
            node_id: NodeId::new("miner-b").unwrap(),
            payout_destination: "bc1q-miner-b".into(),
            uptime_bps_30d: 9_500,
            attestation_streak_days: 1,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
    // Waiting miner must not receive share.
    upsert
        .execute(MinerOperator {
            node_id: NodeId::new("miner-wait").unwrap(),
            payout_destination: "bc1q-miner-wait".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 30,
            bond_sats: 0,
            waiting: true,
        })
        .unwrap();

    let accrue = AccrueMinerRewards::new(economy.clone(), ledger.clone(), ids[0].clone());
    let receipt = accrue.execute(1_000_000).unwrap();
    assert_eq!(receipt.accrued_to_pool_sats, 10_000);
    assert_eq!(receipt.channels_sats + receipt.infra_sats + receipt.accrued_to_pool_sats, 1_000_000);

    let clock = Arc::new(kerosene_vault::adapters::SystemClock);
    let propose =
        ProposeMinerPayouts::new(economy.clone(), ledger, clock, kerosene_vault::domain::MinerPayoutCadence::Manual);
    let proposal = propose.execute(10_000, "pay").unwrap();
    assert_eq!(proposal.intents.len(), 2);
    assert_eq!(proposal.total_sats, 10_000);
    assert!(proposal.intents.iter().all(|i| i.bucket == BucketKind::Miners));
    assert!(!proposal.intents.iter().any(|i| i.destination == "bc1q-miner-wait"));
    assert_eq!(economy.snapshot().unwrap().miner_pool_sats, 0);
}

#[test]
fn open_gate_rejects_unregistered_miner_destination() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let economy = Arc::new(InMemoryEconomy::open());
    UpsertMiner::new(economy.clone())
        .execute(MinerOperator {
            node_id: NodeId::new("miner-a").unwrap(),
            payout_destination: "bc1q-miner-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 2,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
    let gate = GateIntent::new(buckets, ledger, economy);
    let evil = SettlementIntent::new("self-pay", BucketKind::Miners, "bc1q-vault-self", 100, policy_hash).unwrap();
    assert_eq!(gate.execute(evil).unwrap_err(), DomainError::MinerSelfPayForbidden);
}

#[test]
fn open_gate_accepts_registered_eligible_miner() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let economy = Arc::new(InMemoryEconomy::open());
    UpsertMiner::new(economy.clone())
        .execute(MinerOperator {
            node_id: NodeId::new("miner-a").unwrap(),
            payout_destination: "bc1q-miner-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 2,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
    let gate = GateIntent::new(buckets, ledger, economy);
    let intent = SettlementIntent::new("bank-pay-1", BucketKind::Miners, "bc1q-miner-a", 100, policy_hash).unwrap();
    assert_eq!(gate.execute(intent).unwrap().status, "ACCEPTED");
}

#[test]
fn survivability_fail_closed_when_below_quorum() {
    let eco = EconomyState::new_open();
    assert!(!eco.survivability_ok(1, 2));
    assert!(eco.survivability_ok(2, 2));
}
