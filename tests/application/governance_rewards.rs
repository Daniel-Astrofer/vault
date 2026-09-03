//! Governance job rewards: day rotation / reshare + release cosign/activate accrual.

use std::collections::BTreeSet;
use std::sync::Arc;

use kerosene_vault::adapters::DistributedDkgAdapter;
use kerosene_vault::adapters::{
    FrostShareSlot, FrostShareState, FrostTrShareSlot, InMemoryEconomy, InMemoryLedger, InMemoryReleaseMesh,
    PolicyReshareHook,
};
use kerosene_vault::application::{
    AccrueGovernanceWork, ActivateRelease, BlobStorePort, ClockPort, CosignRelease, EconomyPort, GetEconomyStatus,
    LedgerPort, ProposeRelease, RebuildRelease, ReleaseStorePort, ReshareHookPort, UpsertMiner,
};
use kerosene_vault::domain::{
    AttestationMode, Constitution, DayEpoch, EconomyState, GovernanceJobKind, GovernanceRewardConfig, LedgerEventKind,
    MinerOperator, NodeId, ReleasePolicy, ResharePolicy, VaultNodeTier,
};

struct FixedClock(u64);
impl ClockPort for FixedClock {
    fn unix_now_secs(&self) -> u64 {
        self.0
    }
}

fn eligible_op(id: &str, dest: &str) -> MinerOperator {
    MinerOperator {
        node_id: NodeId::new(id).unwrap(),
        payout_destination: dest.into(),
        uptime_bps_30d: 9_900,
        attestation_streak_days: 3,
        bond_sats: 0,
        waiting: false,
    }
}

fn three_ids() -> [NodeId; 3] {
    [NodeId::new("vault-1").unwrap(), NodeId::new("vault-2").unwrap(), NodeId::new("vault-3").unwrap()]
}

fn gov_cfg() -> GovernanceRewardConfig {
    GovernanceRewardConfig { reward_sats: 1_000, reward_bps_of_pool: 0 }
}

#[cfg(feature = "dealer_lab")]
#[test]
fn day_rotation_and_reshare_accrue_governance_rewards() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let economy = Arc::new(InMemoryEconomy::new(EconomyState::new_open()));
    let upsert = UpsertMiner::new(economy.clone());
    for (i, id) in ids.iter().enumerate() {
        upsert.execute(eligible_op(id.as_str(), &format!("bc1q-vault-{i}"))).unwrap();
    }

    let gov = Arc::new(AccrueGovernanceWork::new(economy.clone(), ledger.clone(), ids[0].clone(), gov_cfg()));
    let shares = Arc::new(FrostShareSlot::new());
    let bundle = DistributedDkgAdapter::run_in_process(3, 2).unwrap();
    shares.install(FrostShareState {
        key_packages: bundle.key_packages,
        pubkey_package: bundle.pubkey_package,
        min_signers: 2,
    });
    let hook = PolicyReshareHook::new(
        ResharePolicy::Daily,
        ledger.clone(),
        ids[0].clone(),
        shares,
        Arc::new(FrostTrShareSlot::new()),
    )
    .with_governance(gov.clone());

    let from = DayEpoch::parse("2024-01-01").unwrap();
    let to = DayEpoch::parse("2024-01-02").unwrap();
    let voters = vec![ids[0].clone(), ids[1].clone()];
    hook.on_day_advance(&from, &to, &voters).unwrap();

    let eco = economy.snapshot().unwrap();
    // day_advanced (1000) + reshare_completed (1000) among 2 eligible voters
    assert_eq!(eco.pending_governance_reward_sats, 2_000);
    assert_eq!(eco.miner_pool_sats, 2_000);
    assert_eq!(eco.governance_credits.get("vault-1"), Some(&1_000));
    assert_eq!(eco.governance_credits.get("vault-2"), Some(&1_000));
    assert!(!eco.governance_credits.contains_key("vault-3"));

    let kinds: Vec<_> = ledger.entries().unwrap().into_iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&LedgerEventKind::DayAdvanced));
    assert!(kinds.contains(&LedgerEventKind::ReshareCompleted));
    assert!(kinds.iter().filter(|k| **k == LedgerEventKind::GovernanceRewardAccrued).count() >= 2);

    let status = GetEconomyStatus::new(
        economy,
        ledger,
        gov_cfg(),
        kerosene_vault::domain::MinerPayoutCadence::Manual,
        VaultNodeTier::Domestic,
        AttestationMode::Sim,
        false,
    )
    .execute()
    .unwrap();
    assert_eq!(status.pending_governance_reward_sats, 2_000);
    assert_eq!(status.governance_reward_sats, 1_000);
    assert!(status.to_json().contains("pending_governance_reward_sats"));
}

#[test]
fn release_cosign_and_activate_accrue_governance_rewards() {
    let ids = three_ids();
    let constitution = Constitution::v1_open(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let economy = Arc::new(InMemoryEconomy::new(EconomyState::new_open()));
    let upsert = UpsertMiner::new(economy.clone());
    for (i, id) in ids.iter().enumerate() {
        upsert.execute(eligible_op(id.as_str(), &format!("bc1q-rel-{i}"))).unwrap();
    }
    let gov = Arc::new(AccrueGovernanceWork::new(economy.clone(), ledger.clone(), ids[0].clone(), gov_cfg()));

    let mut policy = ReleasePolicy::lab_default(3);
    policy.lab_timelock_scale = 0;
    policy.min_rebuilds = 3;
    policy.council_n = 3;
    let mesh = Arc::new(InMemoryReleaseMesh::new(policy));
    let release_port: Arc<dyn ReleaseStorePort> = mesh.clone();
    let blob_port: Arc<dyn BlobStorePort> = mesh.clone();
    let clock: Arc<dyn ClockPort> = Arc::new(FixedClock(1_700_000_000));

    ProposeRelease::new(release_port.clone(), blob_port.clone(), ledger.clone(), clock.clone())
        .execute("rel-gov", b"kerosene-vault-src-gov", BTreeSet::from(["council-a".into(), "council-b".into()]))
        .unwrap();

    let rebuild = RebuildRelease::new(release_port.clone(), blob_port);
    for id in &ids {
        rebuild.execute("rel-gov", id).unwrap();
    }

    for id in ids.iter().take(2) {
        CosignRelease::new(release_port.clone(), ledger.clone(), clock.clone(), id.clone())
            .with_governance(gov.clone())
            .execute("rel-gov")
            .unwrap();
    }

    ActivateRelease::new(release_port, ledger.clone(), clock).with_governance(gov.clone()).execute("rel-gov").unwrap();

    let eco = economy.snapshot().unwrap();
    // 2 cosigns × 1000 + 1 activate × 1000 (split among 2 cosigners) = 3000
    assert_eq!(eco.pending_governance_reward_sats, 3_000);
    assert_eq!(eco.miner_pool_sats, 3_000);
    assert_eq!(eco.governance_credits.get("vault-1"), Some(&1_500));
    assert_eq!(eco.governance_credits.get("vault-2"), Some(&1_500));

    let gov_events =
        ledger.entries().unwrap().into_iter().filter(|e| e.kind == LedgerEventKind::GovernanceRewardAccrued).count();
    assert_eq!(gov_events, 3); // 2 cosign + 1 activate

    // Disabled config accrues nothing further.
    let disabled =
        AccrueGovernanceWork::new(economy.clone(), ledger, ids[0].clone(), GovernanceRewardConfig::disabled());
    let before = economy.snapshot().unwrap().miner_pool_sats;
    disabled.execute(GovernanceJobKind::ReleaseCosign, &[ids[0].clone()], "noop").unwrap();
    assert_eq!(economy.snapshot().unwrap().miner_pool_sats, before);
}
