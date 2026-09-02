//! §13.4 lab E2E / pentest suite (F6): quorum, fail-stop, caps, release, replay, partition.

use std::collections::BTreeSet;
use std::sync::Arc;

use kerosene_vault::adapters::{
    InMemoryBucketLedger, InMemoryEconomy, InMemoryLedger, InMemoryReleaseMesh, ThresholdVaultState,
};
use kerosene_vault::application::{
    ActivateRelease, AllocateProfit, BlobStorePort, ClockPort, CosignRelease, GateIntent, GetAllowlist, LedgerPort,
    MutableOnlineCount, ProposeEpochAdvance, ProposeRelease, RebuildRelease, ReleaseStorePort, SignMessage,
    VoteEpochAdvance,
};
use kerosene_vault::domain::{run_dkg, BucketKind, Constitution, ContentHash, NodeId, ReleasePolicy, SettlementIntent};

struct FixedClock(u64);
impl ClockPort for FixedClock {
    fn unix_now_secs(&self) -> u64 {
        self.0
    }
}

fn three_vault_ids() -> [NodeId; 3] {
    [NodeId::new("vault-1").unwrap(), NodeId::new("vault-2").unwrap(), NodeId::new("vault-3").unwrap()]
}

fn council() -> BTreeSet<String> {
    BTreeSet::from(["c1".into(), "c2".into()])
}

#[test]
fn suite_happy_intent_gate_then_frost_sign() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let gate = GateIntent::new(buckets, ledger, Arc::new(InMemoryEconomy::open()));
    let intent =
        SettlementIntent::new("intent-happy", BucketKind::Users, "tb1q-users-withdraw", 10_000, policy_hash).unwrap();
    let receipt = gate.execute(intent).unwrap();
    assert_eq!(receipt.status, "ACCEPTED");

    let (group, shares) = run_dkg(&ids, constitution.signing_t, b"e2e-happy").unwrap();
    let online = Arc::new(MutableOnlineCount::new(3));
    let state = Arc::new(ThresholdVaultState::new(group, shares[0].clone(), shares));
    let sign = SignMessage::new(state, online);
    let sig = sign.run_lab_quorum_sign("sess-happy", "msg-hash-happy").unwrap();
    assert_eq!(sig.session_id, "sess-happy");
}

#[test]
fn suite_fail_stop_when_online_below_t() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let (group, shares) = run_dkg(&ids, constitution.signing_t, b"e2e-fail").unwrap();
    let online = Arc::new(MutableOnlineCount::new(1)); // t=2
    let state = Arc::new(ThresholdVaultState::new(group, shares[0].clone(), shares));
    let sign = SignMessage::new(state, online);
    let err = sign.run_lab_quorum_sign("sess-fail", "mh").unwrap_err().to_string();
    assert!(err.contains("fail-stop"), "{err}");
}

#[test]
fn suite_partition_still_signs_with_t_online() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let (group, shares) = run_dkg(&ids, constitution.signing_t, b"e2e-part").unwrap();
    let online = Arc::new(MutableOnlineCount::new(3));
    let state = Arc::new(ThresholdVaultState::new(group, shares[0].clone(), shares));
    let sign = SignMessage::new(state, online.clone());
    // Partition: lose 1 of 3 → still t=2 online.
    online.set(2);
    assert!(sign.run_lab_quorum_sign("sess-part", "mh-part").is_ok());
    online.set(1);
    assert!(sign.run_lab_quorum_sign("sess-part2", "mh-part2").is_err());
}

#[test]
fn suite_intent_above_cap_rejected() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let gate = GateIntent::new(buckets, ledger, Arc::new(InMemoryEconomy::open()));
    let intent = SettlementIntent::new(
        "intent-cap",
        BucketKind::Users,
        "tb1q-users-withdraw",
        constitution.max_withdraw_per_tx_sats + 1,
        policy_hash,
    )
    .unwrap();
    let err = gate.execute(intent).unwrap_err().to_string();
    assert!(err.contains("cap exceeded"), "{err}");
}

#[test]
fn suite_intent_replay_rejected() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let gate = GateIntent::new(buckets, ledger, Arc::new(InMemoryEconomy::open()));
    let mk =
        || SettlementIntent::new("intent-replay", BucketKind::Users, "tb1q-users-withdraw", 1, &policy_hash).unwrap();
    gate.execute(mk()).unwrap();
    let err = gate.execute(mk()).unwrap_err().to_string();
    assert!(err.contains("intent replay"), "{err}");
}

#[test]
fn suite_release_clean_and_tampered() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let mut policy = ReleasePolicy::lab_default(3);
    policy.lab_timelock_scale = 0;
    let mesh = Arc::new(InMemoryReleaseMesh::new(policy));
    let release: Arc<dyn ReleaseStorePort> = mesh.clone();
    let blobs: Arc<dyn BlobStorePort> = mesh.clone();
    let clock: Arc<dyn ClockPort> = Arc::new(FixedClock(10));

    let propose = ProposeRelease::new(release.clone(), blobs.clone(), ledger.clone(), clock.clone());
    propose.execute("rel-ok", b"src-clean", council()).unwrap();
    let rebuild = RebuildRelease::new(release.clone(), blobs.clone());
    for id in &ids {
        rebuild.execute("rel-ok", id).unwrap();
    }
    for id in ids.iter().take(2) {
        CosignRelease::new(release.clone(), ledger.clone(), clock.clone(), id.clone()).execute("rel-ok").unwrap();
    }
    let entry = ActivateRelease::new(release.clone(), ledger.clone(), clock.clone()).execute("rel-ok").unwrap();
    GetAllowlist::new(release.clone()).require_hb(&entry.hb).unwrap();

    // Tampered Hb
    let source = b"src-evil";
    let hs = ContentHash::from_bytes(source);
    blobs.put(&hs, source).unwrap();
    let evil = ContentHash::from_bytes(b"evil-bin");
    propose.execute_with_hashes("rel-bad", hs, evil, council()).unwrap();
    let err = rebuild.execute("rel-bad", &ids[0]).unwrap_err().to_string();
    assert!(err.contains("rebuild mismatch"), "{err}");
}

#[test]
fn suite_non_allowlisted_hb_rejected() {
    let mesh = Arc::new(InMemoryReleaseMesh::new(ReleasePolicy::lab_default(3)));
    let allow = GetAllowlist::new(mesh);
    let hb = ContentHash::from_bytes(b"not-listed");
    assert!(allow.require_hb(&hb).is_err());
}

#[test]
fn suite_bad_node_cannot_propose_epoch() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let evil = NodeId::new("evil-node").unwrap();
    let propose = ProposeEpochAdvance::new(ledger, evil);
    assert!(propose.execute("p-evil").is_err());
}

#[test]
fn suite_profit_allocate_dry_run_miners_zero() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    assert_eq!(constitution.profit_splits.miners_bps, 0);
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    let alloc = AllocateProfit::new(ledger).execute(1_000_000).unwrap();
    assert!(alloc.dry_run_miners);
    assert_eq!(alloc.miners_sats, 0);
    assert_eq!(alloc.channels_sats + alloc.infra_sats, 1_000_000);
}

#[test]
fn suite_miners_bucket_cannot_use_users_destination_policy() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let policy_hash = constitution.hash.clone();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution.clone(), ids.to_vec(), ids[0].clone()).unwrap());
    let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(
        constitution.max_withdraw_per_tx_sats,
        constitution.max_withdraw_per_day_sats,
    ));
    let gate = GateIntent::new(buckets, ledger, Arc::new(InMemoryEconomy::open()));
    // Miners intent to a USERS-only destination must fail allowlist.
    let intent =
        SettlementIntent::new("intent-miner-cross", BucketKind::Miners, "tb1q-users-withdraw", 1, policy_hash).unwrap();
    let err = gate.execute(intent).unwrap_err().to_string();
    assert!(err.contains("destination not allowed"), "{err}");
}

#[test]
fn suite_governance_epoch_still_advances() {
    let ids = three_vault_ids();
    let constitution = Constitution::v1_lab(3).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, ids.to_vec(), ids[0].clone()).unwrap());
    ProposeEpochAdvance::new(ledger.clone(), ids[0].clone()).execute("e2e-epoch").unwrap();
    VoteEpochAdvance::new(ledger.clone(), ids[1].clone()).execute("e2e-epoch").unwrap();
    let p = VoteEpochAdvance::new(ledger.clone(), ids[2].clone()).execute("e2e-epoch").unwrap();
    assert!(p.closed);
    assert_eq!(ledger.epoch().unwrap().number, 1);
}
