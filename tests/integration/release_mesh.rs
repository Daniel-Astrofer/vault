use std::collections::BTreeSet;
use std::sync::Arc;

use kerosene_vault::adapters::{InMemoryLedger, InMemoryReleaseMesh};
use kerosene_vault::application::{
    ActivateRelease, BlobStorePort, ClockPort, CosignRelease, GetAllowlist, ProposeRelease, RebuildRelease,
    ReleaseStorePort,
};
use kerosene_vault::domain::{lab_rebuild_binary_hash, Constitution, ContentHash, NodeId, ReleasePhase, ReleasePolicy};

struct FixedClock(u64);
impl ClockPort for FixedClock {
    fn unix_now_secs(&self) -> u64 {
        self.0
    }
}

fn lab_mesh(n: usize) -> (Arc<InMemoryReleaseMesh>, Arc<InMemoryLedger>, Arc<dyn ClockPort>) {
    let constitution = Constitution::v1_lab(n).unwrap();
    let nodes: Vec<_> = (1..=n).map(|i| NodeId::new(format!("vault-{i}")).unwrap()).collect();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, nodes.clone(), nodes[0].clone()).unwrap());
    let mut policy = ReleasePolicy::lab_default(n);
    policy.lab_timelock_scale = 0;
    policy.min_rebuilds = 3;
    policy.council_n = 3;
    let mesh = Arc::new(InMemoryReleaseMesh::new(policy));
    let clock: Arc<dyn ClockPort> = Arc::new(FixedClock(1_700_000_000));
    (mesh, ledger, clock)
}

fn council_two_of_three() -> BTreeSet<String> {
    BTreeSet::from(["council-a".into(), "council-b".into()])
}

#[test]
fn clean_release_rebuild_cosign_allowlist() {
    let (mesh, ledger, clock) = lab_mesh(3);
    let release_port: Arc<dyn ReleaseStorePort> = mesh.clone();
    let blob_port: Arc<dyn BlobStorePort> = mesh.clone();

    let propose = ProposeRelease::new(release_port.clone(), blob_port.clone(), ledger.clone(), clock.clone());
    let c = propose.execute("rel-clean", b"kerosene-vault-src-v1", council_two_of_three()).unwrap();
    assert_eq!(c.phase, ReleasePhase::Proposed);
    assert_eq!(c.hb, lab_rebuild_binary_hash(b"kerosene-vault-src-v1"));

    let rebuild = RebuildRelease::new(release_port.clone(), blob_port);
    for i in 1..=3 {
        let v = NodeId::new(format!("vault-{i}")).unwrap();
        rebuild.execute("rel-clean", &v).unwrap();
    }
    let after = release_port.get_candidate("rel-clean").unwrap();
    assert_eq!(after.rebuilds.len(), 3);

    // Cosign from majority of vaults (2 of 3).
    for i in 1..=2 {
        let cosign = CosignRelease::new(
            release_port.clone(),
            ledger.clone(),
            clock.clone(),
            NodeId::new(format!("vault-{i}")).unwrap(),
        );
        cosign.execute("rel-clean").unwrap();
    }

    let activate = ActivateRelease::new(release_port.clone(), ledger.clone(), clock.clone());
    let entry = activate.execute("rel-clean").unwrap();
    assert_eq!(entry.release_id, "rel-clean");

    let allow = GetAllowlist::new(release_port);
    assert!(allow.require_hb(&entry.hb).is_ok());
    let list = allow.execute().unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn tampered_hb_rejected_on_rebuild() {
    let (mesh, ledger, clock) = lab_mesh(3);
    let release_port: Arc<dyn ReleaseStorePort> = mesh.clone();
    let blob_port: Arc<dyn BlobStorePort> = mesh.clone();

    let source = b"kerosene-vault-src-v1";
    let hs = ContentHash::from_bytes(source);
    blob_port.put(&hs, source).unwrap();
    let evil_hb = ContentHash::from_bytes(b"evil-prebuilt-binary");

    let propose = ProposeRelease::new(release_port.clone(), blob_port.clone(), ledger, clock);
    propose.execute_with_hashes("rel-evil", hs, evil_hb, council_two_of_three()).unwrap();

    let rebuild = RebuildRelease::new(release_port, blob_port);
    let v1 = NodeId::new("vault-1").unwrap();
    let err = rebuild.execute("rel-evil", &v1).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rebuild mismatch"), "expected rebuild mismatch, got {msg}");
}

#[test]
fn insufficient_council_sigs_rejected() {
    let (mesh, ledger, clock) = lab_mesh(3);
    let release_port: Arc<dyn ReleaseStorePort> = mesh.clone();
    let blob_port: Arc<dyn BlobStorePort> = mesh;
    let propose = ProposeRelease::new(release_port, blob_port, ledger, clock);
    let one = BTreeSet::from(["council-a".into()]);
    let err = propose.execute("rel-weak", b"src", one).unwrap_err();
    assert!(err.to_string().contains("quorum not met"));
}

#[test]
fn app_cannot_pull_non_allowlisted_hb() {
    let (mesh, _ledger, _clock) = lab_mesh(3);
    let allow = GetAllowlist::new(mesh);
    let hb = ContentHash::from_bytes(b"random");
    assert!(allow.require_hb(&hb).is_err());
}
