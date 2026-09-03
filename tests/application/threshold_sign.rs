use std::sync::Arc;

use kerosene_vault::adapters::ThresholdVaultState;
use kerosene_vault::application::{SignMessage, StaticOnlineCount};
use kerosene_vault::domain::{run_dkg, DomainError, NodeId};

fn nodes3() -> Vec<NodeId> {
    vec![NodeId::new("vault-1").unwrap(), NodeId::new("vault-2").unwrap(), NodeId::new("vault-3").unwrap()]
}

#[test]
fn dkg_shares_reconstruct_joint_secret() {
    let set = nodes3();
    let (group, shares) = run_dkg(&set, 2, b"test-entropy").unwrap();
    assert_eq!(group.n, 3);
    assert_eq!(group.t, 2);
    assert_eq!(shares.len(), 3);
    let pts: Vec<(u8, u64)> = shares.iter().take(2).map(|s| (s.index.0, s.value)).collect();
    let _secret = kerosene_vault::domain::interpolate_secret(&pts).unwrap();
    // 3-of-3 also works
    let pts3: Vec<(u8, u64)> = shares.iter().map(|s| (s.index.0, s.value)).collect();
    let s3 = kerosene_vault::domain::interpolate_secret(&pts3).unwrap();
    let s2 = kerosene_vault::domain::interpolate_secret(&pts).unwrap();
    assert_eq!(s2, s3);
}

#[test]
fn sign_succeeds_at_two_thirds_online() {
    let set = nodes3();
    let (group, shares) = run_dkg(&set, 2, b"sign-entropy").unwrap();
    let local = shares[0].clone();
    let state = Arc::new(ThresholdVaultState::new(group, local, shares));
    let online = Arc::new(StaticOnlineCount { count: 2 });
    let sign = SignMessage::new(state, online);
    let sig = sign.run_lab_quorum_sign("sess-1", "msg-hash-abc").unwrap();
    assert_eq!(sig.session_id, "sess-1");
    assert_eq!(sig.participants.len(), 2);
}

#[test]
fn fail_stop_when_online_below_t() {
    let set = nodes3();
    let (group, shares) = run_dkg(&set, 2, b"fail-entropy").unwrap();
    let local = shares[0].clone();
    let state = Arc::new(ThresholdVaultState::new(group, local, shares));
    let online = Arc::new(StaticOnlineCount { count: 1 });
    let sign = SignMessage::new(state, online);
    let err = sign.run_lab_quorum_sign("sess-fail", "m").unwrap_err();
    assert!(matches!(err, DomainError::FailStop { online: 1, need: 2 }));
}

#[test]
fn session_id_reuse_rejected() {
    let set = nodes3();
    let (group, shares) = run_dkg(&set, 2, b"reuse-entropy").unwrap();
    let local = shares[0].clone();
    let state = Arc::new(ThresholdVaultState::new(group, local, shares));
    let online = Arc::new(StaticOnlineCount { count: 3 });
    let sign = SignMessage::new(state, online);
    sign.run_lab_quorum_sign("sess-x", "m1").unwrap();
    let err = sign.run_lab_quorum_sign("sess-x", "m2").unwrap_err();
    assert!(matches!(err, DomainError::NonceReuse(_)));
}
