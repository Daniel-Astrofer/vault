use std::sync::Arc;

use kerosene_vault::adapters::InMemoryLedger;
use kerosene_vault::application::{LedgerPort, ProposeEpochAdvance, VoteEpochAdvance};
use kerosene_vault::domain::{Constitution, NodeId};

#[test]
fn epoch_advances_with_governance_quorum() {
    let n1 = NodeId::new("vault-1").unwrap();
    let n2 = NodeId::new("vault-2").unwrap();
    let n3 = NodeId::new("vault-3").unwrap();
    let constitution = Constitution::v1_lab(3).unwrap();
    assert_eq!(constitution.signing_t, 2);
    assert_eq!(constitution.governance_t, 3); // signing_t+1 capped at n

    let ledger =
        Arc::new(InMemoryLedger::genesis(constitution, vec![n1.clone(), n2.clone(), n3.clone()], n1.clone()).unwrap());

    let propose = ProposeEpochAdvance::new(ledger.clone(), n1.clone());
    let p = propose.execute("prop-1").unwrap();
    assert_eq!(p.votes.len(), 1);
    assert_eq!(ledger.epoch().unwrap().number, 0);

    let vote2 = VoteEpochAdvance::new(ledger.clone(), n2.clone());
    let p = vote2.execute("prop-1").unwrap();
    assert_eq!(p.votes.len(), 2);
    assert_eq!(ledger.epoch().unwrap().number, 0);

    let vote3 = VoteEpochAdvance::new(ledger.clone(), n3);
    let p = vote3.execute("prop-1").unwrap();
    assert!(p.closed);
    assert_eq!(ledger.epoch().unwrap().number, 1);
}

#[test]
fn outsider_cannot_propose() {
    let n1 = NodeId::new("vault-1").unwrap();
    let n2 = NodeId::new("vault-2").unwrap();
    let outsider = NodeId::new("evil").unwrap();
    let constitution = Constitution::v1_lab(2).unwrap();
    let ledger = Arc::new(InMemoryLedger::genesis(constitution, vec![n1.clone(), n2], n1).unwrap());
    let propose = ProposeEpochAdvance::new(ledger, outsider);
    assert!(propose.execute("x").is_err());
}
