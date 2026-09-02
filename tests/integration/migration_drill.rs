//! Quantum migration drill tests — state machine transitions, emergency sweep
//! validation, and deposit/withdrawal blocking at each quantum state.
//!
//! Tests verify the monotonic state machine (Q0→Q5), transition authorization,
//! and the emergency readiness gating.

use kerosene_vault::application::{validate_emergency_ready, QuantumMigrationPort, StubQuantumMigrationController};
use kerosene_vault::domain::{DayEpoch, QuantumMigrationConfig, QuantumState, TransitionAuth};

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn epoch(s: &str) -> DayEpoch {
    DayEpoch::parse(s).expect("valid epoch")
}

fn ready_config() -> QuantumMigrationConfig {
    let mut cfg = QuantumMigrationConfig::default_at(epoch("2026-01-01"));
    cfg.emergency_constitution_hash = Some("emergency-hash-deadbeef".into());
    cfg.migration_destination_descriptor = Some("wsh(sortedmulti(3,key1,key2,key3,key4,key5))".into());
    cfg
}

fn config_at(state: QuantumState) -> QuantumMigrationConfig {
    let mut cfg = ready_config();
    cfg.current_state = state;
    cfg
}

// ═══════════════════════════════════════════════════════════════════
// State transition tests
// ═══════════════════════════════════════════════════════════════════

/// Valid: Q0 → Q1 → Q2 → Q3 → Q4 → Q5 transitions all succeed.
#[test]
fn q0_to_q1_to_q2_to_q3_to_q4_to_q5_valid() {
    let mut cfg = ready_config();

    // Q0 → Q1
    let auth =
        cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2026-01-02")).expect("Q0→Q1 should be valid");
    assert_eq!(auth, TransitionAuth::Quorum(5));
    cfg.apply_transition(QuantumState::Q1PqPrepared, "test", epoch("2026-01-02")).expect("Q0→Q1 apply failed");

    // Q1 → Q2
    let auth =
        cfg.validate_transition(QuantumState::Q2ElevatedRisk, 5, &epoch("2026-01-03")).expect("Q1→Q2 should be valid");
    assert_eq!(auth, TransitionAuth::Quorum(5));
    cfg.apply_transition(QuantumState::Q2ElevatedRisk, "test", epoch("2026-01-03")).expect("Q1→Q2 apply failed");

    // Q2 → Q3
    let auth = cfg
        .validate_transition(QuantumState::Q3MigrationRequired, 5, &epoch("2026-01-04"))
        .expect("Q2→Q3 should be valid");
    assert_eq!(auth, TransitionAuth::Quorum(5));
    cfg.apply_transition(QuantumState::Q3MigrationRequired, "test", epoch("2026-01-04")).expect("Q2→Q3 apply failed");

    // Q3 → Q4
    let auth = cfg
        .validate_transition(QuantumState::Q4DepositsDisabled, 5, &epoch("2026-01-05"))
        .expect("Q3→Q4 should be valid");
    assert_eq!(auth, TransitionAuth::QuorumOrAuto);
    cfg.apply_transition(QuantumState::Q4DepositsDisabled, "test", epoch("2026-01-05")).expect("Q3→Q4 apply failed");

    // Q4 → Q5
    let auth = cfg
        .validate_transition(QuantumState::Q5EmergencySweep, 5, &epoch("2026-01-06"))
        .expect("Q4→Q5 should be valid");
    assert_eq!(auth, TransitionAuth::ReducedQuorum(3));
    cfg.apply_transition(QuantumState::Q5EmergencySweep, "test", epoch("2026-01-06")).expect("Q4→Q5 apply failed");

    assert_eq!(cfg.current_state, QuantumState::Q5EmergencySweep);
    assert_eq!(cfg.state_changed_at.as_str(), "2026-01-06");
}

/// Invalid: Q5 → Q1 (reverse transition) must be rejected.
#[test]
fn q5_to_q1_rejected() {
    let cfg = config_at(QuantumState::Q5EmergencySweep);

    let result = cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2026-01-07"));

    assert!(result.is_err(), "Q5→Q1 reverse transition must be rejected");
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        msg.contains("monotonic") || msg.contains("not monotonic") || msg.contains("increases"),
        "Error should mention monotonic constraint: {msg}"
    );
}

/// Invalid: Q0 → Q0 (non-monotonic, same state) must be rejected.
#[test]
fn q0_to_q0_rejected() {
    let cfg = config_at(QuantumState::Q0Normal);

    let result = cfg.validate_transition(QuantumState::Q0Normal, 5, &epoch("2026-01-02"));
    assert!(result.is_err(), "Q0→Q0 must be rejected (not monotonic)");
}

/// Invalid: Q0 → Q3 (skip Q1, Q2) must be rejected.
#[test]
fn q0_to_q3_skip_rejected() {
    let cfg = ready_config();

    let result = cfg.validate_transition(QuantumState::Q3MigrationRequired, 5, &epoch("2026-01-02"));
    assert!(result.is_err(), "Q0→Q3 (skip) must be rejected");
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        msg.contains("gap") || msg.contains("step") || msg.contains("one step"),
        "Error should mention single-step constraint: {msg}"
    );
}

/// Invalid: Q0 → Q1 without emergency_constitution_hash must be rejected.
#[test]
fn q0_to_q1_without_emergency_hash_rejected() {
    let cfg = QuantumMigrationConfig::default_at(epoch("2026-01-01"));
    // No emergency hash set

    let result = cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2026-01-02"));
    assert!(result.is_err(), "Q0→Q1 without emergency_constitution_hash must be rejected");
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("emergency_constitution_hash"), "Error should mention emergency_constitution_hash: {msg}");
}

/// Invalid: Q0 → Q1 without migration_destination_descriptor must be rejected.
#[test]
fn q0_to_q1_without_destination_descriptor_rejected() {
    let mut cfg = QuantumMigrationConfig::default_at(epoch("2026-01-01"));
    cfg.emergency_constitution_hash = Some("hash".into());
    // No destination descriptor

    let result = cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2026-01-02"));
    assert!(result.is_err(), "Q0→Q1 without migration_destination_descriptor must be rejected");
}

// ═══════════════════════════════════════════════════════════════════
// State behavior tests
// ═══════════════════════════════════════════════════════════════════

/// Q0-Q2: deposits allowed. Q3+: deposits blocked.
#[test]
fn deposits_blocked_at_q3_and_above() {
    assert!(QuantumState::Q0Normal.deposits_allowed());
    assert!(QuantumState::Q1PqPrepared.deposits_allowed());
    assert!(QuantumState::Q2ElevatedRisk.deposits_allowed());
    assert!(!QuantumState::Q3MigrationRequired.deposits_allowed());
    assert!(!QuantumState::Q4DepositsDisabled.deposits_allowed());
    assert!(!QuantumState::Q5EmergencySweep.deposits_allowed());
}

/// Q0-Q1: normal signing allowed. Q2+: normal signing blocked.
#[test]
fn normal_signing_blocked_at_q2_and_above() {
    assert!(QuantumState::Q0Normal.normal_signing_allowed());
    assert!(QuantumState::Q1PqPrepared.normal_signing_allowed());
    assert!(!QuantumState::Q2ElevatedRisk.normal_signing_allowed());
    assert!(!QuantumState::Q3MigrationRequired.normal_signing_allowed());
    assert!(!QuantumState::Q4DepositsDisabled.normal_signing_allowed());
    assert!(!QuantumState::Q5EmergencySweep.normal_signing_allowed());
}

/// Q4-Q5: sweep allowed. Q0-Q3: sweep blocked.
#[test]
fn sweep_only_allowed_at_q4_and_q5() {
    assert!(!QuantumState::Q0Normal.sweep_allowed());
    assert!(!QuantumState::Q1PqPrepared.sweep_allowed());
    assert!(!QuantumState::Q2ElevatedRisk.sweep_allowed());
    assert!(!QuantumState::Q3MigrationRequired.sweep_allowed());
    assert!(QuantumState::Q4DepositsDisabled.sweep_allowed());
    assert!(QuantumState::Q5EmergencySweep.sweep_allowed());
}

/// Q5 is emergency mode. All other states are not.
#[test]
fn only_q5_is_emergency() {
    assert!(!QuantumState::Q0Normal.is_emergency());
    assert!(!QuantumState::Q1PqPrepared.is_emergency());
    assert!(!QuantumState::Q2ElevatedRisk.is_emergency());
    assert!(!QuantumState::Q3MigrationRequired.is_emergency());
    assert!(!QuantumState::Q4DepositsDisabled.is_emergency());
    assert!(QuantumState::Q5EmergencySweep.is_emergency());
}

// ═══════════════════════════════════════════════════════════════════
// Emergency sweep validation tests
// ═══════════════════════════════════════════════════════════════════

/// Emergency sweep requires state >= Q4.
#[test]
fn emergency_sweep_requires_q4_or_higher() {
    // Q0: rejected
    let result = validate_emergency_ready(&QuantumMigrationConfig::default_at(epoch("2026-01-01")), 10);
    assert!(result.is_err(), "Q0 must reject emergency sweep");
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("q4"), "Error should mention Q4 requirement: {msg}");

    // Q3: rejected
    let q3_cfg = config_at(QuantumState::Q3MigrationRequired);
    let result = validate_emergency_ready(&q3_cfg, 10);
    assert!(result.is_err(), "Q3 must reject emergency sweep (needs Q4+)");

    // Q4: allowed with UTXOs
    let q4_cfg = config_at(QuantumState::Q4DepositsDisabled);
    let result = validate_emergency_ready(&q4_cfg, 10);
    assert!(result.is_ok(), "Q4 with UTXOs must allow emergency sweep");

    // Q5: allowed with UTXOs
    let q5_cfg = config_at(QuantumState::Q5EmergencySweep);
    let result = validate_emergency_ready(&q5_cfg, 10);
    assert!(result.is_ok(), "Q5 with UTXOs must allow emergency sweep");
}

/// Emergency sweep requires non-empty UTXO inventory.
#[test]
fn emergency_sweep_requires_utxos() {
    let cfg = config_at(QuantumState::Q4DepositsDisabled);
    let result = validate_emergency_ready(&cfg, 0);
    assert!(result.is_err(), "Q4 with 0 UTXOs must reject sweep");
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(msg.contains("no utxos") || msg.contains("empty"), "Error should mention empty UTXOs: {msg}");
}

/// Emergency sweep requires both emergency_constitution_hash and destination_descriptor.
#[test]
fn emergency_sweep_requires_hash_and_descriptor() {
    let mut cfg = config_at(QuantumState::Q4DepositsDisabled);
    cfg.emergency_constitution_hash = None;
    let result = validate_emergency_ready(&cfg, 10);
    assert!(result.is_err(), "Missing emergency hash must reject sweep");

    let mut cfg2 = config_at(QuantumState::Q4DepositsDisabled);
    cfg2.migration_destination_descriptor = None;
    let result = validate_emergency_ready(&cfg2, 10);
    assert!(result.is_err(), "Missing destination descriptor must reject sweep");
}

// ═══════════════════════════════════════════════════════════════════
// Stub controller tests
// ═══════════════════════════════════════════════════════════════════

/// Stub controller returns current state.
#[test]
fn stub_controller_state_is_q0_by_default() {
    let cfg = QuantumMigrationConfig::default_at(epoch("2026-01-01"));
    let ctl = StubQuantumMigrationController::new(cfg);
    assert_eq!(ctl.current_state(), QuantumState::Q0Normal);
}

/// Stub controller inventory is empty.
#[test]
fn stub_controller_inventory_empty() {
    let cfg = ready_config();
    let ctl = StubQuantumMigrationController::new(cfg);
    let inv = ctl.utxo_inventory().expect("inventory should succeed");
    assert!(inv.is_empty());
}

/// Stub controller drill returns not-implemented.
#[test]
fn stub_controller_drill_not_implemented() {
    let cfg = ready_config();
    let ctl = StubQuantumMigrationController::new(cfg);
    let report = ctl.execute_drill().expect("drill should not panic");
    assert!(!report.is_success());
    assert!(report.errors.iter().any(|e| e.contains("not implemented")));
}

/// Stub controller sweep returns not-implemented.
#[test]
fn stub_controller_sweep_not_implemented() {
    let cfg = ready_config();
    let ctl = StubQuantumMigrationController::new(cfg);
    let report = ctl.sweep_all().expect("sweep should not panic");
    assert!(!report.is_success());
    assert!(report.errors.iter().any(|e| e.contains("not implemented")));
}

// ═══════════════════════════════════════════════════════════════════
// Serialization tests
// ═══════════════════════════════════════════════════════════════════

/// QuantumState serializes/deserializes via numeric level.
#[test]
fn quantum_state_level_roundtrip() {
    let states = [
        QuantumState::Q0Normal,
        QuantumState::Q1PqPrepared,
        QuantumState::Q2ElevatedRisk,
        QuantumState::Q3MigrationRequired,
        QuantumState::Q4DepositsDisabled,
        QuantumState::Q5EmergencySweep,
    ];

    for state in &states {
        let level = state.level();
        let parsed = QuantumState::from_level(level).expect("valid level");
        assert_eq!(*state, parsed, "Roundtrip failed for {:?}", state);
    }

    // Invalid level
    assert!(QuantumState::from_level(6).is_none());
    assert!(QuantumState::from_level(255).is_none());
}

/// State ordering is monotonic.
#[test]
fn state_ordering() {
    assert!(QuantumState::Q0Normal < QuantumState::Q1PqPrepared);
    assert!(QuantumState::Q1PqPrepared < QuantumState::Q2ElevatedRisk);
    assert!(QuantumState::Q2ElevatedRisk < QuantumState::Q3MigrationRequired);
    assert!(QuantumState::Q3MigrationRequired < QuantumState::Q4DepositsDisabled);
    assert!(QuantumState::Q4DepositsDisabled < QuantumState::Q5EmergencySweep);
}
