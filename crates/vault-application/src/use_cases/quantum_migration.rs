//! Quantum migration controller — on-chain fund sweep strategy for the vault mesh.
//!
//! Coordinates state transitions, UTXO inventory, PSBT template preparation,
//! and emergency sweep operations across the vault mesh.
//!
//! **Stub:** Sweep operations return "not yet implemented" until PSBT signing
//! adapters and UTXO index are wired.

use vault_domain::{DayEpoch, DomainError, DrillReport, QuantumMigrationConfig, QuantumState, SweepReport, UtxoRecord};

/// Port defining quantum migration operations.
///
/// All state transitions require quorum authorization. Sweep operations
/// require full mesh coordination through the FROST signing adapter.
pub trait QuantumMigrationPort: Send + Sync {
    /// Current quantum migration state.
    fn current_state(&self) -> QuantumState;

    /// Full UTXO inventory snapshot.
    /// Returns all UTXOs at mesh-controlled addresses with metadata.
    fn utxo_inventory(&self) -> Result<Vec<UtxoRecord>, DomainError>;

    /// Prepare unsigned PSBTs for emergency sweep.
    /// One PSBT per bucket (USERS, CHANNELS) with all UTXOs as inputs
    /// and migration destination as output.
    fn prepare_emergency_psbts(&self) -> Result<Vec<PsbtSkeleton>, DomainError>;

    /// Transition to a new quantum state.
    /// Validates monotonic invariant and quorum requirements.
    fn transition_to(&self, new_state: QuantumState, reason: &str) -> Result<(), DomainError>;

    /// Execute a migration drill (testnet only).
    /// Builds unsigned PSBTs, co-signs, broadcasts, and verifies.
    fn execute_drill(&self) -> Result<DrillReport, DomainError>;

    /// Emergency sweep all UTXOs to migration destination.
    /// Real sweep — ignores caps, uses max fee priority in Q5.
    fn sweep_all(&self) -> Result<SweepReport, DomainError>;
}

/// PSBT skeleton (unsigned, no signatures).
/// Adapter layer builds actual `bitcoin::Psbt` from this skeleton.
#[derive(Debug, Clone)]
pub struct PsbtSkeleton {
    /// PSBT identifier for tracking.
    pub id: String,
    /// Hex-encoded serialized PSBT.
    pub psbt_hex: String,
    /// Total input amount in satoshis.
    pub total_input_sats: u64,
    /// Fee estimate in satoshis.
    pub fee_estimate_sats: u64,
    /// Number of UTXOs swept.
    pub num_inputs: usize,
    /// Migration destination address.
    pub destination: String,
}

/// Stub implementation of QuantumMigrationPort.
///
/// Returns "not yet implemented" for sweep operations. State transitions
/// are validated but not persisted (requires adapter wiring).
pub struct StubQuantumMigrationController {
    state: QuantumState,
    config: QuantumMigrationConfig,
}

impl StubQuantumMigrationController {
    /// Creates a stub controller initialized from the configuration's current state.
    pub fn new(config: QuantumMigrationConfig) -> Self {
        let state = config.current_state;
        Self { state, config }
    }

    /// Read-only snapshot of current config.
    pub fn config(&self) -> &QuantumMigrationConfig {
        &self.config
    }
}

impl QuantumMigrationPort for StubQuantumMigrationController {
    /// Returns the controller's initial state; this stub never mutates it.
    fn current_state(&self) -> QuantumState {
        self.state
    }

    /// Returns an empty inventory because the UTXO index is not wired in this stub.
    fn utxo_inventory(&self) -> Result<Vec<UtxoRecord>, DomainError> {
        // Stub: returns empty inventory. Real impl queries Bitcoin Core
        // via UTXO index adapter (listunspent + taproot filter).
        Ok(vec![])
    }

    /// Returns no PSBT skeletons because emergency PSBT construction is not implemented.
    fn prepare_emergency_psbts(&self) -> Result<Vec<PsbtSkeleton>, DomainError> {
        // Stub: PSBT construction not implemented.
        // Real impl uses frost_tr_bitcoin adapter + UTXO inventory + fee estimator.
        Ok(vec![])
    }

    /// Validates a transition against placeholder quorum/epoch values without persisting it.
    fn transition_to(&self, new_state: QuantumState, reason: &str) -> Result<(), DomainError> {
        // Stub: validates transition conditions but does not persist.
        // Real impl would: (1) validate monotonic, (2) verify quorum via
        // mesh governance, (3) persist to ledger, (4) emit KFE notification.
        let epoch = DayEpoch::parse("2025-01-01")?; // placeholder; real impl uses ClockPort

        self.config.validate_transition(new_state, 5, &epoch)?;

        let _ = reason;
        // State not mutated — stub is read-only. Real impl would update and persist.
        Ok(())
    }

    /// Returns a failed report because migration drill execution is not implemented.
    fn execute_drill(&self) -> Result<DrillReport, DomainError> {
        // Stub: drill not implemented. Real impl:
        // 1. Verify network is testnet (drills forbidden on mainnet).
        // 2. Snapshot UTXO inventory.
        // 3. Build unsigned PSBTs.
        // 4. Mesh co-signs via FROST adapter.
        // 5. Broadcast sweep transaction.
        // 6. Verify confirmations at destination.
        Ok(DrillReport::failed(vec!["drill not implemented — stub returns no-op".into()]))
    }

    /// Returns a failed report because emergency sweep execution is not implemented.
    fn sweep_all(&self) -> Result<SweepReport, DomainError> {
        // Stub: sweep not implemented. Real impl:
        // 1. Verify state >= Q4.
        // 2. Build PSBTs from emergency templates.
        // 3. Set fee strategy based on quantum state (normal / elevated / max).
        // 4. Mesh co-signs with appropriate quorum (normal or reduced).
        // 5. Broadcast all sweep transactions.
        // 6. Verify confirmations at migration destination.
        // 7. Emit KFE notification + ledger event.
        Ok(SweepReport {
            duration_ms: 0,
            utxos_swept: 0,
            fees_spent_sat: 0,
            errors: vec!["sweep not implemented — stub returns no-op".into()],
            txids: vec![],
        })
    }
}

/// Validate that the controller is ready for Q5 emergency sweep.
///
/// Required preconditions:
/// - State >= Q4
/// - Emergency constitution hash is set
/// - Migration destination descriptor is set
/// - UTXO inventory is non-empty (if there are funds to sweep)
pub fn validate_emergency_ready(config: &QuantumMigrationConfig, utxo_count: usize) -> Result<(), DomainError> {
    if config.current_state < QuantumState::Q4DepositsDisabled {
        return Err(DomainError::InvalidConstitution(format!(
            "emergency sweep requires state >= Q4, current: {}",
            config.current_state.as_str()
        )));
    }
    if config.emergency_constitution_hash.is_none() {
        return Err(DomainError::InvalidConstitution("emergency constitution hash not set".into()));
    }
    if config.migration_destination_descriptor.is_none() {
        return Err(DomainError::InvalidConstitution("migration destination descriptor not set".into()));
    }
    if utxo_count == 0 {
        return Err(DomainError::InvalidConstitution("no UTXOs to sweep — inventory empty".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_domain::DayEpoch;

    fn test_epoch() -> DayEpoch {
        DayEpoch::parse("2025-06-01").unwrap()
    }

    fn ready_config_q4() -> QuantumMigrationConfig {
        let mut cfg = QuantumMigrationConfig::default_at(test_epoch());
        cfg.current_state = QuantumState::Q4DepositsDisabled;
        cfg.emergency_constitution_hash = Some("deadbeef".into());
        cfg.migration_destination_descriptor = Some("wsh(sortedmulti(3,key1,key2,key3,key4,key5))".into());
        cfg
    }

    #[test]
    fn stub_controller_returns_state() {
        let cfg = QuantumMigrationConfig::default_at(test_epoch());
        let ctl = StubQuantumMigrationController::new(cfg.clone());
        assert_eq!(ctl.current_state(), QuantumState::Q0Normal);
        assert_eq!(ctl.config().current_state, QuantumState::Q0Normal);
    }

    #[test]
    fn stub_inventory_is_empty() {
        let cfg = QuantumMigrationConfig::default_at(test_epoch());
        let ctl = StubQuantumMigrationController::new(cfg);
        let inv = ctl.utxo_inventory().unwrap();
        assert!(inv.is_empty());
    }

    #[test]
    fn stub_psbts_are_empty() {
        let cfg = QuantumMigrationConfig::default_at(test_epoch());
        let ctl = StubQuantumMigrationController::new(cfg);
        let psbts = ctl.prepare_emergency_psbts().unwrap();
        assert!(psbts.is_empty());
    }

    #[test]
    fn stub_drill_returns_not_implemented() {
        let cfg = QuantumMigrationConfig::default_at(test_epoch());
        let ctl = StubQuantumMigrationController::new(cfg);
        let report = ctl.execute_drill().unwrap();
        assert!(!report.is_success());
        assert!(report.errors[0].contains("not implemented"));
    }

    #[test]
    fn stub_sweep_returns_not_implemented() {
        let cfg = QuantumMigrationConfig::default_at(test_epoch());
        let ctl = StubQuantumMigrationController::new(cfg);
        let report = ctl.sweep_all().unwrap();
        assert!(!report.is_success());
        assert!(report.errors[0].contains("not implemented"));
    }

    #[test]
    fn validate_emergency_ready_requires_q4() {
        let result = validate_emergency_ready(&QuantumMigrationConfig::default_at(test_epoch()), 10);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(">= Q4"));
    }

    #[test]
    fn validate_emergency_ready_requires_hash() {
        let mut cfg = ready_config_q4();
        cfg.emergency_constitution_hash = None;
        let result = validate_emergency_ready(&cfg, 10);
        assert!(result.is_err());
    }

    #[test]
    fn validate_emergency_ready_requires_utxos() {
        let cfg = ready_config_q4();
        let result = validate_emergency_ready(&cfg, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no UTXOs"));
    }

    #[test]
    fn validate_emergency_ready_passes_with_utxos() {
        let cfg = ready_config_q4();
        assert!(validate_emergency_ready(&cfg, 5).is_ok());
    }
}
