//! Quantum migration state machine for on-chain fund sweep strategy.
//!
//! BIP 341 Taproot exposes the tweaked x-only pubkey in the witness program,
//! making the omnibus address vulnerable to Shor's ECDLP attack. This module
//! defines a monotonic state machine (Q0→Q5) that progressively locks down
//! deposits and authorizes sweeps.
//!
//! **Monotonic invariant:** state only increases, never decreases.
//! Return to Q0 requires full mesh redeployment with fresh key material.

use crate::{DayEpoch, DomainError};

/// Quantum migration states (monotonic: Q0 → Q5).
///
/// | State | Name              | Deposits | Signs    | Sweep |
/// |-------|-------------------|----------|----------|-------|
/// | Q0    | Normal            | Open     | Normal   | No    |
/// | Q1    | Post-Quantum Prep | Open     | Normal   | No    |
/// | Q2    | Elevated Risk     | Open     | Reduced  | No    |
/// | Q3    | Migration Required| Blocked  | Reduced  | Prep  |
/// | Q4    | Deposits Disabled | Blocked  | Admin    | Yes   |
/// | Q5    | Emergency Sweep   | Blocked  | Reduced  | Max   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum QuantumState {
    /// Normal operation — no threat detected.
    Q0Normal = 0,
    /// Post-quantum prepared — hybrid envelopes active, migration plan set.
    Q1PqPrepared = 1,
    /// Elevated risk — external threat detected, reduced permanence limits.
    Q2ElevatedRisk = 2,
    /// Migration required — deposits blocked, sweep preparation active.
    Q3MigrationRequired = 3,
    /// Deposits disabled — sweep in progress, new deposits rejected.
    Q4DepositsDisabled = 4,
    /// Emergency sweep — sweep all UTXOs, ignore caps, max fee priority.
    Q5EmergencySweep = 5,
}

impl QuantumState {
    /// Returns the numeric level for comparisons and monotonic checks.
    pub fn level(self) -> u8 {
        self as u8
    }

    /// Deposits allowed from KFE?
    pub fn deposits_allowed(self) -> bool {
        matches!(self, Self::Q0Normal | Self::Q1PqPrepared | Self::Q2ElevatedRisk)
    }

    /// Normal signing (withdrawal) allowed?
    pub fn normal_signing_allowed(self) -> bool {
        matches!(self, Self::Q0Normal | Self::Q1PqPrepared)
    }

    /// Sweep operations permitted?
    pub fn sweep_allowed(self) -> bool {
        matches!(self, Self::Q4DepositsDisabled | Self::Q5EmergencySweep)
    }

    /// Emergency mode active (Q5)?
    pub fn is_emergency(self) -> bool {
        self == Self::Q5EmergencySweep
    }

    /// Human-readable name for logging/API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Q0Normal => "Q0_NORMAL",
            Self::Q1PqPrepared => "Q1_PQ_PREPARED",
            Self::Q2ElevatedRisk => "Q2_ELEVATED_RISK",
            Self::Q3MigrationRequired => "Q3_MIGRATION_REQUIRED",
            Self::Q4DepositsDisabled => "Q4_DEPOSITS_DISABLED",
            Self::Q5EmergencySweep => "Q5_EMERGENCY_SWEEP",
        }
    }

    /// Parse numeric level to state.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Q0Normal),
            1 => Some(Self::Q1PqPrepared),
            2 => Some(Self::Q2ElevatedRisk),
            3 => Some(Self::Q3MigrationRequired),
            4 => Some(Self::Q4DepositsDisabled),
            5 => Some(Self::Q5EmergencySweep),
            _ => None,
        }
    }
}

/// UTXO record for quantum migration inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRecord {
    /// Transaction id (hex, 64 chars).
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Value in satoshis.
    pub amount_sat: u64,
    /// Block confirmations.
    pub confirmations: u64,
    /// Script type: "p2tr", "p2wpkh", "p2wsh", "p2sh", "p2pkh".
    pub script_type: String,
    /// Pubkey exposed in output (true for p2tr, p2wpkh, p2pkh).
    pub pubkey_exposed: bool,
    /// Epochs since first confirmation.
    pub age_epochs: u64,
}

/// Report from a migration drill (testnet only).
#[derive(Debug, Clone)]
pub struct DrillReport {
    /// Total drill duration in milliseconds.
    pub duration_ms: u64,
    /// Number of UTXOs swept.
    pub utxos_swept: u64,
    /// Total fees spent in satoshis.
    pub fees_spent_sat: u64,
    /// Errors encountered (empty = success).
    pub errors: Vec<String>,
}

impl DrillReport {
    pub fn success(utxos: u64, fees: u64, duration_ms: u64) -> Self {
        Self { duration_ms, utxos_swept: utxos, fees_spent_sat: fees, errors: vec![] }
    }

    pub fn failed(errors: Vec<String>) -> Self {
        Self { duration_ms: 0, utxos_swept: 0, fees_spent_sat: 0, errors }
    }

    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Report from a real emergency sweep.
#[derive(Debug, Clone)]
pub struct SweepReport {
    /// Total sweep duration in milliseconds.
    pub duration_ms: u64,
    /// Number of UTXOs swept.
    pub utxos_swept: u64,
    /// Total fees spent in satoshis.
    pub fees_spent_sat: u64,
    /// Errors encountered (empty = success).
    pub errors: Vec<String>,
    /// Sweep transaction ids.
    pub txids: Vec<String>,
}

impl SweepReport {
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Quantum migration configuration persisted in the mesh constitution.
///
/// Added as `quantum_migration` block in [`crate::Constitution`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantumMigrationConfig {
    /// Current state (monotonic).
    pub current_state: QuantumState,
    /// Day epoch when state last changed.
    pub state_changed_at: DayEpoch,
    /// Descriptor for migration destination (committed at Q1).
    pub migration_destination_descriptor: Option<String>,
    /// Emergency constitution hash for reduced-quorum sweep (committed at Q1).
    pub emergency_constitution_hash: Option<String>,
    /// Day epoch of last drill execution.
    pub last_drill_at: Option<DayEpoch>,
    /// Number of epochs to wait in Q3 before auto-advancing to Q4.
    pub auto_advance_epochs: u64,
}

impl QuantumMigrationConfig {
    /// Default: Q0, no migration config set.
    pub fn default_at(epoch: DayEpoch) -> Self {
        Self {
            current_state: QuantumState::Q0Normal,
            state_changed_at: epoch,
            migration_destination_descriptor: None,
            emergency_constitution_hash: None,
            last_drill_at: None,
            auto_advance_epochs: 3,
        }
    }

    /// Validate a state transition. Monotonic: new > current.
    /// Returns the conditions that must be satisfied for this transition.
    pub fn validate_transition(
        &self,
        new_state: QuantumState,
        quorum_size: usize,
        current_epoch: &DayEpoch,
    ) -> Result<TransitionAuth, DomainError> {
        if new_state <= self.current_state {
            return Err(DomainError::InvalidConstitution(format!(
                "quantum state transition denied: {} → {} is not monotonic (state only increases)",
                self.current_state.as_str(),
                new_state.as_str()
            )));
        }
        // Validate that new_state is exactly one step ahead (no skipping).
        let current_level = self.current_state.level();
        let new_level = new_state.level();
        // Allow single-step or emergency jump Q4→Q5 only.
        if new_level != current_level + 1 && !(current_level == 4 && new_level == 5) {
            return Err(DomainError::InvalidConstitution(format!(
                "quantum state can only advance one step at a time: {} → {} invalid (gap > 1)",
                self.current_state.as_str(),
                new_state.as_str()
            )));
        }

        let auth = match new_state {
            QuantumState::Q0Normal => {
                unreachable!("cannot transition down to Q0")
            }
            QuantumState::Q1PqPrepared => TransitionAuth::Quorum(quorum_size),
            QuantumState::Q2ElevatedRisk => TransitionAuth::Quorum(quorum_size),
            QuantumState::Q3MigrationRequired => TransitionAuth::Quorum(quorum_size),
            QuantumState::Q4DepositsDisabled => {
                // Auto-advance after N epochs in Q3, or quorum override.
                let _ = current_epoch; // auto-advance computed in controller
                TransitionAuth::QuorumOrAuto
            }
            QuantumState::Q5EmergencySweep => {
                // Reduced quorum: 2/3 with minimum 2 vaults.
                let reduced = quorum_size.max(2).min(quorum_size * 2 / 3).max(2);
                TransitionAuth::ReducedQuorum(reduced)
            }
        };

        // Q1→Q5: must have emergency constitution hash and migration descriptor.
        if new_state >= QuantumState::Q1PqPrepared && self.emergency_constitution_hash.is_none() {
            return Err(DomainError::InvalidConstitution(
                "quantum migration requires emergency_constitution_hash set at Q1+".into(),
            ));
        }
        if new_state >= QuantumState::Q1PqPrepared && self.migration_destination_descriptor.is_none() {
            return Err(DomainError::InvalidConstitution(
                "quantum migration requires migration_destination_descriptor set at Q1+".into(),
            ));
        }

        Ok(auth)
    }

    /// Apply a validated transition.
    pub fn apply_transition(
        &mut self,
        new_state: QuantumState,
        reason: &str,
        epoch: DayEpoch,
    ) -> Result<(), DomainError> {
        // validate_transition must be called first; this is the commit step.
        self.current_state = new_state;
        self.state_changed_at = epoch;
        // Log reason via DomainError channel (adapter should persist to ledger).
        let _ = reason;
        Ok(())
    }
}

/// Required authorization for a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionAuth {
    /// Full governance quorum required.
    Quorum(usize),
    /// Quorum or automatic (timed) advance.
    QuorumOrAuto,
    /// Reduced quorum for emergency (2/3 with minimum 2 vaults).
    ReducedQuorum(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DayEpoch;

    fn epoch(s: &str) -> DayEpoch {
        DayEpoch::parse(s).unwrap()
    }

    #[test]
    fn state_ordering_is_monotonic() {
        assert!(QuantumState::Q0Normal < QuantumState::Q5EmergencySweep);
        assert!(QuantumState::Q2ElevatedRisk < QuantumState::Q3MigrationRequired);
        assert!(QuantumState::Q3MigrationRequired < QuantumState::Q4DepositsDisabled);
    }

    #[test]
    fn deposits_blocked_at_q3() {
        assert!(QuantumState::Q0Normal.deposits_allowed());
        assert!(QuantumState::Q2ElevatedRisk.deposits_allowed());
        assert!(!QuantumState::Q3MigrationRequired.deposits_allowed());
        assert!(!QuantumState::Q4DepositsDisabled.deposits_allowed());
        assert!(!QuantumState::Q5EmergencySweep.deposits_allowed());
    }

    #[test]
    fn sweep_only_in_q4_q5() {
        assert!(!QuantumState::Q0Normal.sweep_allowed());
        assert!(!QuantumState::Q3MigrationRequired.sweep_allowed());
        assert!(QuantumState::Q4DepositsDisabled.sweep_allowed());
        assert!(QuantumState::Q5EmergencySweep.sweep_allowed());
    }

    #[test]
    fn normal_signing_stops_at_q2() {
        assert!(QuantumState::Q0Normal.normal_signing_allowed());
        assert!(QuantumState::Q1PqPrepared.normal_signing_allowed());
        assert!(!QuantumState::Q2ElevatedRisk.normal_signing_allowed());
        assert!(!QuantumState::Q3MigrationRequired.normal_signing_allowed());
    }

    #[test]
    fn validate_monotonic_only_increases() {
        let mut cfg = QuantumMigrationConfig::default_at(epoch("2025-01-01"));
        cfg.emergency_constitution_hash = Some("abc123".into());
        cfg.migration_destination_descriptor = Some("wsh(sortedmulti(3,...))".into());

        // Valid: Q0→Q1
        assert!(cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2025-01-02")).is_ok());

        // Invalid: Q0→Q2 (skip Q1)
        assert!(cfg.validate_transition(QuantumState::Q2ElevatedRisk, 5, &epoch("2025-01-02")).is_err());

        // Invalid: Q0→Q0 (not monotonic)
        assert!(cfg.validate_transition(QuantumState::Q0Normal, 5, &epoch("2025-01-02")).is_err());
    }

    #[test]
    fn transition_requires_descriptor_and_hash() {
        let cfg = QuantumMigrationConfig::default_at(epoch("2025-01-01"));
        // Missing descriptor and emergency hash — should fail.
        assert!(cfg.validate_transition(QuantumState::Q1PqPrepared, 5, &epoch("2025-01-02")).is_err());
    }

    #[test]
    fn emergency_uses_reduced_quorum() {
        let mut cfg = QuantumMigrationConfig::default_at(epoch("2025-01-01"));
        cfg.current_state = QuantumState::Q4DepositsDisabled;
        cfg.emergency_constitution_hash = Some("abc123".into());
        cfg.migration_destination_descriptor = Some("wsh(...)".into());

        let auth = cfg.validate_transition(QuantumState::Q5EmergencySweep, 5, &epoch("2025-01-03")).unwrap();
        assert_eq!(auth, TransitionAuth::ReducedQuorum(3));
        // 5 vaults → 2/3 = 3, min 2 → 3
    }

    #[test]
    fn reduced_quorum_minimum_two() {
        let mut cfg = QuantumMigrationConfig::default_at(epoch("2025-01-01"));
        cfg.current_state = QuantumState::Q4DepositsDisabled;
        cfg.emergency_constitution_hash = Some("abc123".into());
        cfg.migration_destination_descriptor = Some("wsh(...)".into());

        // 3 vaults → 2/3 = 2, min 2 → 2
        let auth = cfg.validate_transition(QuantumState::Q5EmergencySweep, 3, &epoch("2025-01-03")).unwrap();
        assert_eq!(auth, TransitionAuth::ReducedQuorum(2));
    }

    #[test]
    fn serialization_roundtrip_via_level() {
        for level in 0..=5 {
            let state = QuantumState::from_level(level).unwrap();
            assert_eq!(state.level(), level);
        }
        assert!(QuantumState::from_level(6).is_none());
    }

    #[test]
    fn apply_transition_updates_state() {
        let mut cfg = QuantumMigrationConfig::default_at(epoch("2025-01-01"));
        cfg.emergency_constitution_hash = Some("abc123".into());
        cfg.migration_destination_descriptor = Some("wsh(...)".into());

        cfg.apply_transition(QuantumState::Q1PqPrepared, "quorum decision", epoch("2025-01-02")).unwrap();

        assert_eq!(cfg.current_state, QuantumState::Q1PqPrepared);
        assert_eq!(cfg.state_changed_at.as_str(), "2025-01-02");
    }

    #[test]
    fn drill_report_success_empty_errors() {
        let report = DrillReport::success(10, 5000, 120_000);
        assert!(report.is_success());
        assert_eq!(report.utxos_swept, 10);
    }

    #[test]
    fn drill_report_failure_has_errors() {
        let report = DrillReport::failed(vec!["input 3 invalid".into()]);
        assert!(!report.is_success());
    }

    #[test]
    fn sweep_report_tracks_txids() {
        let report = SweepReport {
            duration_ms: 60_000,
            utxos_swept: 50,
            fees_spent_sat: 100_000,
            errors: vec![],
            txids: vec!["abcdef...".into(), "123456...".into()],
        };
        assert!(report.is_success());
        assert_eq!(report.txids.len(), 2);
    }
}
