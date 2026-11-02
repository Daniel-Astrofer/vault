use crate::{DayEpoch, DomainError, Measurement, MinerPayoutCadence, ProfitSplits, QuantumMigrationConfig};

/// Cryptographic capability requirements for downgrade prevention.
///
/// All checks are fail-closed: if a capability is missing or below minimum,
/// the operation is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DowngradePolicy {
    /// Minimum NIST security category for KEM (ML-KEM-768 = category 3).
    pub pq_kem_security_category: u8,
    /// Minimum NIST security category for signatures (ML-DSA-65 = category 3).
    pub pq_signature_security_category: u8,
    /// Minimum symmetric security bits (AES-256 = 256).
    pub symmetric_security_bits: u16,
    /// Hybrid KEM (X25519 + ML-KEM) is mandatory.
    pub hybrid_kem_required: bool,
    /// Hybrid signature (Ed25519 + ML-DSA) is mandatory.
    pub hybrid_signature_required: bool,
    /// If true, reject classical-only messages entirely.
    pub require_pq_signatures: bool,
    /// If true, reject envelopes without ML-KEM.
    pub require_pq_kem: bool,
}

impl Default for DowngradePolicy {
    fn default() -> Self {
        Self {
            pq_kem_security_category: 3,
            pq_signature_security_category: 3,
            symmetric_security_bits: 256,
            hybrid_kem_required: true,
            hybrid_signature_required: true,
            require_pq_signatures: true,
            require_pq_kem: true,
        }
    }
}

impl DowngradePolicy {
    /// Enforce the minimum supported post-quantum and symmetric security categories.
    ///
    /// The boolean requirement flags are descriptive policy switches and are
    /// not normalized or cross-checked by this method.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.pq_kem_security_category < 3 {
            return Err(DomainError::InvalidConstitution(format!(
                "pq_kem_security_category {} < 3",
                self.pq_kem_security_category
            )));
        }
        if self.pq_signature_security_category < 3 {
            return Err(DomainError::InvalidConstitution(format!(
                "pq_signature_security_category {} < 3",
                self.pq_signature_security_category
            )));
        }
        if self.symmetric_security_bits < 256 {
            return Err(DomainError::InvalidConstitution(format!(
                "symmetric_security_bits {} < 256",
                self.symmetric_security_bits
            )));
        }
        Ok(())
    }
}

/// Wire-format versioning for all vault mesh protocols.
///
/// Each format has its own version number. Unknown or below-minimum versions
/// are rejected (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatVersions {
    /// Version of settlement intent records accepted by this constitution.
    pub intent: u16,
    /// Version of settlement receipt records accepted by this constitution.
    pub receipt: u16,
    /// Version of encrypted share envelopes accepted by this constitution.
    pub share_envelope: u16,
    /// Version of distributed key generation transcripts accepted by this constitution.
    pub dkg_transcript: u16,
    /// Version of resharing transcripts accepted by this constitution.
    pub reshare_transcript: u16,
    /// Version of certificates accepted by this constitution.
    pub certificate: u16,
    /// Version of audit records accepted by this constitution.
    pub audit_record: u16,
    /// Minimum protocol version accepted.
    pub min_protocol_version: u16,
    /// Current protocol version negotiated via `X-Protocol-Version`.
    pub current_protocol_version: u16,
}

impl Default for FormatVersions {
    /// Set all format and protocol version fields to the initial version `1`.
    fn default() -> Self {
        Self {
            intent: 1,
            receipt: 1,
            share_envelope: 1,
            dkg_transcript: 1,
            reshare_transcript: 1,
            certificate: 1,
            audit_record: 1,
            min_protocol_version: 1,
            current_protocol_version: 1,
        }
    }
}

impl FormatVersions {
    /// Validate that a received format_version is acceptable.
    pub fn accept(&self, received_version: u16, min_version: u16) -> Result<(), DomainError> {
        if received_version < min_version {
            return Err(DomainError::InvalidIntent(format!(
                "format_version {} below minimum {}",
                received_version, min_version
            )));
        }
        if received_version > self.current_protocol_version {
            return Err(DomainError::InvalidIntent(format!(
                "unknown format_version {} (current max {})",
                received_version, self.current_protocol_version
            )));
        }
        Ok(())
    }
}

/// Active security/economic constitution anchored on the vault ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constitution {
    /// Monotonic constitution schema/revision number.
    pub version: u32,
    /// Aggregate withdrawal ceiling for one day, in satoshis.
    pub max_withdraw_per_day_sats: u64,
    /// Maximum amount for an individual withdrawal, in satoshis.
    pub max_withdraw_per_tx_sats: u64,
    /// Number of nodes in the active signing set.
    pub signing_n: usize,
    /// Minimum signing participants required by the configured quorum.
    pub signing_t: usize,
    /// Minimum governance voters required to amend governed state.
    pub governance_t: usize,
    /// Current miner reward fraction, in basis points of profit.
    pub p_reward_bps: u32,
    /// Upper bound allowed for the miner reward fraction, in basis points.
    pub p_reward_max_bps: u32,
    /// Distribution of realized profit among operational child buckets.
    pub profit_splits: ProfitSplits,
    /// Mesh-governed miner payout frequency. Amended by quorum vote.
    /// Default: daily. Override at genesis via `VAULT_MINER_PAYOUT_FREQUENCY`.
    /// TODO(4.1): Final value pending stakeholder decision.
    pub payout_frequency: MinerPayoutCadence,
    /// Identifier for the cryptographic suite selected by the mesh.
    pub crypto_suite_id: String,
    /// Canonical measurement hash over the fields included by [`Self::compute_hash`].
    pub hash: String,
    /// Pinned code/binary measurement for HW/staging attestation binding.
    /// Not part of `hash` material (derived/bound separately to avoid circularity).
    pub measurement_pin: Option<Measurement>,
    /// Anti-downgrade policy: capability-based minimum requirements.
    pub downgrade_policy: DowngradePolicy,
    /// Wire-format versioning for all protocols.
    pub format_versions: FormatVersions,
    /// Hash of previous constitution for rollback prevention (chain).
    pub previous_hash: Option<String>,
    /// Quantum migration state and configuration (Item 0.6).
    /// Defaults to Q0 (normal). Not in hash — mutates monotonic outside versioning.
    pub quantum_migration: QuantumMigrationConfig,
}

impl Constitution {
    /// Build the lab dry-run constitution for `n` signing nodes.
    ///
    /// Uses a two-thirds signing threshold, a stricter governance threshold,
    /// lab profit splits, default downgrade/version policies, and a zero-time
    /// quantum-migration epoch. Rejects sets smaller than two nodes.
    pub fn v1_lab(n: usize) -> Result<Self, DomainError> {
        if n < 2 {
            return Err(DomainError::InvalidConstitution("signing_n must be >= 2".into()));
        }
        let signing_t = quorum_two_thirds(n);
        let governance_t = (signing_t + 1).min(n);
        let profit_splits = ProfitSplits::lab_dry_run();
        profit_splits.validate()?;
        let mut c = Self {
            version: 1,
            max_withdraw_per_day_sats: 1_000_000,
            max_withdraw_per_tx_sats: 250_000,
            signing_n: n,
            signing_t,
            governance_t,
            p_reward_bps: 100,
            p_reward_max_bps: 800,
            profit_splits,
            // TODO(4.1): Final profit split values pending stakeholder decision.
            // Current lab dry-run: miners_bps=0, channels=50%, infra=50%.
            payout_frequency: MinerPayoutCadence::Daily,
            crypto_suite_id: "hybrid-v1-placeholder".into(),
            hash: String::new(),
            measurement_pin: None,
            downgrade_policy: DowngradePolicy::default(),
            format_versions: FormatVersions::default(),
            previous_hash: None,
            quantum_migration: QuantumMigrationConfig::default_at(DayEpoch::from_unix_secs(0)),
        };
        c.hash = c.compute_hash();
        c.ensure_measurement_pin();
        Ok(c)
    }

    /// Open economy constitution: `p%=1%` miners split live (F9).
    ///
    /// Uses the same threshold and withdrawal defaults as the lab constitution,
    /// but routes the configured miner reward through [`ProfitSplits::open_with_reward`].
    pub fn v1_open(n: usize) -> Result<Self, DomainError> {
        if n < 2 {
            return Err(DomainError::InvalidConstitution("signing_n must be >= 2".into()));
        }
        let signing_t = quorum_two_thirds(n);
        let governance_t = (signing_t + 1).min(n);
        let p_reward_bps = 100;
        let profit_splits = ProfitSplits::open_with_reward(p_reward_bps)?;
        let mut c = Self {
            version: 2,
            max_withdraw_per_day_sats: 1_000_000,
            max_withdraw_per_tx_sats: 250_000,
            signing_n: n,
            signing_t,
            governance_t,
            p_reward_bps,
            p_reward_max_bps: 800,
            profit_splits,
            payout_frequency: MinerPayoutCadence::Daily,
            crypto_suite_id: "hybrid-v1-placeholder".into(),
            hash: String::new(),
            measurement_pin: None,
            downgrade_policy: DowngradePolicy::default(),
            format_versions: FormatVersions::default(),
            previous_hash: None,
            quantum_migration: QuantumMigrationConfig::default_at(DayEpoch::from_unix_secs(0)),
        };
        c.hash = c.compute_hash();
        c.ensure_measurement_pin();
        Ok(c)
    }

    /// If no explicit pin, bind attestation to the constitution hash bytes.
    pub fn ensure_measurement_pin(&mut self) {
        if self.measurement_pin.is_none() {
            self.measurement_pin = Some(Measurement::from_bytes(self.hash.as_bytes()));
        }
    }

    /// Return the explicit attestation measurement pin, falling back to a digest of `hash`.
    pub fn measurement_pin_or_hash(&self) -> Measurement {
        self.measurement_pin.clone().unwrap_or_else(|| Measurement::from_bytes(self.hash.as_bytes()))
    }

    /// Set an explicit hardware/staging measurement pin without changing the constitution hash.
    pub fn with_measurement_pin(mut self, pin: Measurement) -> Self {
        self.measurement_pin = Some(pin);
        self
    }

    /// Override mesh-governed payout frequency (e.g. from env at genesis bootstrap).
    ///
    /// Recomputes `hash` after changing the field. The current hash material
    /// does not serialize `payout_frequency`, so the recomputation preserves
    /// the existing digest until the hash scheme includes that field.
    pub fn with_payout_frequency(mut self, freq: MinerPayoutCadence) -> Self {
        self.payout_frequency = freq;
        self.hash = self.compute_hash();
        self
    }

    /// Compute the canonical digest from the constitution's current hash material.
    ///
    /// The material includes version, withdrawal limits, thresholds, reward
    /// bounds, profit split, crypto suite, and optional previous hash. Measurement
    /// pin, downgrade policy, format versions, payout frequency, and quantum
    /// migration state are not part of this digest in the current implementation.
    pub fn compute_hash(&self) -> String {
        let prev = self.previous_hash.as_deref().unwrap_or("");
        let material = format!(
            "v{}|day{}|tx{}|n{}|t{}|gt{}|p{}|max{}|m{}|ch{}|inf{}|{}{}",
            self.version,
            self.max_withdraw_per_day_sats,
            self.max_withdraw_per_tx_sats,
            self.signing_n,
            self.signing_t,
            self.governance_t,
            self.p_reward_bps,
            self.p_reward_max_bps,
            self.profit_splits.miners_bps,
            self.profit_splits.channels_bps,
            self.profit_splits.infra_bps,
            self.crypto_suite_id,
            if prev.is_empty() { String::new() } else { format!("|prev_{}", prev) }
        );
        crate::Measurement::from_bytes(material.as_bytes()).as_hex().to_string()
    }

    /// Validate threshold/range invariants, nested policies, and the stored hash.
    ///
    /// Returns [`DomainError::InvalidConstitution`] when any check fails. This
    /// method does not independently validate every descriptive or version field.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.signing_n < 2 {
            return Err(DomainError::InvalidConstitution("n < 2".into()));
        }
        if self.signing_t == 0 || self.signing_t > self.signing_n {
            return Err(DomainError::InvalidConstitution("bad signing_t".into()));
        }
        if self.governance_t < self.signing_t || self.governance_t > self.signing_n {
            return Err(DomainError::InvalidConstitution("bad governance_t".into()));
        }
        if self.p_reward_bps > self.p_reward_max_bps {
            return Err(DomainError::InvalidConstitution("p_reward exceeds max".into()));
        }
        self.profit_splits.validate()?;
        self.downgrade_policy.validate()?;
        if self.hash != self.compute_hash() {
            return Err(DomainError::InvalidConstitution("constitution hash mismatch".into()));
        }
        Ok(())
    }

    /// Serialize the constitution's current public policy fields into its JSON wire form.
    ///
    /// The current representation omits payout frequency, previous hash, and
    /// quantum-migration state, and directly interpolates string values. It should
    /// not be treated as a lossless representation of every struct field.
    pub fn to_json(&self) -> String {
        let pin = self.measurement_pin.as_ref().map(|m| m.as_hex().to_string()).unwrap_or_default();
        format!(
            r#"{{"version":{},"max_withdraw_per_day_sats":{},"max_withdraw_per_tx_sats":{},"signing_n":{},"signing_t":{},"governance_t":{},"p_reward_bps":{},"p_reward_max_bps":{},"profit_splits":{{"miners_bps":{},"channels_bps":{},"infra_bps":{}}},"crypto_suite_id":"{}","hash":"{}","measurement_pin":"{}","downgrade_policy":{{"pq_kem_cat":{},"pq_sig_cat":{},"sym_bits":{},"hybrid_kem":{},"hybrid_sig":{},"req_pq_sig":{},"req_pq_kem":{}}},"format_versions":{{"intent":{},"receipt":{},"share_envelope":{},"dkg_transcript":{},"reshare_transcript":{},"certificate":{},"audit_record":{},"min_proto":{},"current_proto":{}}}"#,
            self.version,
            self.max_withdraw_per_day_sats,
            self.max_withdraw_per_tx_sats,
            self.signing_n,
            self.signing_t,
            self.governance_t,
            self.p_reward_bps,
            self.p_reward_max_bps,
            self.profit_splits.miners_bps,
            self.profit_splits.channels_bps,
            self.profit_splits.infra_bps,
            self.crypto_suite_id,
            self.hash,
            pin,
            self.downgrade_policy.pq_kem_security_category,
            self.downgrade_policy.pq_signature_security_category,
            self.downgrade_policy.symmetric_security_bits,
            self.downgrade_policy.hybrid_kem_required,
            self.downgrade_policy.hybrid_signature_required,
            self.downgrade_policy.require_pq_signatures,
            self.downgrade_policy.require_pq_kem,
            self.format_versions.intent,
            self.format_versions.receipt,
            self.format_versions.share_envelope,
            self.format_versions.dkg_transcript,
            self.format_versions.reshare_transcript,
            self.format_versions.certificate,
            self.format_versions.audit_record,
            self.format_versions.min_protocol_version,
            self.format_versions.current_protocol_version,
        )
    }
}

/// `t = ceil(2n/3)` for transaction signing quorum.
///
/// Returns the smallest integer threshold that is at least two-thirds of `n`;
/// for `n == 0` it returns zero.
pub fn quorum_two_thirds(n: usize) -> usize {
    (2 * n).div_ceil(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_thirds_examples() {
        assert_eq!(quorum_two_thirds(3), 2);
        assert_eq!(quorum_two_thirds(6), 4);
        assert_eq!(quorum_two_thirds(7), 5);
    }
}
