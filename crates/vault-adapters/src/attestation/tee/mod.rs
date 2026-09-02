//! SEV-SNP / SGX HW attestation quote verify path (Gate / F8).
//!
//! - Staging: `ATTESTATION_STAGING_STUB=1` may issue measurement-bound stub quotes (not sim).
//! - Production ceremony: refuses sim quotes and staging stub (adapter + config hygiene).
//! - Quotes bind to `constitution.measurement_pin`; when an allowlist is present, the pin
//!   must also satisfy release Hb predicates.
//! - Real HW verify is structured under `sev_snp` / `sgx`; without `--features tee_hw`
//!   (CI default) the path stays fail-closed with clear errors.

mod quote;
mod sev_snp;
mod sgx;

use crate::application::AttestationPort;
use crate::domain::{
    admits_attestation_measurement, AttestationMode, AttestationQuote, ContentHash, DomainError, Measurement,
};

use self::quote::{HwQuoteEnvelope, PLATFORM_SEV, PLATFORM_SGX};

/// SEV/SGX attestation adapter.
pub struct TeeAttestationAdapter {
    mode: AttestationMode,
    staging_stub: bool,
    /// Production / ceremonial: never take the staging-stub path.
    refuse_stub: bool,
    platform_root: Vec<u8>,
    /// Expected binary / constitution measurement pin.
    pinned_measurement: Measurement,
    /// Allowlisted release Hb values (empty = pin-only admission at genesis).
    allowlisted_hbs: Vec<ContentHash>,
}

impl TeeAttestationAdapter {
    /// Lab/staging constructor (`refuse_stub = false`).
    pub fn new(
        mode: AttestationMode,
        staging_stub: bool,
        platform_root: &[u8],
        pinned_measurement: Measurement,
    ) -> Result<Self, DomainError> {
        Self::with_policy(mode, staging_stub, false, platform_root, pinned_measurement, Vec::new())
    }

    /// Full policy constructor: production sets `refuse_stub` to reject staging stubs.
    pub fn with_policy(
        mode: AttestationMode,
        staging_stub: bool,
        refuse_stub: bool,
        platform_root: &[u8],
        pinned_measurement: Measurement,
        allowlisted_hbs: Vec<ContentHash>,
    ) -> Result<Self, DomainError> {
        if !matches!(mode, AttestationMode::Sev | AttestationMode::Sgx) {
            return Err(DomainError::AttestationRejected("TeeAttestationAdapter requires sev or sgx mode".into()));
        }
        if refuse_stub && staging_stub {
            return Err(DomainError::LabFlagForbidden("ATTESTATION_STAGING_STUB in production ceremony".into()));
        }
        Ok(Self {
            mode,
            staging_stub,
            refuse_stub,
            platform_root: platform_root.to_vec(),
            pinned_measurement,
            allowlisted_hbs,
        })
    }

    pub fn with_allowlist(
        mode: AttestationMode,
        staging_stub: bool,
        refuse_stub: bool,
        platform_root: &[u8],
        pinned_measurement: Measurement,
        allowlisted_hbs: Vec<ContentHash>,
    ) -> Result<Self, DomainError> {
        Self::with_policy(mode, staging_stub, refuse_stub, platform_root, pinned_measurement, allowlisted_hbs)
    }

    pub fn pinned_measurement(&self) -> &Measurement {
        &self.pinned_measurement
    }

    pub fn set_allowlisted_hbs(&mut self, hbs: Vec<ContentHash>) {
        self.allowlisted_hbs = hbs;
    }

    fn stub_tag(&self) -> &'static [u8] {
        match self.mode {
            AttestationMode::Sev => b"kerosene-vault-sev-stub-v1",
            AttestationMode::Sgx => b"kerosene-vault-sgx-stub-v1",
            AttestationMode::Sim | AttestationMode::Software => b"invalid",
        }
    }

    fn stub_mac(&self, measurement: &Measurement) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.stub_tag());
        out.extend_from_slice(&self.platform_root);
        out.extend_from_slice(measurement.as_hex().as_bytes());
        out.extend_from_slice(b"|pin|");
        out.extend_from_slice(self.pinned_measurement.as_hex().as_bytes());
        Measurement::from_bytes(&out).as_hex().as_bytes().to_vec()
    }

    fn enforce_measurement(&self, measurement: &Measurement) -> Result<(), DomainError> {
        if !admits_attestation_measurement(measurement, &self.pinned_measurement, &self.allowlisted_hbs) {
            if measurement != &self.pinned_measurement {
                return Err(DomainError::MeasurementMismatch);
            }
            return Err(DomainError::NotAllowlisted(measurement.as_hex().to_string()));
        }
        Ok(())
    }

    fn platform_code(&self) -> u8 {
        match self.mode {
            AttestationMode::Sev => PLATFORM_SEV,
            AttestationMode::Sgx => PLATFORM_SGX,
            AttestationMode::Sim | AttestationMode::Software => 0,
        }
    }

    fn issue_hw_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
        // Structure a versioned envelope; platform report bytes require real TEE / `tee_hw`.
        let report = match self.mode {
            AttestationMode::Sev => sev_snp::issue_report(measurement)?,
            AttestationMode::Sgx => sgx::issue_report(measurement)?,
            AttestationMode::Sim | AttestationMode::Software => {
                return Err(DomainError::SimAttestationForbidden);
            }
        };
        let blob =
            HwQuoteEnvelope { platform: self.platform_code(), measurement: measurement.clone(), report }.encode();
        Ok(AttestationQuote { mode: self.mode, measurement: measurement.clone(), quote_blob: blob })
    }

    fn verify_hw_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError> {
        let env = HwQuoteEnvelope::decode(&quote.quote_blob)?;
        if env.platform != self.platform_code() {
            return Err(DomainError::AttestationRejected(format!(
                "HW quote platform byte {} != adapter {}",
                env.platform,
                self.mode.as_str()
            )));
        }
        if &env.measurement != &quote.measurement {
            return Err(DomainError::AttestationRejected("HW quote envelope measurement != quote.measurement".into()));
        }
        self.enforce_measurement(&env.measurement)?;
        match self.mode {
            AttestationMode::Sev => sev_snp::verify_report(&env.measurement, &env.report),
            AttestationMode::Sgx => sgx::verify_report(&env.measurement, &env.report),
            AttestationMode::Sim | AttestationMode::Software => Err(DomainError::SimAttestationForbidden),
        }
    }

    fn stub_path_allowed(&self) -> bool {
        self.staging_stub && !self.refuse_stub
    }
}

impl AttestationPort for TeeAttestationAdapter {
    fn mode(&self) -> AttestationMode {
        self.mode
    }

    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
        self.enforce_measurement(measurement)?;
        if self.stub_path_allowed() {
            return Ok(AttestationQuote {
                mode: self.mode,
                measurement: measurement.clone(),
                quote_blob: self.stub_mac(measurement),
            });
        }
        if self.refuse_stub {
            // Production: HW path only (fail-closed without real TEE / tee_hw).
            return self.issue_hw_quote(measurement);
        }
        Err(DomainError::AttestationRejected(format!(
            "{} hardware quote unavailable (set ATTESTATION_STAGING_STUB=1 for staging only; production requires --features tee_hw + platform)",
            self.mode.as_str()
        )))
    }

    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError> {
        if quote.mode.is_software_measurement() {
            return Err(DomainError::AttestationRejected("TEE adapter rejects software/sim quotes".into()));
        }
        if quote.mode != self.mode {
            return Err(DomainError::AttestationRejected(format!(
                "quote mode {} != adapter {}",
                quote.mode.as_str(),
                self.mode.as_str()
            )));
        }
        self.enforce_measurement(&quote.measurement)?;

        // Prefer structured HW envelope when present.
        if HwQuoteEnvelope::looks_like(&quote.quote_blob) {
            if self.refuse_stub || !self.staging_stub {
                return self.verify_hw_quote(quote);
            }
            // Staging with stub still accepts HW envelopes if presented.
            return self.verify_hw_quote(quote);
        }

        if !self.stub_path_allowed() {
            if self.refuse_stub {
                return Err(DomainError::LabFlagForbidden("ATTESTATION_STAGING_STUB in production ceremony".into()));
            }
            return Err(DomainError::AttestationRejected(format!(
                "{} hardware verify unavailable (CI fail-closed without --features tee_hw; staging may set ATTESTATION_STAGING_STUB=1)",
                self.mode.as_str()
            )));
        }

        let expected = self.stub_mac(&quote.measurement);
        if expected != quote.quote_blob {
            return Err(DomainError::AttestationRejected("TEE staging stub quote mac mismatch".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> Measurement {
        Measurement::from_bytes(b"constitution-pin")
    }

    #[test]
    fn staging_stub_roundtrip_sev() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, true, b"plat", pin()).unwrap();
        let q = tee.issue_quote(&pin()).unwrap();
        assert_eq!(q.mode, AttestationMode::Sev);
        tee.verify_quote(&q).unwrap();
    }

    #[test]
    fn refuse_sim_quotes() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat", pin()).unwrap();
        let bad = AttestationQuote { mode: AttestationMode::Sim, measurement: pin(), quote_blob: vec![1, 2, 3] };
        assert!(matches!(
            tee.verify_quote(&bad),
            Err(DomainError::AttestationRejected(ref r)) if r.contains("sim")
        ));
    }

    #[test]
    fn refuse_stub_in_production() {
        assert!(matches!(
            TeeAttestationAdapter::with_policy(
                AttestationMode::Sev,
                true,
                true,
                b"plat",
                pin(),
                Vec::new()
            ),
            Err(DomainError::LabFlagForbidden(ref f))
                if f.contains("ATTESTATION_STAGING_STUB")
        ));

        let tee =
            TeeAttestationAdapter::with_policy(AttestationMode::Sev, false, true, b"plat", pin(), Vec::new()).unwrap();
        // Production without HW: issue fails closed (clear error).
        let err = tee.issue_quote(&pin()).unwrap_err();
        assert!(matches!(err, DomainError::AttestationRejected(_) | DomainError::TeeRequired(_)), "unexpected: {err}");
        // Stub-shaped blob refused in production.
        let stubby = AttestationQuote {
            mode: AttestationMode::Sev,
            measurement: pin(),
            quote_blob: b"not-a-hw-envelope".to_vec(),
        };
        assert!(matches!(
            tee.verify_quote(&stubby),
            Err(DomainError::LabFlagForbidden(_)) | Err(DomainError::AttestationRejected(_))
        ));
    }

    #[test]
    fn measurement_mismatch_rejected() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat", pin()).unwrap();
        let other = Measurement::from_bytes(b"other-binary");
        assert!(matches!(tee.issue_quote(&other), Err(DomainError::MeasurementMismatch)));
        let bad = AttestationQuote { mode: AttestationMode::Sgx, measurement: other, quote_blob: vec![1, 2, 3] };
        assert!(matches!(tee.verify_quote(&bad), Err(DomainError::MeasurementMismatch)));
    }

    #[test]
    fn allowlist_predicate_required_when_populated() {
        let pin = pin();
        let other_hb = ContentHash::from_bytes(b"allowlisted-binary");
        let tee = TeeAttestationAdapter::with_allowlist(
            AttestationMode::Sev,
            true,
            false,
            b"plat",
            pin.clone(),
            vec![other_hb],
        )
        .unwrap();
        // Pin matches constitution but is not on allowlist → NotAllowlisted.
        assert!(matches!(tee.issue_quote(&pin), Err(DomainError::NotAllowlisted(_))));

        let admitted = Measurement::from_hex(ContentHash::from_bytes(b"allowlisted-binary").as_str()).unwrap();
        // Wrong pin still mismatches first.
        assert!(matches!(tee.issue_quote(&admitted), Err(DomainError::MeasurementMismatch)));
    }

    #[test]
    fn allowlist_admits_when_pin_is_allowlisted_hb() {
        let hb = ContentHash::from_bytes(b"release-hb-v1");
        let pin = Measurement::from_hex(hb.as_str()).unwrap();
        let tee =
            TeeAttestationAdapter::with_allowlist(AttestationMode::Sgx, true, false, b"plat", pin.clone(), vec![hb])
                .unwrap();
        let q = tee.issue_quote(&pin).unwrap();
        tee.verify_quote(&q).unwrap();
    }

    #[test]
    fn hw_path_fail_closed_without_stub() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, false, b"plat", pin()).unwrap();
        assert!(tee.issue_quote(&pin()).is_err());
        assert!(tee
            .verify_quote(&AttestationQuote {
                mode: AttestationMode::Sev,
                measurement: pin(),
                quote_blob: vec![9, 9, 9],
            })
            .is_err());
    }

    #[test]
    fn hw_envelope_verify_fail_closed_clear_error() {
        let tee =
            TeeAttestationAdapter::with_policy(AttestationMode::Sev, false, true, b"plat", pin(), Vec::new()).unwrap();
        let env = HwQuoteEnvelope { platform: PLATFORM_SEV, measurement: pin(), report: b"fake-sev-report".to_vec() };
        let q = AttestationQuote { mode: AttestationMode::Sev, measurement: pin(), quote_blob: env.encode() };
        let err = tee.verify_quote(&q).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tee_hw")
                || msg.contains("SEV-SNP")
                || msg.contains("fail-closed")
                || msg.contains("unavailable"),
            "expected clear HW fail-closed message, got: {msg}"
        );
    }
}
