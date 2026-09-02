//! Intel SGX DCAP / ECDSA quote verify path.
//!
//! Without `--features tee_hw` (CI / no enclave), issue and verify fail closed.
//! With `tee_hw`, quote parse + MRENCLAVE bind structure is compiled; QE/PCK collateral
//! verification remains ops-wired (still fail-closed until linked).
//!
//! ## Item 2.4: DCAP Quote Generation + Verification
//!
//! Intel SGX DCAP (Data Center Attestation Primitives) replaces the deprecated
//! EPID-based attestation. The flow:
//!
//! 1. **Enclave generates Report**: `sgx_create_report(target_info, report_data)`
//!    - `report_data`: SHA-384 of constitution + measurement (binding)
//!    - Report is MAC'd with the QE's report key (local only)
//! 2. **Quoting Enclave (QE) converts Report → Quote**:
//!    - `sgx_targetinfo`: from QE identity
//!    - QE verifies report MAC, signs with attestation key → DCAP Quote v3/v4
//! 3. **Quote verification against Intel PCS (Provisioning Certification Service)**:
//!    - Fetch PCK certificate chain from `https://api.trustedservices.intel.com/sgx/certification/v4/`
//!    - Verify QE signature (ECDSA P-256)
//!    - Fetch TCB info: `https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={value}`
//!    - Check `cpu_svn` against minimum and `tcb_evaluation_data_number`
//!    - Verify MRENCLAVE matches expected measurement
//!    - Verify MRSIGNER in allowlist (ceremony-approved signer identity)
//!
//! 4. **Rust crates for DCAP**:
//!    - `sgx_dcap_quoteverify_rs` (Intel official) — quote verification
//!    - `dcap-qvl` (community) — quote verification library
//!    - `sgx_types` — SGX data structures
//!
//! ## Item 2.5: TCB Version Check (anti-rollback)
//!
//! DCAP quote TCB info contains:
//! - `cpu_svn`: CPU security version number (array of 16 u8 values)
//! - `pce_svn`: PCE (Provisioning Certification Enclave) security version
//! - `qe_svn`: QE (Quoting Enclave) security version
//!
//! Verification checks:
//! - Each `cpu_svn[i]` >= minimum known for that component
//! - `pce_svn` >= minimum PCE version
//! - If any is lower → outdated TCB, possible rollback → refuse
//!
//! See [`validate_sgx_tcb`] for the check.

use crate::domain::{DomainError, Measurement};

/// Issue an SGX quote for `measurement` (MRENCLAVE bind target).
pub fn issue_report(measurement: &Measurement) -> Result<Vec<u8>, DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SGX quote issue: tee_hw compiled but DCAP quote generation not linked (fail-closed). \
             Requires SGX SDK + DCAP driver. See Item 2.4 in VAULT_IMPLEMENTATION_PLAN.md."
                .into(),
        ))
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SGX hardware quote unavailable: rebuild with --features tee_hw (CI fail-closed without HW)".into(),
        ))
    }
}

/// Verify an SGX quote and bind MRENCLAVE to `measurement`.
pub fn verify_report(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        verify_report_structure(measurement, report)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = (measurement, report);
        Err(DomainError::AttestationRejected(
            "SGX hardware verify unavailable: rebuild with --features tee_hw (CI fail-closed without HW)".into(),
        ))
    }
}

#[cfg(feature = "tee_hw")]
fn verify_report_structure(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    if report.is_empty() {
        return Err(DomainError::AttestationRejected("SGX quote empty".into()));
    }
    // Expected future layout hook: parse Quote v3/v4, verify ECDSA + collateral, compare
    // MRENCLAVE to `measurement`. Until DCAP is linked, fail closed.
    //
    // Full implementation plan:
    //
    // ```ignore
    // use sgx_dcap_quoteverify_rs::Quote3Verifier;
    //
    // // 1. Parse DCAP quote
    // let quote = Quote3Verifier::parse(report)?;
    //
    // // 2. Verify QE signature (ECDSA P-256) via QVL library
    // //    This fetches PCK collateral from Intel PCS and validates the chain
    // let collateral = fetch_collateral(&quote)?;
    // let qe_report = quote.verify(&collateral)?;
    //
    // // 3. Verify MRENCLAVE (enclave measurement) matches expected
    // if qe_report.mrenclave != measurement.as_hex().as_bytes() {
    //     return Err(DomainError::AttestationRejected(
    //         "SGX MRENCLAVE mismatch".into()
    //     ));
    // }
    //
    // // 4. Verify MRSIGNER in ceremony allowlist
    // if !allowlist.contains(&qe_report.mrsigner) {
    //     return Err(DomainError::AttestationRejected(
    //         format!("SGX MRSIGNER {mrsigner} not in allowlist")
    //     ));
    // }
    //
    // // 5. Check REPORT_DATA bind: SHA-384 of constitution + measurement
    // let expected_bind = sha384_bind(constitution, measurement);
    // if qe_report.report_data[..48] != expected_bind {
    //     return Err(DomainError::AttestationRejected(
    //         "SGX REPORT_DATA bind mismatch".into()
    //     ));
    // }
    // ```
    let _ = measurement;
    Err(DomainError::AttestationRejected(
        "SGX quote verify: tee_hw path structured but DCAP/QE collateral verify not linked (fail-closed). \
         See VAULT_IMPLEMENTATION_PLAN.md Item 2.4 for integration requirements."
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// Item 2.4: DCAP integration constants + Intel PCS endpoints
// ---------------------------------------------------------------------------

/// Intel PCS (Provisioning Certification Service) API base URL.
///
/// DCAP quote verification fetches PCK certificates from this endpoint.
/// Production vaults should cache PCK collateral to avoid PCS dependency
/// at every verification.
pub const INTEL_PCS_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4";

/// Intel PCS TCB info endpoint suffix.
/// Format: `{INTEL_PCS_BASE_URL}/tcb?fmspc={hex_value}`
pub const INTEL_PCS_TCB_PATH: &str = "/tcb";

/// Intel PCS PCK certificate endpoint suffix.
/// Format: `{INTEL_PCS_BASE_URL}/pckcert?encrypted_ppid={hex}&cpusvn={hex}&pcesvn={hex}&pceid={hex}`
pub const INTEL_PCS_PCKCERT_PATH: &str = "/pckcert";

/// Build Intel PCS TCB info URL for a given FMSPC value.
pub fn intel_pcs_tcb_url(fmspc: &str) -> String {
    format!("{INTEL_PCS_BASE_URL}{INTEL_PCS_TCB_PATH}?fmspc={fmspc}")
}

// ---------------------------------------------------------------------------
// Item 2.5: SGX TCB version check (anti-rollback)
// ---------------------------------------------------------------------------

/// SGX DCAP TCB security version numbers.
///
/// Each component has a minimum known-good version. If any reported component
/// is below the minimum, the platform may be running vulnerable firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgxTcbVersion {
    /// CPU security version (16 bytes from DCAP quote)
    pub cpu_svn: [u8; 16],
    /// Provisioning Certification Enclave security version
    pub pce_svn: u16,
    /// Quoting Enclave security version
    pub qe_svn: u16,
}

impl SgxTcbVersion {
    /// Minimum required TCB version for vault go-live.
    /// Must be updated when Intel publishes TCB recoveries.
    pub const MINIMUM: Self = Self { cpu_svn: [0u8; 16], pce_svn: 0, qe_svn: 0 };
}

/// Validate SGX TCB version against minimum required.
///
/// Each `cpu_svn` component and `pce_svn`/`qe_svn` must be >= the minimum.
/// If any is lower → outdated TCB → possible firmware rollback → refuse.
///
/// Returns `Err(AttestationRejected)` with component details if validation fails.
pub fn validate_sgx_tcb(reported: &SgxTcbVersion, minimum: &SgxTcbVersion) -> Result<(), DomainError> {
    // Check cpu_svn byte-by-byte (lexicographic comparison)
    for (i, (&r, &m)) in reported.cpu_svn.iter().zip(minimum.cpu_svn.iter()).enumerate() {
        if r < m {
            return Err(DomainError::AttestationRejected(format!(
                "SGX TCB cpu_svn[{i}] rollback: reported={r} < minimum={m}"
            )));
        }
    }

    if reported.pce_svn < minimum.pce_svn {
        return Err(DomainError::AttestationRejected(format!(
            "SGX TCB pce_svn rollback: reported={} < minimum={}",
            reported.pce_svn, minimum.pce_svn,
        )));
    }

    if reported.qe_svn < minimum.qe_svn {
        return Err(DomainError::AttestationRejected(format!(
            "SGX TCB qe_svn rollback: reported={} < minimum={}",
            reported.qe_svn, minimum.qe_svn,
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(feature = "tee_hw")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_report_rejects_empty_bytes() {
        let m = Measurement::from_bytes(b"test-mrenclave");
        let err = verify_report(&m, &[]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn verify_report_fails_closed_without_dcap_link() {
        let m = Measurement::from_bytes(b"test-mrenclave");
        let err = verify_report(&m, b"not-empty").unwrap_err();
        assert!(err.to_string().contains("not linked"));
    }

    // Item 2.5: SGX TCB tests

    #[test]
    fn sgx_tcb_validation_accepts_equal() {
        let reported = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 5, qe_svn: 5 };
        let minimum = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 5, qe_svn: 5 };
        assert!(validate_sgx_tcb(&reported, &minimum).is_ok());
    }

    #[test]
    fn sgx_tcb_validation_accepts_greater() {
        let reported = SgxTcbVersion { cpu_svn: [2u8; 16], pce_svn: 10, qe_svn: 10 };
        let minimum = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 5, qe_svn: 5 };
        assert!(validate_sgx_tcb(&reported, &minimum).is_ok());
    }

    #[test]
    fn sgx_tcb_validation_rejects_cpu_svn_rollback() {
        let reported = SgxTcbVersion { cpu_svn: [0u8; 16], pce_svn: 5, qe_svn: 5 };
        let minimum = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 5, qe_svn: 5 };
        assert!(matches!(
            validate_sgx_tcb(&reported, &minimum),
            Err(DomainError::AttestationRejected(ref msg)) if msg.contains("cpu_svn")
        ));
    }

    #[test]
    fn sgx_tcb_validation_rejects_pce_svn_rollback() {
        let reported = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 4, qe_svn: 5 };
        let minimum = SgxTcbVersion { cpu_svn: [1u8; 16], pce_svn: 5, qe_svn: 5 };
        assert!(matches!(
            validate_sgx_tcb(&reported, &minimum),
            Err(DomainError::AttestationRejected(ref msg)) if msg.contains("pce_svn")
        ));
    }

    #[test]
    fn intel_pcs_url_is_well_formed() {
        let url = intel_pcs_tcb_url("00606A000000");
        assert!(url.starts_with("https://api.trustedservices.intel.com"));
        assert!(url.contains("tcb"));
        assert!(url.contains("00606A000000"));
    }
}
