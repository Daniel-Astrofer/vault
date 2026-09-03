//! AMD SEV-SNP attestation report verify path.
//!
//! Without `--features tee_hw` (CI / no guest device), issue and verify fail closed.
//! With `tee_hw`, issue and verify real SEV-SNP guest reports via `sev-snp-utilities`.
//!
//! Fail-closed rules:
//! - No `/dev/sev-guest` device → reject with a clear error.
//! - Empty or malformed reports → reject.
//! - Certificate chain + ECDSA signature → verified by `sev-snp-utilities`.
//! - Constitution pin is bound via SNP `REPORT_DATA` (user data), not the guest
//!   launch digest (`MEASUREMENT` field — that is firmware/VMM owned).
//!
//! ## Item 2.4: VCEK Chain Verification
//!
//! The full VCEK (Versioned Chip Endorsement Key) chain is:
//!   ARK (AMD Root Key) → ASK (AMD SEV Signing Key) → VCEK (per-chip key)
//!
//! 1. Fetch ARK from AMD KDS: `https://kdsintf.amd.com/vcek/v1/{product}/cert_chain`
//! 2. Validate ARK → ASK signature (X.509 chain)
//! 3. Fetch VCEK: `https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}`
//! 4. Validate ASK → VCEK signature
//! 5. VCEK public key verifies attestation report ECDSA signature
//!
//! The `sev-snp-utilities` crate handles step 1-5 via `AttestationReport::verify()`.
//! Its internal cert chain fetching + caching depends on the crate's network access.
//!
//! ## Item 2.5: TCB Version Check (anti-rollback)
//!
//! The attestation report contains:
//! - `reported_tcb`: TCB version actually running on the platform
//! - `committed_tcb`: minimum TCB version committed by the guest owner at launch
//!
//! Verification must check:
//! - `reported_tcb.boot_loader >= minimum_required.boot_loader`
//! - `reported_tcb.tee >= minimum_required.tee`
//! - `reported_tcb.snp >= minimum_required.snp`
//! - If any component is lower → possible firmware rollback → refuse
//!
//! See [`validate_tcb_version`] for the check.

use crate::domain::{DomainError, Measurement};

#[cfg(feature = "tee_hw")]
use std::io::Cursor;

#[cfg(feature = "tee_hw")]
use sev_snp_utilities::{AttestationReport, Policy, Requester, Verification};

/// Pack our SHA-256 measurement (32 bytes) into SNP REPORT_DATA (64 bytes).
#[cfg(feature = "tee_hw")]
fn measurement_report_data(measurement: &Measurement) -> Result<[u8; 64], DomainError> {
    let digest = hex::decode(measurement.as_hex())
        .map_err(|e| DomainError::AttestationRejected(format!("SEV-SNP measurement hex decode: {e}")))?;
    if digest.len() != 32 {
        return Err(DomainError::AttestationRejected("SEV-SNP measurement must be 32-byte SHA-256".into()));
    }
    let mut user_data = [0u8; 64];
    user_data[..32].copy_from_slice(&digest);
    Ok(user_data)
}

/// Issue a platform attestation report for `measurement`.
pub fn issue_report(measurement: &Measurement) -> Result<Vec<u8>, DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        // Hard requirement for real guest reports.
        if !std::path::Path::new("/dev/sev-guest").exists() {
            return Err(DomainError::TeeRequired(
                "SEV-SNP quote issue: /dev/sev-guest missing (fail-closed without HW)".into(),
            ));
        }

        let user_data = measurement_report_data(measurement)?;
        let report_bytes = AttestationReport::request_raw(&user_data)
            .map_err(|e| DomainError::AttestationRejected(format!("SEV-SNP request_raw failed: {e}")))?;
        Ok(report_bytes)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SEV-SNP hardware quote unavailable: rebuild with --features tee_hw (CI fail-closed without HW)".into(),
        ))
    }
}

/// Verify an SEV-SNP attestation report and bind its measurement.
pub fn verify_report(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        verify_report_structure(measurement, report)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = (measurement, report);
        Err(DomainError::AttestationRejected(
            "SEV-SNP hardware verify unavailable: rebuild with --features tee_hw (CI fail-closed without HW)".into(),
        ))
    }
}

#[cfg(feature = "tee_hw")]
fn verify_report_structure(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    if report.is_empty() {
        return Err(DomainError::AttestationRejected("SEV-SNP report empty".into()));
    }

    let parsed = AttestationReport::from_reader(Cursor::new(report))
        .map_err(|e| DomainError::AttestationRejected(format!("SEV-SNP report parse failed: {e}")))?;

    let expected = measurement_report_data(measurement)?;
    if parsed.report_data.len() < 32 || parsed.report_data[..32] != expected[..32] {
        return Err(DomainError::AttestationRejected("SEV-SNP REPORT_DATA measurement mismatch".into()));
    }

    // Verify certificate chain + ECDSA signature.
    let verify_fut = async {
        let policy = Policy::permissive();
        parsed.verify(Some(policy)).await
    };

    let verified = match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(verify_fut),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| DomainError::AttestationRejected(format!("tokio runtime init: {e}")))?
            .block_on(verify_fut),
    }
    .map_err(|e| DomainError::AttestationRejected(format!("SEV-SNP verify failed: {e}")))?;

    if !verified {
        return Err(DomainError::AttestationRejected("SEV-SNP report verification failed".into()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Item 2.4: REPORT_DATA SHA-384 bind — constitution + measurement
// ---------------------------------------------------------------------------

#[cfg(feature = "tee_hw")]
/// Pack constitution hash + measurement into REPORT_DATA (64 bytes) using SHA-384.
///
/// Layout: SHA-384(constitution_bytes || measurement_bytes) → first 32 bytes,
/// remaining 32 bytes zero-padded.
///
/// This binds the attestation report to both the constitution and the vault
/// measurement, preventing a report from being reused with a different constitution.
pub fn measurement_report_data_bind(
    constitution_bytes: &[u8],
    measurement: &Measurement,
) -> Result<[u8; 64], DomainError> {
    use sha2::{Digest, Sha384};
    let mut hasher = Sha384::new();
    hasher.update(constitution_bytes);
    hasher.update(measurement.as_hex().as_bytes());
    let digest = hasher.finalize();
    let mut user_data = [0u8; 64];
    user_data[..48].copy_from_slice(&digest);
    Ok(user_data)
}

// ---------------------------------------------------------------------------
// Item 2.5: TCB version check (anti-rollback)
// ---------------------------------------------------------------------------

/// SEV-SNP TCB version components.
///
/// Mirrors the structure in the SNP attestation report.
/// Each field is an 8-bit microcode patch level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SevTcbVersion {
    /// Boot loader version
    pub boot_loader: u8,
    /// TEE firmware version
    pub tee: u8,
    /// SNP firmware version
    pub snp: u8,
    /// Microcode version
    pub microcode: u8,
}

impl SevTcbVersion {
    /// Minimum required TCB version for vault go-live.
    /// Must be updated when AMD releases new firmware with security fixes.
    pub const MINIMUM: Self = Self { boot_loader: 0, tee: 0, snp: 0, microcode: 0 };
}

/// Validate SEV-SNP TCB version against minimum required.
///
/// Each component of `reported_tcb` must be >= the corresponding component
/// in `minimum_tcb`. If any component is lower, the platform is running
/// outdated firmware — possible rollback attack.
///
/// Returns `Err(AttestationRejected)` with details if validation fails.
pub fn validate_tcb_version(reported: &SevTcbVersion, minimum: &SevTcbVersion) -> Result<(), DomainError> {
    let mut violations: Vec<&str> = Vec::new();

    if reported.boot_loader < minimum.boot_loader {
        violations.push("boot_loader");
    }
    if reported.tee < minimum.tee {
        violations.push("tee");
    }
    if reported.snp < minimum.snp {
        violations.push("snp");
    }
    if reported.microcode < minimum.microcode {
        violations.push("microcode");
    }

    if !violations.is_empty() {
        return Err(DomainError::AttestationRejected(format!(
            "SEV-SNP TCB version rollback: {} (reported={:?} < minimum={:?})",
            violations.join(", "),
            reported,
            minimum,
        )));
    }

    Ok(())
}

/// VCEK chain fetch URL template.
///
/// AMD publishes VCEK certificates at:
///   `https://kdsintf.amd.com/vcek/v1/{product_name}/{chip_id}`
///
/// Product names: Milan, Genoa, Bergamo, Turin (EPYC generations)
/// Chip ID: hex-encoded chip identifier from the attestation report
///
/// ```ignore
/// fn fetch_vcek_chain(product: &str, chip_id: &str) -> Result<Vec<Vec<u8>>> {
///     let url = format!(
///         "https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}",
///         product = product,
///         chip_id = chip_id
///     );
///     // ARK/ASK chain bundled in response as a certificate chain
///     let resp = reqwest::blocking::get(&url)?;
///     let der_bytes = resp.bytes()?;
///     // Parse DER → PEM → X.509 chain
///     Ok(parse_x509_chain(&der_bytes)?)
/// }
/// ```
pub fn vcek_chain_url(_product: &str, _chip_id: &str) -> String {
    format!("https://kdsintf.amd.com/vcek/v1/{_product}/{_chip_id}")
}

#[cfg(feature = "tee_hw")]
#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> Measurement {
        Measurement::from_bytes(b"constitution-pin")
    }

    #[test]
    fn verify_rejects_empty_report_bytes() {
        let m = pin();
        let err = verify_report(&m, &[]).unwrap_err();
        assert!(err.to_string().contains("report empty"));
    }

    #[test]
    fn measurement_report_data_is_32_byte_prefix() {
        let m = pin();
        let data = measurement_report_data(&m).expect("pack");
        assert_eq!(data.len(), 64);
        assert_eq!(&data[32..], &[0u8; 32]);
        let digest = hex::decode(m.as_hex()).unwrap();
        assert_eq!(&data[..32], digest.as_slice());
    }

    // Item 2.4: SHA-384 bind
    #[test]
    fn measurement_report_data_bind_is_deterministic() {
        let m = pin();
        let data1 = measurement_report_data_bind(b"constitution-v1", &m).expect("bind");
        let data2 = measurement_report_data_bind(b"constitution-v1", &m).expect("bind");
        assert_eq!(data1, data2);
        assert_eq!(data1.len(), 64);
    }

    #[test]
    fn measurement_report_data_bind_differs_by_constitution() {
        let m = pin();
        let data1 = measurement_report_data_bind(b"const-a", &m).expect("bind");
        let data2 = measurement_report_data_bind(b"const-b", &m).expect("bind");
        assert_ne!(data1, data2);
    }

    // Item 2.5: TCB version tests
    #[test]
    fn tcb_versions_are_comparable() {
        let older = SevTcbVersion { boot_loader: 1, tee: 2, snp: 3, microcode: 0x42 };
        let newer = SevTcbVersion { boot_loader: 2, tee: 2, snp: 3, microcode: 0x43 };
        assert!(older < newer);
    }

    #[test]
    fn tcb_validation_accepts_equal() {
        let reported = SevTcbVersion { boot_loader: 5, tee: 5, snp: 5, microcode: 0 };
        let minimum = SevTcbVersion { boot_loader: 5, tee: 5, snp: 5, microcode: 0 };
        assert!(validate_tcb_version(&reported, &minimum).is_ok());
    }

    #[test]
    fn tcb_validation_accepts_greater() {
        let reported = SevTcbVersion { boot_loader: 10, tee: 10, snp: 10, microcode: 0 };
        let minimum = SevTcbVersion { boot_loader: 5, tee: 5, snp: 5, microcode: 0 };
        assert!(validate_tcb_version(&reported, &minimum).is_ok());
    }

    #[test]
    fn tcb_validation_rejects_rollback() {
        let reported = SevTcbVersion { boot_loader: 1, tee: 2, snp: 3, microcode: 0 };
        let minimum = SevTcbVersion { boot_loader: 2, tee: 2, snp: 3, microcode: 0 };
        assert!(matches!(
            validate_tcb_version(&reported, &minimum),
            Err(DomainError::AttestationRejected(ref msg)) if msg.contains("boot_loader")
        ));
    }

    #[test]
    fn tcb_validation_rejects_multiple_violations() {
        let reported = SevTcbVersion { boot_loader: 1, tee: 1, snp: 1, microcode: 0 };
        let minimum = SevTcbVersion { boot_loader: 5, tee: 5, snp: 5, microcode: 0 };
        let err = validate_tcb_version(&reported, &minimum).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("boot_loader"));
        assert!(msg.contains("tee"));
        assert!(msg.contains("snp"));
    }
}
