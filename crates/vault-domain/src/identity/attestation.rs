use sha2::{Digest, Sha256};

use crate::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    /// Lab-only visualization quote (refused under hardened / production ceremony).
    Sim,
    /// Domestic software measurement — honest non-TEE label; prod-capable for domestic tier.
    Software,
    Sev,
    Sgx,
}

impl AttestationMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sim" | "simulation" => Some(Self::Sim),
            // Alias: historical lab docs said "sim"; domestic prod uses "software".
            "software" | "sw" | "measurement" => Some(Self::Software),
            "sev" | "sev-snp" | "sev_snp" => Some(Self::Sev),
            "sgx" => Some(Self::Sgx),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sim => "sim",
            Self::Software => "software",
            Self::Sev => "sev",
            Self::Sgx => "sgx",
        }
    }

    pub fn is_lab_only(self) -> bool {
        matches!(self, Self::Sim)
    }

    pub fn is_software_measurement(self) -> bool {
        matches!(self, Self::Sim | Self::Software)
    }

    pub fn is_tee(self) -> bool {
        matches!(self, Self::Sev | Self::Sgx)
    }
}

/// SHA-256 measurement as 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement(String);

impl Measurement {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex::encode(digest))
    }

    pub fn from_hex(hex_str: impl Into<String>) -> Result<Self, DomainError> {
        let s = hex_str.into();
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::AttestationRejected("measurement must be 32-byte SHA-256 hex (64 chars)".into()));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationQuote {
    pub mode: AttestationMode,
    pub measurement: Measurement,
    pub quote_blob: Vec<u8>,
}

/// Bind a quote measurement to the constitution pin and optional release allowlist Hb set.
///
/// - Always requires `measurement == pin`.
/// - When `allowlisted_hbs` is non-empty, `measurement` must also equal one of those Hb values
///   (release allowlist predicate). Empty allowlist = genesis / pin-only.
pub fn admits_attestation_measurement(
    measurement: &Measurement,
    pin: &Measurement,
    allowlisted_hbs: &[crate::ContentHash],
) -> bool {
    if measurement != pin {
        return false;
    }
    if allowlisted_hbs.is_empty() {
        return true;
    }
    allowlisted_hbs.iter().any(|hb| hb.as_str() == measurement.as_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_measurement_is_64_hex() {
        let m = Measurement::from_bytes(b"kerosene");
        assert_eq!(m.as_hex().len(), 64);
        assert!(m.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(m.as_hex(), "3e5e2cac8b6b93348880dc878d785e53e1b7d54bcaeaa4fb2ff231a90c76c043");
        assert_eq!(m, Measurement::from_bytes(b"kerosene"));
        assert_ne!(m, Measurement::from_bytes(b"other"));
    }

    #[test]
    fn from_hex_rejects_short() {
        assert!(Measurement::from_hex("abcd").is_err());
    }

    #[test]
    fn admits_pin_only_when_allowlist_empty() {
        let pin = Measurement::from_bytes(b"pin");
        assert!(admits_attestation_measurement(&pin, &pin, &[]));
        assert!(!admits_attestation_measurement(&Measurement::from_bytes(b"other"), &pin, &[]));
    }

    #[test]
    fn admits_requires_allowlist_hb_when_populated() {
        use crate::ContentHash;
        let hb = ContentHash::from_bytes(b"bin-v1");
        let pin = Measurement::from_hex(hb.as_str()).unwrap();
        assert!(admits_attestation_measurement(&pin, &pin, &[hb.clone()]));
        let wrong_pin = Measurement::from_bytes(b"not-allowlisted");
        assert!(!admits_attestation_measurement(&wrong_pin, &wrong_pin, &[hb]));
    }
}
