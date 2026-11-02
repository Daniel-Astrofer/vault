//! Versioned HW attestation quote envelope shared by SEV-SNP and SGX paths.

use crate::domain::{DomainError, Measurement};

/// `KVAQTEE1` — Kerosene Vault Attestation Quote TEE v1.
pub const QUOTE_MAGIC: &[u8; 8] = b"KVAQTEE1";
pub const QUOTE_VERSION: u8 = 1;
pub const PLATFORM_SEV: u8 = 1;
pub const PLATFORM_SGX: u8 = 2;

/// Structured quote blob before platform-specific report verification.
///
/// Layout: magic(8) | version(1) | platform(1) | measurement_hex(64 ascii) | report_len(u32 BE) | report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwQuoteEnvelope {
    pub platform: u8,
    pub measurement: Measurement,
    pub report: Vec<u8>,
}

impl HwQuoteEnvelope {
    pub fn looks_like(blob: &[u8]) -> bool {
        blob.len() >= 8 && &blob[..8] == QUOTE_MAGIC
    }

    pub fn encode(&self) -> Vec<u8> {
        let hex = self.measurement.as_hex();
        let mut out = Vec::with_capacity(8 + 1 + 1 + 64 + 4 + self.report.len());
        out.extend_from_slice(QUOTE_MAGIC);
        out.push(QUOTE_VERSION);
        out.push(self.platform);
        out.extend_from_slice(hex.as_bytes());
        let len = self.report.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.report);
        out
    }

    pub fn decode(blob: &[u8]) -> Result<Self, DomainError> {
        if blob.len() < 8 + 1 + 1 + 64 + 4 {
            return Err(DomainError::AttestationRejected("HW quote envelope too short".into()));
        }
        if &blob[..8] != QUOTE_MAGIC {
            return Err(DomainError::AttestationRejected("HW quote magic mismatch".into()));
        }
        let version = blob[8];
        if version != QUOTE_VERSION {
            return Err(DomainError::AttestationRejected(format!("unsupported HW quote version {version}")));
        }
        let platform = blob[9];
        if platform != PLATFORM_SEV && platform != PLATFORM_SGX {
            return Err(DomainError::AttestationRejected(format!("unknown HW quote platform {platform}")));
        }
        let meas_hex = std::str::from_utf8(&blob[10..74])
            .map_err(|_| DomainError::AttestationRejected("HW quote measurement not ascii hex".into()))?;
        let measurement = Measurement::from_hex(meas_hex)?;
        let report_len = u32::from_be_bytes([blob[74], blob[75], blob[76], blob[77]]) as usize;
        if blob.len() != 78 + report_len {
            return Err(DomainError::AttestationRejected("HW quote report length mismatch".into()));
        }
        Ok(Self { platform, measurement, report: blob[78..].to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let m = Measurement::from_bytes(b"m");
        let env = HwQuoteEnvelope { platform: PLATFORM_SEV, measurement: m.clone(), report: vec![1, 2, 3, 4] };
        let blob = env.encode();
        assert!(HwQuoteEnvelope::looks_like(&blob));
        let decoded = HwQuoteEnvelope::decode(&blob).unwrap();
        assert_eq!(decoded, env);
    }
}
