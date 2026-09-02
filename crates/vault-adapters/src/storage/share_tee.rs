//! TEE seal share store — versioned sealed envelope (`KVSEAL01`).
//!
//! - Lab / staging stub: only when explicitly allowed (`ATTESTATION_STAGING_STUB`) and
//!   **not** compiled under `--features production`.
//! - HW path: compiled behind feature `tee_hw` (SEV-SNP derived-key via `sev-snp-utilities`;
//!   SGX host path fails closed until an enclave sealing SDK is wired).
//! - Default / CI without HW: **fail-closed** — no stub, no host-disk plaintext fallback.
//! - Unseal runs only after attestation issue+verify succeeds.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(not(feature = "production"))]
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
#[cfg(not(feature = "production"))]
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::application::{AttestationPort, ShareStorePort};
use crate::domain::{AttestationMode, DomainError, Measurement};

const MAGIC: &[u8; 8] = b"KVSEAL01";
const ENVELOPE_VERSION: u8 = 1;
const MODE_STAGING_STUB: u8 = 1;
const MODE_HW_SEV: u8 = 2;
const MODE_HW_SGX: u8 = 3;

enum SealBackend {
    /// Production / CI default: refuse seal and unseal.
    FailClosed,
    /// Lab-only measurement-bound AEAD envelope (never under `production` feature).
    #[cfg(not(feature = "production"))]
    StagingStub { passphrase: SecretString },
    /// Hardware TEE seal (compiled with `tee_hw`).
    #[cfg(feature = "tee_hw")]
    Hw { platform: AttestationMode },
}

/// Versioned TEE seal adapter (`ShareStorePort`).
///
/// Prefer this name in Gate docs; `TeeSealShareStore` remains a type alias.
pub struct TeeSealAdapter {
    root: PathBuf,
    backend: SealBackend,
    measurement: Measurement,
    attestation: Option<Arc<dyn AttestationPort>>,
}

/// Historical name used in wiring / Gate table.
pub type TeeSealShareStore = TeeSealAdapter;

impl TeeSealAdapter {
    /// Production-style constructor: refuse seal/unseal until real TEE HW is available.
    pub fn fail_closed(measurement: Measurement) -> Self {
        Self { root: PathBuf::from("/dev/null"), backend: SealBackend::FailClosed, measurement, attestation: None }
    }

    /// Staging-stub seal path (lab / `ATTESTATION_STAGING_STUB=1` only).
    /// Not available under `--features production`.
    #[cfg(not(feature = "production"))]
    pub fn staging_stub(root: impl Into<PathBuf>, passphrase: impl Into<String>, measurement: Measurement) -> Self {
        Self {
            root: root.into(),
            backend: SealBackend::StagingStub { passphrase: SecretString::from(passphrase.into()) },
            measurement,
            attestation: None,
        }
    }

    /// HW TEE seal path (requires `tee_hw`). Runtime still fail-closed without device/SDK.
    #[cfg(feature = "tee_hw")]
    pub fn hw(
        root: impl Into<PathBuf>,
        platform: AttestationMode,
        measurement: Measurement,
        attestation: Arc<dyn AttestationPort>,
    ) -> Result<Self, DomainError> {
        if !matches!(platform, AttestationMode::Sev | AttestationMode::Sgx) {
            return Err(DomainError::TeeRequired("tee_hw seal requires ATTESTATION_MODE=sev|sgx".into()));
        }
        Ok(Self {
            root: root.into(),
            backend: SealBackend::Hw { platform },
            measurement,
            attestation: Some(attestation),
        })
    }

    pub fn with_attestation(mut self, attestation: Arc<dyn AttestationPort>) -> Self {
        self.attestation = Some(attestation);
        self
    }

    pub fn new() -> Self {
        Self::fail_closed(Measurement::from_bytes(b"kerosene-vault-tee-unconfigured"))
    }

    fn path_for(&self, share_id: &str) -> PathBuf {
        let id_hash = hex::encode(Sha256::digest(share_id.as_bytes()));
        self.root.join(format!("tee-share-{id_hash}.seal"))
    }

    /// Unseal (and HW seal) only after a live attestation quote verifies.
    fn require_attestation_ok(&self) -> Result<(), DomainError> {
        let Some(att) = self.attestation.as_ref() else {
            return Err(DomainError::TeeRequired("attestation required before TEE unseal".into()));
        };
        let quote = att.issue_quote(&self.measurement)?;
        att.verify_quote(&quote)
    }

    #[cfg(not(feature = "production"))]
    fn derive_stub_key(&self, passphrase: &SecretString, salt: &[u8; 16]) -> Result<[u8; 32], DomainError> {
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut material = Vec::with_capacity(passphrase.expose_secret().len() + 64);
        material.extend_from_slice(passphrase.expose_secret().as_bytes());
        material.extend_from_slice(self.measurement.as_hex().as_bytes());
        let mut key = [0u8; 32];
        argon
            .hash_password_into(&material, salt, &mut key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2: {e}")))?;
        material.zeroize();
        Ok(key)
    }

    #[cfg(feature = "tee_hw")]
    fn mix_seal_key(root: &[u8; 32], salt: &[u8; 16], measurement: &Measurement) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"KVSEAL01/v1/seal-key");
        hasher.update(root);
        hasher.update(salt);
        hasher.update(measurement.as_hex().as_bytes());
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }

    #[cfg(feature = "tee_hw")]
    fn derive_hw_root(platform: AttestationMode) -> Result<[u8; 32], DomainError> {
        match platform {
            AttestationMode::Sev => hw::sev_snp_derived_root(),
            AttestationMode::Sgx => hw::sgx_seal_root(),
            AttestationMode::Sim | AttestationMode::Software => {
                Err(DomainError::TeeRequired("software/sim attestation cannot derive HW seal keys".into()))
            }
        }
    }

    fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), DomainError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| DomainError::ShareStoreForbidden("tee encrypt failed".into()))?;
        Ok((nonce_bytes, ciphertext))
    }

    fn aead_decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DomainError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).map_err(|_| DomainError::ShareStoreForbidden("tee decrypt failed".into()))
    }

    fn pack_envelope(mode: u8, salt: &[u8; 16], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + 1 + 16 + 12 + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(mode);
        out.extend_from_slice(salt);
        out.extend_from_slice(nonce);
        out.extend_from_slice(ciphertext);
        out
    }

    fn parse_envelope(blob: &[u8]) -> Result<(u8, [u8; 16], &[u8], &[u8]), DomainError> {
        if blob.len() < 8 + 1 + 1 + 16 + 12 + 16 {
            return Err(DomainError::ShareStoreForbidden("tee seal envelope too short".into()));
        }
        if &blob[..8] != MAGIC {
            return Err(DomainError::ShareStoreForbidden("tee seal magic mismatch".into()));
        }
        let version = blob[8];
        if version != ENVELOPE_VERSION {
            return Err(DomainError::ShareStoreForbidden(format!("unsupported tee seal version {version}")));
        }
        let mode = blob[9];
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&blob[10..26]);
        let nonce = &blob[26..38];
        let ciphertext = &blob[38..];
        Ok((mode, salt, nonce, ciphertext))
    }

    fn seal_envelope(&self, plaintext: &[u8]) -> Result<Vec<u8>, DomainError> {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        match &self.backend {
            SealBackend::FailClosed => Err(DomainError::TeeRequired(
                "TEE seal path not available; host disk AEAD is lab-only (production fail-closed)".into(),
            )),
            #[cfg(not(feature = "production"))]
            SealBackend::StagingStub { passphrase } => {
                let mut key = self.derive_stub_key(passphrase, &salt)?;
                let (nonce, ct) = Self::aead_encrypt(&key, plaintext)?;
                key.zeroize();
                Ok(Self::pack_envelope(MODE_STAGING_STUB, &salt, &nonce, &ct))
            }
            #[cfg(feature = "tee_hw")]
            SealBackend::Hw { platform } => {
                let mut root = Self::derive_hw_root(*platform)?;
                let mut key = Self::mix_seal_key(&root, &salt, &self.measurement);
                root.zeroize();
                let mode = match platform {
                    AttestationMode::Sev => MODE_HW_SEV,
                    AttestationMode::Sgx => MODE_HW_SGX,
                    AttestationMode::Sim | AttestationMode::Software => {
                        return Err(DomainError::TeeRequired("software/sim cannot produce HW seal envelopes".into()));
                    }
                };
                let (nonce, ct) = Self::aead_encrypt(&key, plaintext)?;
                key.zeroize();
                Ok(Self::pack_envelope(mode, &salt, &nonce, &ct))
            }
        }
    }

    fn unseal_envelope(&self, blob: &[u8]) -> Result<Vec<u8>, DomainError> {
        let (mode, salt, nonce, ciphertext) = Self::parse_envelope(blob)?;
        match mode {
            MODE_STAGING_STUB => {
                #[cfg(feature = "production")]
                {
                    return Err(DomainError::TeeRequired(
                        "staging-stub envelope refused under production feature".into(),
                    ));
                }
                #[cfg(not(feature = "production"))]
                {
                    let SealBackend::StagingStub { passphrase } = &self.backend else {
                        return Err(DomainError::TeeRequired(
                            "staging-stub envelope refused without ATTESTATION_STAGING_STUB".into(),
                        ));
                    };
                    let mut key = self.derive_stub_key(passphrase, &salt)?;
                    let plain = Self::aead_decrypt(&key, nonce, ciphertext)?;
                    key.zeroize();
                    Ok(plain)
                }
            }
            MODE_HW_SEV | MODE_HW_SGX => {
                #[cfg(not(feature = "tee_hw"))]
                {
                    let _ = (salt, nonce, ciphertext);
                    return Err(DomainError::TeeRequired("HW TEE unseal requires --features tee_hw".into()));
                }
                #[cfg(feature = "tee_hw")]
                {
                    let SealBackend::Hw { platform } = &self.backend else {
                        return Err(DomainError::TeeRequired(
                            "HW TEE envelope refused without tee_hw HW backend".into(),
                        ));
                    };
                    let expected = if mode == MODE_HW_SEV { AttestationMode::Sev } else { AttestationMode::Sgx };
                    if *platform != expected {
                        return Err(DomainError::ShareStoreForbidden(format!(
                            "tee seal mode {} does not match platform {}",
                            mode,
                            platform.as_str()
                        )));
                    }
                    let mut root = Self::derive_hw_root(*platform)?;
                    let mut key = Self::mix_seal_key(&root, &salt, &self.measurement);
                    root.zeroize();
                    let plain = Self::aead_decrypt(&key, nonce, ciphertext)?;
                    key.zeroize();
                    Ok(plain)
                }
            }
            other => Err(DomainError::ShareStoreForbidden(format!("unknown tee seal mode {other}"))),
        }
    }
}

impl Default for TeeSealAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareStorePort for TeeSealAdapter {
    fn store_kind(&self) -> &'static str {
        match &self.backend {
            SealBackend::FailClosed => "tee_seal",
            #[cfg(not(feature = "production"))]
            SealBackend::StagingStub { .. } => "tee_seal_staging_stub",
            #[cfg(feature = "tee_hw")]
            SealBackend::Hw { platform } => match platform {
                AttestationMode::Sev => "tee_seal_hw_sev",
                AttestationMode::Sgx => "tee_seal_hw_sgx",
                AttestationMode::Sim | AttestationMode::Software => "tee_seal",
            },
        }
    }

    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError> {
        match &self.backend {
            SealBackend::FailClosed => {
                return Err(DomainError::TeeRequired(
                    "TEE seal path not available; host disk AEAD is lab-only (production fail-closed)".into(),
                ));
            }
            #[cfg(not(feature = "production"))]
            SealBackend::StagingStub { .. } => {
                if self.attestation.is_some() {
                    self.require_attestation_ok()?;
                }
            }
            #[cfg(feature = "tee_hw")]
            SealBackend::Hw { .. } => {
                self.require_attestation_ok()?;
            }
        }
        fs::create_dir_all(&self.root).map_err(|e| DomainError::ShareStoreForbidden(format!("tee seal mkdir: {e}")))?;
        let sealed = self.seal_envelope(plaintext)?;
        atomic_write(&self.path_for(share_id), &sealed)
    }

    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError> {
        if matches!(&self.backend, SealBackend::FailClosed) {
            return Err(DomainError::TeeRequired(
                "TEE unseal path not available; host disk AEAD is lab-only (production fail-closed)".into(),
            ));
        }
        // Versioned HW/stub envelopes unseal only after attestation OK.
        self.require_attestation_ok()?;
        let bytes = fs::read(self.path_for(share_id))
            .map_err(|e| DomainError::ShareStoreForbidden(format!("tee seal read: {e}")))?;
        self.unseal_envelope(&bytes)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), DomainError> {
    super::durable_fs::atomic_write_fsync(path, data)
}

#[cfg(feature = "tee_hw")]
mod hw {
    use super::*;

    pub(super) fn sev_snp_derived_root() -> Result<[u8; 32], DomainError> {
        if !Path::new("/dev/sev-guest").exists() {
            return Err(DomainError::TeeRequired(
                "SEV-SNP seal unavailable: /dev/sev-guest missing (fail-closed without HW)".into(),
            ));
        }
        use sev_snp_utilities::guest::derived_key::derived_key::DerivedKey;
        use sev_snp_utilities::guest::derived_key::get_derived_key::{DerivedKeyRequestBuilder, DerivedKeyRequester};
        let options = DerivedKeyRequestBuilder::new().with_launch_measurement().with_tcb_version().build();
        DerivedKey::request(options).map_err(|e| DomainError::TeeRequired(format!("SEV-SNP derived key failed: {e}")))
    }

    /// SGX sealing (`sgx_seal_data`) lives inside an enclave SDK; host CI has no path.
    pub(super) fn sgx_seal_root() -> Result<[u8; 32], DomainError> {
        let _ = Path::new("/dev/sgx_enclave").exists()
            || Path::new("/dev/isgx").exists()
            || Path::new("/dev/sgx/enclave").exists();
        Err(DomainError::TeeRequired(
            "SGX seal unavailable on host path (enclave sgx_seal_data SDK required; fail-closed)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TeeAttestationAdapter;

    #[cfg(any(not(feature = "production"), feature = "tee_hw"))]
    struct TempDir(PathBuf);
    #[cfg(any(not(feature = "production"), feature = "tee_hw"))]
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-tee-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    #[cfg(any(not(feature = "production"), feature = "tee_hw"))]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(any(not(feature = "production"), feature = "tee_hw"))]
    fn stub_attestation(measurement: Measurement) -> Arc<dyn AttestationPort> {
        Arc::new(TeeAttestationAdapter::new(AttestationMode::Sev, true, b"plat", measurement).unwrap())
    }

    #[cfg(not(feature = "production"))]
    #[test]
    fn staging_stub_roundtrip_envelope() {
        let tmp = TempDir::new("round");
        let m = Measurement::from_bytes(b"pin-v1");
        let store = TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", m.clone()).with_attestation(stub_attestation(m));
        store.put_share("s1", b"frost-share-bytes").unwrap();
        let got = store.get_share("s1").unwrap();
        assert_eq!(got, b"frost-share-bytes");
        let raw = std::fs::read(store.path_for("s1")).unwrap();
        assert_eq!(&raw[..8], MAGIC);
        assert_eq!(raw[8], ENVELOPE_VERSION);
        assert_eq!(raw[9], MODE_STAGING_STUB);
    }

    #[cfg(not(feature = "production"))]
    #[test]
    fn staging_stub_unseal_requires_attestation_ok() {
        let tmp = TempDir::new("att-gate");
        let m = Measurement::from_bytes(b"pin-att");
        let store =
            TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", m.clone()).with_attestation(stub_attestation(m.clone()));
        store.put_share("s1", b"secret").unwrap();

        let no_att = TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", m);
        assert!(matches!(no_att.get_share("s1"), Err(DomainError::TeeRequired(_))));
    }

    #[test]
    fn fail_closed_without_hw_no_stub() {
        let store = TeeSealAdapter::fail_closed(Measurement::from_bytes(b"x"));
        assert!(matches!(store.put_share("s", b"x"), Err(DomainError::TeeRequired(_))));
        assert!(matches!(store.get_share("s"), Err(DomainError::TeeRequired(_))));
        assert_eq!(store.store_kind(), "tee_seal");
    }

    #[cfg(not(feature = "production"))]
    #[test]
    fn stub_path_only_when_explicitly_allowed() {
        let tmp = TempDir::new("stub-only");
        let m = Measurement::from_bytes(b"pin-a");
        let allowed =
            TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", m.clone()).with_attestation(stub_attestation(m.clone()));
        allowed.put_share("s1", b"secret").unwrap();

        let refused = TeeSealAdapter::fail_closed(m);
        assert!(matches!(refused.get_share("s1"), Err(DomainError::TeeRequired(_))));
        assert!(matches!(
            refused.unseal_envelope(&std::fs::read(allowed.path_for("s1")).unwrap()),
            Err(DomainError::TeeRequired(_))
        ));
    }

    #[cfg(feature = "production")]
    #[test]
    fn production_feature_refuses_stub_envelope() {
        let store = TeeSealAdapter::fail_closed(Measurement::from_bytes(b"prod"));
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.push(ENVELOPE_VERSION);
        blob.push(MODE_STAGING_STUB);
        blob.extend_from_slice(&[0u8; 16 + 12 + 16]);
        assert!(matches!(store.unseal_envelope(&blob), Err(DomainError::TeeRequired(_))));
        assert!(!cfg!(feature = "dealer_lab"));
    }

    #[cfg(not(feature = "production"))]
    #[test]
    fn wrong_measurement_cannot_unseal() {
        let tmp = TempDir::new("meas");
        let a = TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", Measurement::from_bytes(b"pin-a"))
            .with_attestation(stub_attestation(Measurement::from_bytes(b"pin-a")));
        a.put_share("s1", b"secret").unwrap();
        let b = TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", Measurement::from_bytes(b"pin-b"))
            .with_attestation(stub_attestation(Measurement::from_bytes(b"pin-b")));
        assert!(b.get_share("s1").is_err());
    }

    #[cfg(feature = "tee_hw")]
    #[test]
    fn tee_hw_sev_fail_closed_without_device() {
        let tmp = TempDir::new("hw-sev");
        let m = Measurement::from_bytes(b"hw-pin");
        let att = stub_attestation(m.clone());
        let store = TeeSealAdapter::hw(&tmp.0, AttestationMode::Sev, m, att).unwrap();
        let err = store.put_share("s", b"x").unwrap_err();
        assert!(matches!(err, DomainError::TeeRequired(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("sev-guest") || msg.contains("SEV") || msg.contains("attestation"),
            "unexpected err: {msg}"
        );
    }

    #[cfg(feature = "tee_hw")]
    #[test]
    fn tee_hw_sgx_fail_closed_without_enclave_sdk() {
        let tmp = TempDir::new("hw-sgx");
        let m = Measurement::from_bytes(b"hw-sgx-pin");
        let att = Arc::new(TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat", m.clone()).unwrap())
            as Arc<dyn AttestationPort>;
        let store = TeeSealAdapter::hw(&tmp.0, AttestationMode::Sgx, m, att).unwrap();
        let err = store.put_share("s", b"x").unwrap_err();
        assert!(matches!(err, DomainError::TeeRequired(_)));
        assert!(err.to_string().contains("SGX") || err.to_string().contains("enclave"));
    }
}
