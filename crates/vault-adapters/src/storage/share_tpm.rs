//! Optional TPM 2.0 protection for domestic AEAD passphrases.
//!
//! TPM ≠ SEV: it protects the passphrase at rest, not host memory after unseal.
//! `VAULT_SHARE_TPM_SEAL=1` enables sealing; `VAULT_SHARE_TPM_STUB=1` and
//! `VAULT_SHARE_TPM_CLEAR_FALLBACK=1` are lab-only controls.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::domain::DomainError;

const MAGIC: &[u8; 8] = b"KVTPM001";
const VERSION: u8 = 1;
const MOCK: u8 = 1;
const HW: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 8 + 1 + 1 + SALT_LEN + NONCE_LEN;

/// Port for policy-bound TPM passphrase sealing.
pub trait TpmSealPort: Send + Sync {
    fn backend_kind(&self) -> &'static str;
    fn available(&self) -> bool;
    fn seal(&self, plaintext: &[u8], policy_digest: &[u8]) -> Result<Vec<u8>, DomainError>;
    fn unseal(&self, sealed: &[u8], policy_digest: &[u8]) -> Result<Vec<u8>, DomainError>;
}

/// Available TPM backends. Hardware probing remains fail-closed until TSS is wired.
///
/// Variants:
/// - `FailClosed`: No TPM available, all operations refused
/// - `Mock`: Software mock for CI/testing (ChaCha20-Poly1305 envelope with mock key derivation)
/// - `HwProbe`: TPM device detected but TSS seal support not compiled/linked
/// - `Tss(Box<TpmTssSealAdapter>)`: Real TSS integration (requires `--features tpm` + libtss2-esys)
#[derive(Debug, Clone)]
pub enum TpmSealAdapter {
    FailClosed,
    Mock,
    HwProbe,
    /// TPM TSS hardware adapter (compiled with `--features tpm`).
    /// Delegates seal/unseal to TCG TSS Enhanced System API.
    Tss(Box<super::share_tpm_tss::TpmTssSealAdapter>),
}

impl TpmSealAdapter {
    fn required(reason: impl Into<String>) -> DomainError {
        DomainError::TpmRequired(reason.into())
    }

    fn mock_key(policy: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"kerosene-vault-tpm-mock-v1");
        digest.update(policy);
        digest.update(salt);
        digest.finalize().into()
    }

    fn mock_seal(plaintext: &[u8], policy: &[u8]) -> Result<Vec<u8>, DomainError> {
        let mut salt = [0; SALT_LEN];
        let mut nonce = [0; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut key = Self::mock_key(policy, &salt);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("TPM mock cipher: {e}")))?;
        key.zeroize();
        let mut envelope = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&[VERSION, MOCK]);
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &envelope })
            .map_err(|_| Self::required("TPM mock seal failed"))?;
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn mock_unseal(sealed: &[u8], policy: &[u8]) -> Result<Vec<u8>, DomainError> {
        if sealed.len() < HEADER_LEN + 16 {
            return Err(Self::required("TPM sealed envelope is too short"));
        }
        if &sealed[..8] != MAGIC || sealed[8] != VERSION || sealed[9] != MOCK {
            return Err(Self::required("TPM sealed envelope is invalid"));
        }
        let salt = &sealed[10..10 + SALT_LEN];
        let nonce_start = 10 + SALT_LEN;
        let ciphertext_start = nonce_start + NONCE_LEN;
        let mut key = Self::mock_key(policy, salt);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("TPM mock cipher: {e}")))?;
        key.zeroize();
        cipher
            .decrypt(
                Nonce::from_slice(&sealed[nonce_start..ciphertext_start]),
                Payload { msg: &sealed[ciphertext_start..], aad: &sealed[..ciphertext_start] },
            )
            .map_err(|_| Self::required("TPM unseal rejected by policy or ciphertext"))
    }
}

impl TpmSealPort for TpmSealAdapter {
    fn backend_kind(&self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::Mock => "mock",
            Self::HwProbe => "hw_probe",
            Self::Tss(_) => "tss",
        }
    }

    fn available(&self) -> bool {
        !matches!(self, Self::FailClosed)
    }

    fn seal(&self, plaintext: &[u8], policy: &[u8]) -> Result<Vec<u8>, DomainError> {
        match self {
            Self::Mock => Self::mock_seal(plaintext, policy),
            Self::FailClosed => Err(Self::required("no TPM 2.0 device is available")),
            Self::HwProbe => Err(Self::required("TPM device detected but TSS seal support is not implemented")),
            Self::Tss(tss) => tss.seal(plaintext, policy),
        }
    }

    fn unseal(&self, sealed: &[u8], policy: &[u8]) -> Result<Vec<u8>, DomainError> {
        match self {
            Self::Mock => Self::mock_unseal(sealed, policy),
            Self::FailClosed => Err(Self::required("no TPM 2.0 device is available")),
            Self::HwProbe => {
                let reason = if sealed.get(9) == Some(&HW) {
                    "TPM hardware envelope requires unimplemented TSS support"
                } else {
                    "TPM device detected but TSS unseal support is not implemented"
                };
                Err(Self::required(reason))
            }
            Self::Tss(tss) => tss.unseal(sealed, policy),
        }
    }
}

/// Resolved passphrase and whether a lab fallback bypassed TPM sealing.
pub struct ResolvedPassphrase {
    pub passphrase: String,
    pub tpm_backend: &'static str,
    pub used_clear_fallback: bool,
}

/// Returns `<data-root>/tpm-passphrase.sealed`.
pub fn sealed_passphrase_path(data_root: &Path) -> PathBuf {
    data_root.join("tpm-passphrase.sealed")
}

/// Returns whether either conventional Linux TPM device node exists.
pub fn tpm_device_present() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

/// Creates the configured TPM port; disabled sealing has no port.
///
/// Priority:
/// 1. If `--features tpm` and device present → `TpmSealAdapter::Tss(TpmTssSealAdapter)`
/// 2. If lab stub → `TpmSealAdapter::Mock` (ChaCha20 mock, lab only)
/// 3. If device present but no TSS → `TpmSealAdapter::HwProbe` (fail-closed)
/// 4. If no device → `TpmSealAdapter::FailClosed`
pub fn build_tpm_seal_port(
    enabled: bool,
    stub: bool,
    refuse_stub: bool,
) -> Result<Option<Box<dyn TpmSealPort>>, DomainError> {
    if !enabled {
        return Ok(None);
    }
    if stub {
        if refuse_stub || cfg!(feature = "production") {
            return Err(DomainError::LabFlagForbidden("VAULT_SHARE_TPM_STUB".into()));
        }
        return Ok(Some(Box::new(TpmSealAdapter::Mock)));
    }
    Ok(Some(Box::new(if tpm_device_present() {
        // Try TSS first if compiled; fall back to HwProbe (fail-closed stub)
        #[cfg(feature = "tpm")]
        {
            use super::share_tpm_tss::TpmTssSealAdapter;
            TpmSealAdapter::Tss(Box::new(TpmTssSealAdapter::new()))
        }
        #[cfg(not(feature = "tpm"))]
        {
            TpmSealAdapter::HwProbe
        }
    } else {
        TpmSealAdapter::FailClosed
    })))
}

fn policy(data_root: &Path) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kerosene-vault-tpm-passphrase-policy-v1|");
    digest.update(data_root.to_string_lossy().as_bytes());
    digest.finalize().into()
}

fn clear(value: Option<&str>) -> Result<String, DomainError> {
    value.filter(|v| !v.is_empty()).map(str::to_owned).ok_or_else(|| {
        DomainError::ShareStoreForbidden(
            "VAULT_SHARE_PASSPHRASE is required to bootstrap TPM-sealed AEAD storage".into(),
        )
    })
}

fn write_envelope(path: &Path, bytes: &[u8]) -> Result<(), DomainError> {
    let parent = path
        .parent()
        .ok_or_else(|| DomainError::ShareStoreForbidden("TPM sealed passphrase path has no parent".into()))?;
    fs::create_dir_all(parent)
        .map_err(|e| DomainError::ShareStoreForbidden(format!("mkdir TPM passphrase root: {e}")))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| DomainError::ShareStoreForbidden(format!("write TPM envelope: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| DomainError::ShareStoreForbidden(format!("rename TPM envelope: {e}")))
}

/// Bootstraps or reloads the AEAD passphrase from its TPM envelope.
pub fn resolve_aead_passphrase(
    data_root: &Path,
    clear_passphrase: Option<&str>,
    tpm: &dyn TpmSealPort,
    clear_fallback: bool,
) -> Result<ResolvedPassphrase, DomainError> {
    let digest = policy(data_root);
    let path = sealed_passphrase_path(data_root);
    let resolved = if path.exists() {
        fs::read(&path)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("read TPM envelope: {e}")))
            .and_then(|blob| tpm.unseal(&blob, &digest))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| DomainError::ShareStoreForbidden("TPM-unsealed passphrase is not UTF-8".into()))
            })
    } else {
        let value = clear(clear_passphrase)?;
        tpm.seal(value.as_bytes(), &digest).and_then(|blob| {
            write_envelope(&path, &blob)?;
            Ok(value)
        })
    };
    match resolved {
        Ok(passphrase) => {
            Ok(ResolvedPassphrase { passphrase, tpm_backend: tpm.backend_kind(), used_clear_fallback: false })
        }
        Err(_) if clear_fallback => Ok(ResolvedPassphrase {
            passphrase: clear(clear_passphrase)?,
            tpm_backend: tpm.backend_kind(),
            used_clear_fallback: true,
        }),
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Item 2.5: Anti-cloning & rollback protection — TPM NV counter validation
// ---------------------------------------------------------------------------

/// Stored sealed blob with embedded counter for anti-rollback.
///
/// On seal: record current monotonic counter value.
/// On unseal: verify current counter >= stored counter.
/// If counter decreased → rollback detected → refuse unseal (fail-closed).
#[derive(Debug, Clone)]
pub struct CounterSealedBlob {
    pub counter: u64,
    pub sealed_blob: Vec<u8>,
}

impl CounterSealedBlob {
    /// Encode counter + sealed blob for persistent storage.
    /// Format: counter(8 BE) | sealed_blob
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sealed_blob.len());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.sealed_blob);
        out
    }

    /// Decode counter + sealed blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, DomainError> {
        if bytes.len() < 8 {
            return Err(DomainError::TpmRequired("counter sealed blob too short".into()));
        }
        let counter =
            u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok(Self { counter, sealed_blob: bytes[8..].to_vec() })
    }
}

/// Validate TPM NV counter for anti-rollback.
///
/// - `stored_counter`: counter value embedded in sealed blob at seal time
/// - `current_counter`: current TPM NV counter value
///
/// Returns `Ok(())` if current >= stored (monotonic invariant holds).
/// Returns `Err(CounterRollback)` if current < stored (rollback detected).
pub fn validate_tpm_counter(stored_counter: u64, current_counter: u64) -> Result<(), DomainError> {
    if current_counter < stored_counter {
        return Err(DomainError::TpmRequired(format!(
            "TPM counter rollback detected: stored={stored_counter} current={current_counter} \
             (possible TPM state restoration or clone attack)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("kv-tpm-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mock_roundtrip() {
        let blob = TpmSealAdapter::Mock.seal(b"secret", b"policy").unwrap();
        assert_eq!(&blob[..8], MAGIC);
        assert_eq!(blob[8], VERSION);
        assert_eq!(blob[9], MOCK);
        assert_eq!(TpmSealAdapter::Mock.unseal(&blob, b"policy").unwrap(), b"secret");
    }
    #[test]
    fn wrong_policy() {
        let blob = TpmSealAdapter::Mock.seal(b"secret", b"a").unwrap();
        assert!(matches!(TpmSealAdapter::Mock.unseal(&blob, b"b"), Err(DomainError::TpmRequired(_))));
    }
    #[test]
    fn fail_closed() {
        assert!(matches!(TpmSealAdapter::FailClosed.seal(b"x", b"p"), Err(DomainError::TpmRequired(_))));
    }
    #[test]
    fn hw_probe_fail_closed() {
        assert!(TpmSealAdapter::HwProbe.available());
        assert!(matches!(TpmSealAdapter::HwProbe.unseal(&[], b"p"), Err(DomainError::TpmRequired(_))));
    }
    #[test]
    fn resolve_bootstrap_reload() {
        let root = TempDir::new("reload");
        assert_eq!(
            resolve_aead_passphrase(&root.0, Some("secret"), &TpmSealAdapter::Mock, false).unwrap().passphrase,
            "secret"
        );
        assert!(sealed_passphrase_path(&root.0).exists());
        assert_eq!(resolve_aead_passphrase(&root.0, None, &TpmSealAdapter::Mock, false).unwrap().passphrase, "secret");
    }
    #[test]
    fn clear_fallback() {
        let root = TempDir::new("fallback");
        assert!(
            resolve_aead_passphrase(&root.0, Some("secret"), &TpmSealAdapter::FailClosed, true)
                .unwrap()
                .used_clear_fallback
        );
    }
    #[test]
    fn no_fallback() {
        let root = TempDir::new("none");
        assert!(matches!(
            resolve_aead_passphrase(&root.0, Some("secret"), &TpmSealAdapter::FailClosed, false),
            Err(DomainError::TpmRequired(_))
        ));
    }
    #[test]
    fn stub_refused_when_hardened() {
        assert!(matches!(build_tpm_seal_port(true, true, true), Err(DomainError::LabFlagForbidden(_))));
    }
    #[test]
    fn build_port_disabled() {
        assert!(build_tpm_seal_port(false, false, false).unwrap().is_none());
    }

    // --- Item 2.5: Counter anti-rollback tests ---

    #[test]
    fn counter_encode_decode_roundtrip() {
        let blob = CounterSealedBlob { counter: 42, sealed_blob: vec![1, 2, 3] };
        let encoded = blob.encode();
        let decoded = CounterSealedBlob::decode(&encoded).unwrap();
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.sealed_blob, vec![1, 2, 3]);
    }

    #[test]
    fn counter_validation_accepts_equal() {
        assert!(validate_tpm_counter(5, 5).is_ok());
    }

    #[test]
    fn counter_validation_accepts_greater() {
        assert!(validate_tpm_counter(5, 10).is_ok());
    }

    #[test]
    fn counter_validation_rejects_rollback() {
        assert!(matches!(
            validate_tpm_counter(10, 5),
            Err(DomainError::TpmRequired(ref msg)) if msg.contains("rollback")
        ));
    }

    #[test]
    fn counter_decode_rejects_short_blob() {
        assert!(matches!(CounterSealedBlob::decode(&[1, 2, 3]), Err(DomainError::TpmRequired(_))));
    }

    // --- TSS variant test ---

    #[test]
    fn tss_variant_is_fail_closed_without_feature() {
        let tss = TpmSealAdapter::Tss(Box::new(super::super::share_tpm_tss::TpmTssSealAdapter::new()));
        assert_eq!(tss.backend_kind(), "tss");
        // Without --features tpm, TSS seal/unseal fail closed
        assert!(matches!(tss.seal(b"x", b"p"), Err(DomainError::TpmRequired(_))));
        assert!(matches!(tss.unseal(b"x", b"p"), Err(DomainError::TpmRequired(_))));
    }
}
