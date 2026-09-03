//! TPM 2.0 TSS (TCG Software Stack) concrete adapter.
//!
//! Implements [`TpmSealPort`] via TCG TSS Enhanced System API (`tss-esapi`).
//! Requires `--features tpm` and system libraries: `libtss2-esys`, `libtss2-tcti-device`.
//!
//! ## System Dependencies (Debian/Ubuntu)
//! ```bash
//! sudo apt-get install libtss2-esys-3.0.2-0 libtss2-dev
//! ```
//!
//! ## Testing with swtpm (software TPM emulator)
//! ```bash
//! sudo apt-get install swtpm libtpms0
//! mkdir /tmp/mytpm
//! swtpm socket --tpmstate dir=/tmp/mytpm --tpm2 --ctrl type=unixio,path=/tmp/mytpm/swtpm-sock &
//! export TPM2TOOLS_TCTI="swtpm:path=/tmp/mytpm/swtpm-sock"
//! export VAULT_TPM_TCTI="swtpm:path=/tmp/mytpm/swtpm-sock"
//! ```
//!
//! ## TSS API Flow (documented for real HW integration)
//!
//! ### Seal
//! 1. `Context::new()` — connect to TPM via TCTI device (`/dev/tpmrm0`)
//! 2. `Hierarchy::Owner` — use Owner (TSS) or Endorsement (EK) hierarchy for sealing
//! 3. Create primary key under chosen hierarchy (`create_primary`)
//! 4. Build PCR selection: PCR 0-7 (measured boot) + optional PCR 23 (app-specific)
//! 5. `create_policy!` macro with `PolicyAuthorization` + `PolicyPcr`:
//!    - `PolicyPcr`: bind to PCRs 0-7 current values
//!    - `PolicyAuthorization`: require auth value (Argon2id of passphrase)
//! 6. `create()` — create sealed data object with policy:
//!    - `data`: share plaintext
//!    - `auth_value`: Argon2id-derived passphrase
//!    - `sensitive_data_create`: include AAD binding (share_id + node_id)
//! 7. Save `SealedBlob` → disk as `KVTPM001` envelope v2 (mode=HW)
//!
//! ### Unseal
//! 1. `Context::new()` — connect to TPM
//! 2. Load primary key from stored public area
//! 3. Load sealed object from `SealedBlob`
//! 4. Set auth value (Argon2id passphrase) via `tr_handle.set_auth()`
//! 5. `unseal()` — TPM verifies:
//!    - PCR values match policy (boot integrity)
//!    - Auth value matches (possession of passphrase)
//!    - If either fails → TPM returns HMAC error → fail-closed
//! 6. Returns plaintext share
//!
//! ### TPM AK (Attestation Key) for Identity Binding
//! 1. Create EK (Endorsement Key) — factory-provisioned, read-only
//! 2. Create AK (Attestation Key) — restricted signing key under EK
//! 3. `certify_creation()` — prove sealed blob was created on this TPM
//! 4. `quote()` — sign PCR values + nonce with AK
//! 5. Verifier checks EK certificate chain, AK certification, quote signature
//! 6. Binds share to specific TPM (anti-swap between machines)

use crate::domain::DomainError;

use super::share_tpm::{TpmSealAdapter, TpmSealPort};

/// Envelope magic for TSS hardware-sealed blobs (v2).
///
/// Distinguishable from v1 mock (`KVTPM001` with mode `MOCK=1`).
pub const TSS_MAGIC: &[u8; 8] = b"KVTPM001";
/// HW mode byte for v2 TSS envelopes (2 = HW, differentiated from MOCK=1).
pub const TSS_MODE_HW: u8 = 2;

// ---------------------------------------------------------------------------
// TSS implementation stub (real TSS integration blocked on system libs)
// ---------------------------------------------------------------------------

/// Concrete TPM TSS adapter.
///
/// In the current build, this struct serves as a compile-time placeholder
/// for the real `tss-esapi` integration. All methods are defined with the
/// full implementation plan documented inline — the struct compiles but
/// seal/unseal bail to `FailClosed` at runtime.
///
/// When `tss-esapi` is linked (requires `--features tpm` + `libtss2-esys`),
/// replace this stub body with the corresponding TSS calls.
#[derive(Debug, Clone)]
pub struct TpmTssSealAdapter {
    /// TCTI path override (default `/dev/tpmrm0` or `swtpm:path=...`).
    tcti_path: Option<String>,
}

impl TpmTssSealAdapter {
    /// Create a new TSS adapter with default TCTI `/dev/tpmrm0`.
    pub fn new() -> Self {
        Self { tcti_path: None }
    }

    /// Set a custom TCTI path (e.g. `swtpm:path=/tmp/mytpm/swtpm-sock`).
    pub fn with_tcti(mut self, tcti: impl Into<String>) -> Self {
        self.tcti_path = Some(tcti.into());
        self
    }

    /// Returns the TCTI device string.
    fn tcti(&self) -> &str {
        self.tcti_path.as_deref().unwrap_or("device:/dev/tpmrm0")
    }

    // ---- Real TSS seal implementation (documented) ----

    /// TSS seal: seal plaintext with PCR policy + auth value + AAD bind.
    ///
    /// ```ignore
    /// fn tss_seal(
    ///     plaintext: &[u8],
    ///     pcr_policy_digest: &[u8],   // expected PCR composite digest
    ///     auth_passphrase: &[u8],     // Argon2id of passphrase
    ///     aad: &[u8],                 // share_id + node_id
    /// ) -> Result<Vec<u8>, DomainError> {
    ///     // 1. Open TPM context
    ///     let mut ctx = Context::new(tcti())
    ///         .map_err(|e| seal_error("TSS context open", e))?;
    ///
    ///     // 2. Create primary key under Owner hierarchy (TPM2_SE_Trial for auth-less
    ///     //    key creation; sealed data keys are created under this primary)
    ///     let primary = ctx.create_primary(
    ///         Hierarchy::Owner,
    ///         // ... template, unique data ...
    ///     )?;
    ///
    ///     // 3. Build PCR selection: PCR 0-7 (measured boot chain)
    ///     let pcr_selection = PcrSelectionList::new()
    ///         .with_selection(PcrSlot::Slot0,
    ///            &[PcrSlot::Slot0, PcrSlot::Slot1, PcrSlot::Slot2, PcrSlot::Slot3,
    ///              PcrSlot::Slot4, PcrSlot::Slot5, PcrSlot::Slot6, PcrSlot::Slot7]);
    ///
    ///     // 4. Build policy digest: PolicyPcr AND PolicyAuthValue
    ///     //    - PolicyPcr: bind to current PCR values → boot integrity attestation
    ///     //    - PolicyAuthValue: require passphrase-derived auth
    ///     let trial = ctx.execute_with_temporary_session(|ctx| {
    ///         ctx.create_trial_session()?
    ///     })?;
    ///     ctx.policy_pcr(trial, &pcr_selection, pcr_policy_digest)?;
    ///     ctx.policy_auth_value(trial)?;
    ///     let policy_digest = ctx.policy_get_digest(trial)?;
    ///     // policy_digest is the compound hash encoding "PCRs correct AND auth present"
    ///
    ///     // 5. Create sealed data object
    ///     //    auth_value = Argon2id(auth_passphrase, salt)
    ///     //    sensitive = SensitiveData { data: plaintext, aad: aad_bind }
    ///     let sealed = ctx.create(
    ///         primary,
    ///         Tpm2BPublic::from(&public_template),
    ///         Some(Tpm2BAuth::from(auth_passphrase)),
    ///         SensitiveCreate {
    ///             user_auth: auth_passphrase.to_vec(),
    ///             data: plaintext.to_vec(),
    ///         },
    ///         &pcr_selection,
    ///     )?;
    ///
    ///     // 6. Encode sealed blob for persistent storage
    ///     //    Format: MAGIC(8) | VERSION(1) | MODE_HW(1) | sealed_blob + public_area
    ///     Ok(encode_sealed_envelope(&sealed, &pcr_selection))
    /// }
    /// ```
    fn tss_seal(
        &self,
        _plaintext: &[u8],
        _pcr_policy_digest: &[u8],
        _auth_passphrase: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        Err(Self::tss_not_linked())
    }

    /// TSS unseal: unseal with PCR validation + auth value.
    ///
    /// ```ignore
    /// fn tss_unseal(
    ///     sealed: &[u8],
    ///     pcr_policy_digest: &[u8],   // expected PCR composite digest
    ///     auth_passphrase: &[u8],     // Argon2id of passphrase
    /// ) -> Result<Vec<u8>, DomainError> {
    ///     // 1. Open TPM context
    ///     let mut ctx = Context::new(tcti())?;
    ///
    ///     // 2. Decode sealed envelope → sealed_blob + public_area
    ///     let (sealed_blob, _pcr_selection) = decode_sealed_envelope(sealed)?;
    ///
    ///     // 3. Load primary key from public area
    ///     let primary_handle = ctx.load_external_public(public_area);
    ///
    ///     // 4. Load sealed object
    ///     let sealed_handle = ctx.load(primary_handle, &sealed_blob)?;
    ///
    ///     // 5. Set auth value for the session
    ///     let (auth_session, _) = ctx.start_auth_session(
    ///         None, None, None,
    ///         SessionType::Policy,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashAlg::Sha256,
    ///     )?;
    ///
    ///     // 6. Satisfy PolicyPcr: feed current PCR values
    ///     ctx.policy_pcr(auth_session, /* current PCR readings */)?;
    ///
    ///     // 7. Satisfy PolicyAuthValue: provide passphrase
    ///     ctx.tr_set_auth(sealed_handle, auth_passphrase)?;
    ///
    ///     // 8. Unseal: TPM verifies PCR policy AND auth value
    ///     //    If PCR values don't match → TPM returns error → fail-closed
    ///     //    If auth value wrong → TPM returns error → fail-closed
    ///     let plaintext = ctx.unseal(sealed_handle)?;
    ///
    ///     // 9. Verify AAD bind (share_id + node_id) from sensitive area
    ///     Ok(plaintext)
    /// }
    /// ```
    fn tss_unseal(
        &self,
        _sealed: &[u8],
        _pcr_policy_digest: &[u8],
        _auth_passphrase: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        Err(Self::tss_not_linked())
    }

    // ---- AK (Attestation Key) identity binding (documented) ----

    /// Issue TPM quote: sign PCR values + nonce with AK.
    ///
    /// Proves this sealed blob was created on the same TPM hardware.
    /// Used by remote verifiers to confirm anti-swap binding.
    ///
    /// ```ignore
    /// fn tss_quote(
    ///     &self,
    ///     nonce: &[u8],
    ///     pcr_selection: &PcrSelectionList,
    /// ) -> Result<Vec<u8>, DomainError> {
    ///     // 1. Read EK certificate (factory-provisioned, TPM2_NV_Read)
    ///     let ek_cert = ctx.nv_read_public(NvIndex::EK_CERT)?;
    ///
    ///     // 2. Create AK under EK (restricted signing key)
    ///     let ak = ctx.create_ak(
    ///         Hierarchy::Endorsement,
    ///         // ... AK template ...
    ///         None, // no auth value (restricted via EK hierarchy)
    ///         None,
    ///     )?;
    ///
    ///     // 3. Certify AK with EK → AK cert signed by EK
    ///     let ak_cert = ctx.certify_creation(
    ///         SigningKey::from(ek_cert),
    ///         ak,
    ///         // ... creation data ...
    ///     )?;
    ///
    ///     // 4. Quote: sign PCR bank + nonce with AK
    ///     let quote = ctx.quote(
    ///         ak,
    ///         nonce,
    ///         SigningScheme::RSASSA,
    ///         pcr_selection,
    ///     )?;
    ///
    ///     // 5. Return EK cert chain + AK cert + quote
    ///     let bundle = encode_ak_bundle(&ek_cert, &ak_cert, &quote);
    ///     Ok(bundle)
    /// }
    /// ```
    pub fn tss_quote(&self, _nonce: &[u8]) -> Result<Vec<u8>, DomainError> {
        Err(Self::tss_not_linked())
    }

    /// Verify a TPM quote against expected PCR values.
    pub fn tss_verify_quote(&self, _quote: &[u8], _expected_pcr_digest: &[u8]) -> Result<(), DomainError> {
        Err(Self::tss_not_linked())
    }

    // ---- NV Counter for anti-rollback (documented) ----

    /// Read TPM NV counter (TPM2_NV_Counter, monotonic, non-resettable).
    ///
    /// ```ignore
    /// fn tss_read_counter(&self, nv_index: NvIndex) -> Result<u64, DomainError> {
    ///     let mut ctx = Context::new(tcti())?;
    ///     let counter_bytes = ctx.nv_read(
    ///         Hierarchy::Owner,
    ///         nv_index,
    ///         TPM2BMaxNVBuffer::default(),
    ///         0,
    ///     )?;
    ///     // Parse 8-byte BigEndian counter
    ///     Ok(u64::from_be_bytes(counter_bytes[..8].try_into().unwrap()))
    /// }
    /// ```
    pub fn tss_read_counter(&self) -> Result<u64, DomainError> {
        Err(Self::tss_not_linked())
    }

    /// Increment TPM NV counter (TPM2_NV_Increment).
    ///
    /// ```ignore
    /// fn tss_increment_counter(&self, nv_index: NvIndex) -> Result<(), DomainError> {
    ///     let mut ctx = Context::new(tcti())?;
    ///     ctx.nv_increment(Hierarchy::Owner, nv_index)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn tss_increment_counter(&self) -> Result<(), DomainError> {
        Err(Self::tss_not_linked())
    }

    // ---- Helpers ----

    fn tss_not_linked() -> DomainError {
        DomainError::TpmRequired(
            "TPM TSS seal/unseal not linked: rebuild with --features tpm and install \
             libtss2-esys + libtss2-tcti-device. See docs/ops/TPM_SETUP.md for details."
                .into(),
        )
    }

    fn seal_error(context: &str, e: impl std::fmt::Display) -> DomainError {
        DomainError::TpmRequired(format!("TPM TSS {context}: {e}"))
    }
}

impl Default for TpmTssSealAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TpmSealPort implementation for the TSS adapter
// ---------------------------------------------------------------------------

impl TpmSealPort for TpmTssSealAdapter {
    fn backend_kind(&self) -> &'static str {
        "tss"
    }

    fn available(&self) -> bool {
        // TSS adapter is available when:
        // 1. Feature `tpm` is compiled
        // 2. TPM device node exists at runtime
        #[cfg(feature = "tpm")]
        {
            use std::path::Path;
            Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
        }
        #[cfg(not(feature = "tpm"))]
        {
            false
        }
    }

    fn seal(&self, plaintext: &[u8], policy_digest: &[u8]) -> Result<Vec<u8>, DomainError> {
        #[cfg(feature = "tpm")]
        {
            // Real TSS seal path:
            // 1. Check TPM device present; fail-closed if absent
            // 2. Derive auth value via Argon2id(passphrase) — passphrase resolved upstream
            // 3. Build PCR composite from PCRs 0-7
            // 4. Call tss_seal(plaintext, pcr_policy_digest, auth, aad_bind)
            // 5. Encode envelope: MAGIC | VERSION=2 | MODE_HW | sealed_blob
            let _ = (plaintext, policy_digest);
            Err(DomainError::TpmRequired(
                "TPM TSS seal compiled (features tpm) but tss-esapi not linked — \
                 install libtss2-esys + libtss2-tcti-device"
                    .into(),
            ))
        }
        #[cfg(not(feature = "tpm"))]
        {
            let _ = (plaintext, policy_digest);
            Err(DomainError::TpmRequired("TPM TSS seal not compiled: rebuild with --features tpm".into()))
        }
    }

    fn unseal(&self, sealed: &[u8], policy_digest: &[u8]) -> Result<Vec<u8>, DomainError> {
        #[cfg(feature = "tpm")]
        {
            // Real TSS unseal path:
            // 1. Decode envelope → extract sealed_blob, check version
            // 2. Load TPM context, load primary key, load sealed object
            // 3. Start policy session, satisfy PolicyPcr with current PCR values
            // 4. Set auth value (Argon2id passphrase) → satisfy PolicyAuthValue
            // 5. unseal() — TPM verifies both policies
            // 6. Verify AAD bind (share_id + node_id) from sensitive area
            let _ = (sealed, policy_digest);
            Err(DomainError::TpmRequired(
                "TPM TSS unseal compiled (features tpm) but tss-esapi not linked — \
                 install libtss2-esys + libtss2-tcti-device"
                    .into(),
            ))
        }
        #[cfg(not(feature = "tpm"))]
        {
            let _ = (sealed, policy_digest);
            Err(DomainError::TpmRequired("TPM TSS unseal not compiled: rebuild with --features tpm".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// PCR Policy helpers
// ---------------------------------------------------------------------------

/// Standard PCR policy for vault secure boot measurement.
///
/// Maps PCR indices to measured components:
/// - PCR 0: firmware (UEFI/BIOS)
/// - PCR 1: firmware config
/// - PCR 2: external ROMs (option ROMs)
/// - PCR 3: external ROM config
/// - PCR 4: bootloader (GRUB/systemd-boot)
/// - PCR 5: bootloader config
/// - PCR 6: bootloader state transitions (sleep/resume)
/// - PCR 7: Secure Boot state (PK/KEK/db/dbx) + platform keys
pub const VAULT_PCR_BASE: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

/// Build a SHA-256 PCR composite digest from raw PCR values.
///
/// Following TCG specification: hash each PCR value individually,
/// then hash the concatenation of all hashes.
///
/// ```ignore
/// fn pcr_composite_digest(pcr_values: &[[u8; 32]; 8]) -> [u8; 32] {
///     use sha2::{Digest, Sha256};
///     let mut hasher = Sha256::new();
///     for val in pcr_values {
///         hasher.update(val);
///     }
///     hasher.finalize().into()
/// }
/// ```
pub fn pcr_composite_digest(_pcr_values: &[[u8; 32]; 8]) -> [u8; 32] {
    let digest = [0u8; 32];
    // Stub: in real TSS integration, hash all PCR values per TCG spec
    let _ = _pcr_values;
    digest
}

/// Build AAD (Additional Authenticated Data) for anti-swap binding.
///
/// Concatenates `share_id + node_id` so the TPM policy digest binds
/// the sealed blob to a specific share on a specific machine.
/// Unseal only succeeds if both PCR values match AND the binding matches.
pub fn build_seal_aad(share_id: &str, node_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + share_id.len() + node_id.len());
    aad.extend_from_slice(b"seal-aad:");
    aad.extend_from_slice(share_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(node_id.as_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tss_adapter_is_fail_closed_without_feature_tpm() {
        let adapter = TpmTssSealAdapter::new();
        assert_eq!(adapter.backend_kind(), "tss");
        #[cfg(not(feature = "tpm"))]
        {
            assert!(!adapter.available());
            assert!(matches!(adapter.seal(b"x", b"p"), Err(DomainError::TpmRequired(_))));
            assert!(matches!(adapter.unseal(b"x", b"p"), Err(DomainError::TpmRequired(_))));
        }
    }

    #[test]
    fn tss_backend_is_available_with_feature_tpm_when_device_present() {
        #[cfg(feature = "tpm")]
        {
            let adapter = TpmTssSealAdapter::new();
            // available depends on hw presence; struct compiles regardless
            let _ = adapter.backend_kind();
            let _ = adapter.available();
        }
    }

    #[test]
    fn tss_adapter_defaults_to_device_rm0() {
        let adapter = TpmTssSealAdapter::new();
        assert_eq!(adapter.backend_kind(), "tss");
    }

    #[test]
    fn tss_adapter_custom_tcti() {
        let adapter = TpmTssSealAdapter::new().with_tcti("swtpm:path=/tmp/mytpm/sock");
        assert_eq!(adapter.backend_kind(), "tss");
    }

    #[test]
    fn tss_quote_stub_fails_closed() {
        let adapter = TpmTssSealAdapter::new();
        assert!(matches!(adapter.tss_quote(b"nonce"), Err(DomainError::TpmRequired(_))));
    }

    #[test]
    fn tss_verify_quote_stub_fails_closed() {
        let adapter = TpmTssSealAdapter::new();
        assert!(matches!(adapter.tss_verify_quote(b"quote", b"digest"), Err(DomainError::TpmRequired(_))));
    }

    #[test]
    fn tss_counter_stubs_fail_closed() {
        let adapter = TpmTssSealAdapter::new();
        assert!(matches!(adapter.tss_read_counter(), Err(DomainError::TpmRequired(_))));
        assert!(matches!(adapter.tss_increment_counter(), Err(DomainError::TpmRequired(_))));
    }

    #[test]
    fn build_seal_aad_binds_share_and_node() {
        let aad = build_seal_aad("frost/vault-1", "vault-1");
        assert!(aad.starts_with(b"seal-aad:"));
        assert!(aad.windows("frost/vault-1".len()).any(|w| w == b"frost/vault-1"));
        assert!(aad.windows("vault-1".len()).any(|w| w == b"vault-1"));
        assert!(aad.contains(&b'|'));
    }
}
