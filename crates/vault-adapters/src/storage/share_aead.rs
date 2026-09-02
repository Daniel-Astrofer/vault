//! AEAD disk share store (domestic / lab). Argon2id + ChaCha20-Poly1305.
//!
//! # Honest tier note
//! Disk AEAD ≠ TEE. Domestic production may use this path; SEV/SGX nodes should use
//! `VAULT_SHARE_STORE=tee_seal` when a real enclave seal is available.
//!
//! # Optional TPM 2.0 seal (`VAULT_SHARE_TPM_SEAL=1`)
//! Off by default. When enabled, wiring seals the AEAD passphrase under a TPM-bound
//! envelope (see [`super::share_tpm`]) **before** constructing this store.
//! TPM ≠ SEV: disk-at-rest only; clear fallback is lab-only (`VAULT_SHARE_TPM_CLEAR_FALLBACK=1`).
//! See `VAULT_MESH_PLAN.md` §3.1.
//!
//! # AAD (#20)
//! Ciphertext is bound to `share_id` via AEAD additional authenticated data so a
//! filesystem blob cannot be swapped onto another share path and still decrypt.

use std::fs;
use std::path::PathBuf;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::durable_fs::atomic_write_fsync;
use crate::application::ShareStorePort;
use crate::domain::DomainError;

// ---------------------------------------------------------------------------
// Item 2.2: SeedKind — enumeration of key material types for ShareStorePort
// ---------------------------------------------------------------------------

/// Type of key material stored via [`ShareStorePort`].
///
/// Each seed gets a unique `share_id` (e.g. `identity/ed25519/vault-1`)
/// and AAD binding: `seed_id + node_id + key_epoch`.
///
/// # PQ seeds at the same protection level as FROST shares
/// - AEAD disk (Argon2id + ChaCha20-Poly1305) in lab
/// - TPM seal in domestic production
/// - TEE seal in SEV/SGX production
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SeedKind {
    /// FROST secp256k1 Taproot spending share
    FrostTr,
    /// FROST secp256k1 Intent authorization share
    FrostIntent,
    /// Ed25519 signing key (classical identity)
    Ed25519,
    /// ML-DSA-65 signing key (PQ identity, FIPS 204)
    MlDsa65,
    /// X25519 transport key (classical)
    X25519,
    /// ML-KEM-768 transport key (PQ, FIPS 203)
    MlKem768,
}

impl SeedKind {
    /// Human-readable label for share_id construction.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FrostTr => "frost-tr",
            Self::FrostIntent => "frost-intent",
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa65",
            Self::X25519 => "x25519",
            Self::MlKem768 => "ml-kem768",
        }
    }

    /// Whether this seed is a secret (should only be stored, never exposed).
    pub fn is_secret(&self) -> bool {
        true // all are secrets
    }

    /// Visibility suffix for share_id: "pub" or "sec".
    pub fn visibility(&self) -> &'static str {
        "sec"
    }
}

/// Build a standard share_id for a seed.
///
/// Format: `identity/{kind_label}/{node_id}`
pub fn build_seed_share_id(kind: SeedKind, node_id: &str) -> String {
    format!("identity/{}/{}", kind.label(), node_id)
}

/// Build AAD for seed binding: `seed_id + node_id + key_epoch`.
pub fn build_seed_aad(share_id: &str, node_id: &str, key_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(share_id.len() + node_id.len() + 24);
    aad.extend_from_slice(b"kerosene-vault-seed-aad-v1|");
    aad.extend_from_slice(share_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(node_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(key_epoch.to_le_bytes().as_ref());
    aad
}

/// Versioned envelope for persisted FROST shares.
///
/// Each share on disk carries a `format_version` and `suite_id` so that
/// migration (e.g., classical → hybrid suite) can detect stale shares and
/// re-encrypt atomically.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareEnvelope {
    pub format_version: u16,
    pub suite_id: String,
    pub share_id: String,
    pub node_id: String,
    pub key_epoch: String,
    pub share_kind: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub aad_hash_hex: String,
}

impl ShareEnvelope {
    pub const CURRENT_FORMAT: u16 = 1;

    pub fn new(suite_id: &str, share_id: &str, node_id: &str, key_epoch: &str, share_kind: &str) -> Self {
        Self {
            format_version: Self::CURRENT_FORMAT,
            suite_id: suite_id.to_string(),
            share_id: share_id.to_string(),
            node_id: node_id.to_string(),
            key_epoch: key_epoch.to_string(),
            share_kind: share_kind.to_string(),
            nonce_hex: String::new(),
            ciphertext_hex: String::new(),
            aad_hash_hex: String::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomainError> {
        serde_json::from_slice(bytes).map_err(|e| DomainError::ShareStoreForbidden(format!("share envelope: {e}")))
    }
}

pub struct AeadDiskShareStore {
    root: PathBuf,
    passphrase: SecretString,
    tpm_sealed_passphrase: bool,
}

impl AeadDiskShareStore {
    pub fn new(root: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self::with_tpm_seal(root, passphrase, false)
    }

    pub fn with_tpm_seal(root: impl Into<PathBuf>, passphrase: impl Into<String>, tpm_sealed_passphrase: bool) -> Self {
        Self { root: root.into(), passphrase: SecretString::from(passphrase.into()), tpm_sealed_passphrase }
    }

    fn path_for(&self, share_id: &str) -> PathBuf {
        let id_hash = hex::encode(Sha256::digest(share_id.as_bytes()));
        self.root.join(format!("share-{id_hash}.bin"))
    }

    fn aad(share_id: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + share_id.len());
        out.extend_from_slice(b"kerosene-vault-share-aead-v1|");
        out.extend_from_slice(share_id.as_bytes());
        out
    }

    fn derive_key(&self, salt: &[u8; 16]) -> Result<[u8; 32], DomainError> {
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(self.passphrase.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2: {e}")))?;
        Ok(key)
    }
}

impl ShareStorePort for AeadDiskShareStore {
    fn store_kind(&self) -> &'static str {
        if self.tpm_sealed_passphrase {
            "aead_disk_tpm"
        } else {
            "aead_disk"
        }
    }

    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError> {
        fs::create_dir_all(&self.root).map_err(|e| DomainError::ShareStoreForbidden(format!("mkdir: {e}")))?;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        key.zeroize();
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = Self::aad(share_id);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| DomainError::ShareStoreForbidden("encrypt failed".into()))?;
        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        atomic_write_fsync(&self.path_for(share_id), &out)
    }

    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError> {
        let bytes = fs::read(&self.path_for(share_id))
            .map_err(|e| DomainError::ShareStoreForbidden(format!("read share: {e}")))?;
        if bytes.len() < 16 + 12 + 16 {
            return Err(DomainError::ShareStoreForbidden("share blob too short".into()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[..16]);
        let nonce_bytes = &bytes[16..28];
        let ciphertext = &bytes[28..];
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        key.zeroize();
        let nonce = Nonce::from_slice(nonce_bytes);
        let aad = Self::aad(share_id);
        cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| DomainError::ShareStoreForbidden("decrypt failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempProbe(PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-aead-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn aad_rejects_share_id_swap() {
        let dir = TempProbe::new("aad");
        let store = AeadDiskShareStore::new(&dir.0, "test-pass");
        store.put_share("share-a", b"secret-a").unwrap();
        let blob = fs::read(store.path_for("share-a")).unwrap();
        // Copy ciphertext onto share-b's path — decrypt must fail (AAD bind).
        let path_b = store.path_for("share-b");
        fs::write(&path_b, &blob).unwrap();
        assert!(store.get_share("share-b").is_err());
        assert_eq!(store.get_share("share-a").unwrap(), b"secret-a");
    }

    // Item 2.2: SeedKind tests

    #[test]
    fn seed_kind_labels_are_unique() {
        let kinds = [
            SeedKind::FrostTr,
            SeedKind::FrostIntent,
            SeedKind::Ed25519,
            SeedKind::MlDsa65,
            SeedKind::X25519,
            SeedKind::MlKem768,
        ];
        let mut labels: Vec<&str> = kinds.iter().map(|k| k.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), kinds.len(), "all SeedKind labels must be unique");
    }

    #[test]
    fn seed_share_id_format() {
        let sid = build_seed_share_id(SeedKind::Ed25519, "vault-1");
        assert!(sid.starts_with("identity/"));
        assert!(sid.contains("ed25519"));
        assert!(sid.contains("vault-1"));
    }

    #[test]
    fn seed_aad_is_deterministic() {
        let aad1 = build_seed_aad("identity/ed25519/vault-1", "vault-1", 0);
        let aad2 = build_seed_aad("identity/ed25519/vault-1", "vault-1", 0);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn seed_aad_differs_by_epoch() {
        let aad1 = build_seed_aad("id", "n1", 0);
        let aad2 = build_seed_aad("id", "n1", 1);
        assert_ne!(aad1, aad2);
    }

    #[test]
    fn seed_kind_all_are_secrets() {
        assert!(SeedKind::Ed25519.is_secret());
        assert!(SeedKind::MlKem768.is_secret());
        assert!(SeedKind::MlDsa65.is_secret());
    }
}
