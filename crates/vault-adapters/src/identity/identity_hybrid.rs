//! Hybrid cryptographic identity for vault mesh nodes.
//!
//! Each vault generates Ed25519 (classical) + ML-DSA-65 (PQ) signing keys
//! and X25519 + ML-KEM-768 (KEM) transport keys at genesis. The roster
//! includes `PeerIdentity` for every seated vault. Wire messages are signed
//! with both keys (AND logic). mTLS certificate fingerprints are bound to
//! the Ed25519 public key for attestation binding.
//!
//! Delegates actual key operations to `vault_identity_core`.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use vault_identity_core::VaultIdentity;

use crate::application::ShareStorePort;
use crate::domain::{DomainError, NodeId};

/// Persisted hybrid identity for a vault node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridIdentity {
    pub node_id: NodeId,
    pub ed25519_public: [u8; 32],
    pub ed25519_secret: [u8; 32],
    pub ml_dsa65_public: Vec<u8>,
    pub ml_dsa65_secret: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
    pub ml_kem768_public: Vec<u8>,
    pub ml_kem768_secret: Vec<u8>,
    /// Unix epoch seconds when identity was created.
    pub created_at: u64,
    /// Unix epoch seconds when this identity expires (0 = never).
    pub expires_at: u64,
}

impl HybridIdentity {
    pub const ED25519_PUB_ID: &'static str = "identity-ed25519-pub";
    pub const ED25519_SEC_ID: &'static str = "identity-ed25519-sec";
    pub const ML_DSA65_PUB_ID: &'static str = "identity-ml-dsa65-pub";
    pub const ML_DSA65_SEC_ID: &'static str = "identity-ml-dsa65-sec";
    pub const X25519_PUB_ID: &'static str = "identity-x25519-pub";
    pub const X25519_SEC_ID: &'static str = "identity-x25519-sec";
    pub const ML_KEM768_PUB_ID: &'static str = "identity-ml-kem768-pub";
    pub const ML_KEM768_SEC_ID: &'static str = "identity-ml-kem768-sec";

    /// Generate a fresh hybrid identity for a vault at genesis.
    ///
    /// Uses `vault_identity_core` for the Ed25519 and ML-DSA-65 key material.
    /// Transport keys (X25519, ML-KEM-768) are generated here directly.
    pub fn genesis(node_id: NodeId) -> Result<Self, DomainError> {
        let mut rng = OsRng;
        use rand::RngCore;

        // Ed25519 signing key (classical) via vault-identity-core.
        let ed_id = vault_identity_core::ed25519_identity::Ed25519Identity::generate()
            .map_err(|e| DomainError::ThresholdError(format!("ed25519 genesis: {e}")))?;
        let ed_public_bytes = *ed_id.public_key();
        let ed_secret_bytes = *ed_id.secret_key();

        // ML-DSA-65 signing key (PQ) via vault-identity-core.
        let ml_id = vault_identity_core::ml_dsa_identity::MlDsa65Identity::generate()
            .map_err(|e| DomainError::ThresholdError(format!("ml-dsa65 genesis: {e}")))?;
        let ml_pub_bytes = ml_id.public_key().clone();
        let ml_sec_bytes = ml_id.secret_key().clone();

        // X25519 transport key (classical) — raw random bytes.
        let mut x_sec_bytes = [0u8; 32];
        rng.fill_bytes(&mut x_sec_bytes);
        let x_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let x_public = x25519_dalek::PublicKey::from(&x_secret);
        let x_pub_bytes: [u8; 32] = *x_public.as_bytes();

        // ML-KEM-768 transport key (PQ). Uses placeholder; TODO: wire full ml-kem crate API.
        let mut ml_kem_pub_bytes = vec![0u8; 1184];
        let mut ml_kem_sec_bytes = vec![0u8; 2400];
        rng.fill_bytes(&mut ml_kem_pub_bytes);
        rng.fill_bytes(&mut ml_kem_sec_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DomainError::ThresholdError(format!("system clock: {e}")))
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            node_id,
            ed25519_public: ed_public_bytes,
            ed25519_secret: ed_secret_bytes,
            ml_dsa65_public: ml_pub_bytes,
            ml_dsa65_secret: ml_sec_bytes,
            x25519_public: x_pub_bytes,
            x25519_secret: x_sec_bytes,
            ml_kem768_public: ml_kem_pub_bytes,
            ml_kem768_secret: ml_kem_sec_bytes,
            created_at: now,
            expires_at: 0,
        })
    }

    /// Returns the peer identity (public keys only) for inclusion in the roster.
    pub fn to_peer_identity(&self) -> crate::domain::PeerIdentity {
        crate::domain::PeerIdentity {
            node_id: self.node_id.clone(),
            ed25519_public: self.ed25519_public,
            ml_dsa65_public: self.ml_dsa65_public.clone(),
            x25519_public: self.x25519_public,
            ml_kem768_public: self.ml_kem768_public.clone(),
            created_at: self.created_at,
        }
    }

    // -----------------------------------------------------------------------
    // Seed persistence via ShareStorePort
    // -----------------------------------------------------------------------

    /// Build the share_id for a specific seed.
    fn seed_share_id(node_id: &str, label: &str) -> String {
        format!("identity/{label}/{node_id}")
    }

    /// Build AAD for seed anti-swap binding.
    fn seed_aad(share_id: &str, node_id: &str, key_epoch: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(share_id.len() + node_id.len() + 24);
        aad.extend_from_slice(b"kerosene-vault-seed-aad-v1|");
        aad.extend_from_slice(share_id.as_bytes());
        aad.push(b'|');
        aad.extend_from_slice(node_id.as_bytes());
        aad.push(b'|');
        aad.extend_from_slice(key_epoch.to_le_bytes().as_ref());
        aad
    }

    /// Persist all secret and public key material to a ShareStorePort.
    pub fn persist_seeds(&self, store: &dyn ShareStorePort, key_epoch: u64) -> Result<(), DomainError> {
        let nid = self.node_id.as_str();
        let secrets: &[(&str, &[u8])] = &[
            ("ed25519", &self.ed25519_secret),
            ("ml-dsa65", &self.ml_dsa65_secret),
            ("x25519", &self.x25519_secret),
            ("ml-kem768", &self.ml_kem768_secret),
        ];
        for (label, data) in secrets {
            let sid = Self::seed_share_id(nid, label);
            store.put_share(&sid, data)?;
        }
        let publics: &[(&str, &[u8])] = &[("ed25519-pub", &self.ed25519_public), ("x25519-pub", &self.x25519_public)];
        for (label, data) in publics {
            let sid = Self::seed_share_id(nid, label);
            store.put_share(&sid, data)?;
        }
        Ok(())
    }

    /// Load secret key material from a ShareStorePort during boot.
    pub fn load_seeds(
        node_id: NodeId,
        store: &dyn ShareStorePort,
        key_epoch: u64,
    ) -> Result<Option<Self>, DomainError> {
        let nid = node_id.as_str();
        let ed25519_secret = match Self::load_seed(store, nid, "ed25519", key_epoch) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let ml_dsa65_secret = match Self::load_seed(store, nid, "ml-dsa65", key_epoch) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let x25519_secret = match Self::load_seed(store, nid, "x25519", key_epoch) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let ml_kem768_secret = match Self::load_seed(store, nid, "ml-kem768", key_epoch) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let ed25519_public: [u8; 32] = match Self::load_seed(store, nid, "ed25519-pub", key_epoch) {
            Ok(Some(v)) => {
                v[..32].try_into().map_err(|_| DomainError::ShareStoreForbidden("ed25519 pub wrong length".into()))?
            }
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let x25519_public: [u8; 32] = match Self::load_seed(store, nid, "x25519-pub", key_epoch) {
            Ok(Some(v)) => {
                v[..32].try_into().map_err(|_| DomainError::ShareStoreForbidden("x25519 pub wrong length".into()))?
            }
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let ed25519_secret_arr: [u8; 32] = ed25519_secret[..32]
            .try_into()
            .map_err(|_| DomainError::ShareStoreForbidden("ed25519 seed wrong length".into()))?;
        let x25519_secret_arr: [u8; 32] = x25519_secret[..32]
            .try_into()
            .map_err(|_| DomainError::ShareStoreForbidden("x25519 seed wrong length".into()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DomainError::ThresholdError(format!("system clock: {e}")))
            .unwrap_or_default()
            .as_secs();

        Ok(Some(Self {
            node_id,
            ed25519_public,
            ed25519_secret: ed25519_secret_arr,
            ml_dsa65_public: vec![],
            ml_dsa65_secret,
            x25519_public,
            x25519_secret: x25519_secret_arr,
            ml_kem768_public: vec![],
            ml_kem768_secret,
            created_at: now,
            expires_at: 0,
        }))
    }

    /// Load a single seed blob from the store.
    fn load_seed(
        store: &dyn ShareStorePort,
        node_id: &str,
        label: &str,
        key_epoch: u64,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        let sid = Self::seed_share_id(node_id, label);
        match store.get_share(&sid) {
            Ok(data) => {
                let min_len = match label {
                    "ed25519" | "x25519" => 32,
                    "ml-dsa65" => 4032,
                    "ml-kem768" => 2400,
                    _ => 1,
                };
                if data.len() < min_len {
                    return Err(DomainError::ShareStoreForbidden(format!(
                        "loaded seed {label} is too short: {} < {min_len}",
                        data.len()
                    )));
                }
                Ok(Some(data))
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("TeeRequired") || msg.contains("TpmRequired") {
                    Err(e)
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::AeadDiskShareStore;
    use std::fs;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("kv-hybrid-{name}-{}", std::process::id()));
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
    fn genesis_generates_all_key_types() {
        let id = HybridIdentity::genesis(NodeId::new("test-vault-1").unwrap()).unwrap();
        assert_eq!(id.node_id.as_str(), "test-vault-1");
        assert_ne!(id.ed25519_public, [0u8; 32]);
        assert_ne!(id.ed25519_secret, [0u8; 32]);
        assert!(!id.ml_dsa65_public.is_empty());
        assert!(!id.ml_dsa65_secret.is_empty());
        assert_ne!(id.x25519_public, [0u8; 32]);
        assert_ne!(id.x25519_secret, [0u8; 32]);
        assert!(!id.ml_kem768_public.is_empty());
        assert!(!id.ml_kem768_secret.is_empty());
        assert!(id.created_at > 0);
        assert_eq!(id.expires_at, 0);
    }

    #[test]
    fn peer_identity_contains_public_keys_only() {
        let id = HybridIdentity::genesis(NodeId::new("vault-1").unwrap()).unwrap();
        let peer = id.to_peer_identity();
        assert_eq!(peer.node_id, id.node_id);
        assert_eq!(peer.ed25519_public, id.ed25519_public);
        assert_eq!(peer.ml_dsa65_public, id.ml_dsa65_public);
        assert_eq!(peer.x25519_public, id.x25519_public);
        assert_eq!(peer.ml_kem768_public, id.ml_kem768_public);
    }

    #[test]
    fn persist_and_load_seeds_roundtrip() {
        let tmp = TempDir::new("persist");
        let store = AeadDiskShareStore::new(&tmp.0, "test-pass");
        let id = HybridIdentity::genesis(NodeId::new("vault-1").unwrap()).unwrap();
        let nid = id.node_id.clone();
        id.persist_seeds(&store, 0).expect("persist");
        let loaded = HybridIdentity::load_seeds(nid, &store, 0).expect("load").expect("seeds present");
        assert_eq!(loaded.ed25519_secret, id.ed25519_secret);
        assert_eq!(loaded.ed25519_public, id.ed25519_public);
        assert_eq!(loaded.x25519_secret, id.x25519_secret);
        assert_eq!(loaded.x25519_public, id.x25519_public);
    }

    #[test]
    fn load_seeds_returns_none_when_missing() {
        let tmp = TempDir::new("missing");
        let store = AeadDiskShareStore::new(&tmp.0, "test-pass");
        let result = HybridIdentity::load_seeds(NodeId::new("nonexistent").unwrap(), &store, 0);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn seed_share_id_is_unique_per_label() {
        let id1 = HybridIdentity::seed_share_id("vault-1", "ed25519");
        let id2 = HybridIdentity::seed_share_id("vault-1", "ml-dsa65");
        assert_ne!(id1, id2);
    }

    #[test]
    fn persist_seeds_stores_all_four_key_types() {
        let tmp = TempDir::new("all");
        let store = AeadDiskShareStore::new(&tmp.0, "test-pass");
        let id = HybridIdentity::genesis(NodeId::new("vault-1").unwrap()).unwrap();
        id.persist_seeds(&store, 0).expect("persist");
        let keys = ["ed25519", "ml-dsa65", "x25519", "ml-kem768"];
        for label in &keys {
            let sid = HybridIdentity::seed_share_id("vault-1", label);
            let data = store.get_share(&sid).expect("get_share");
            assert!(!data.is_empty(), "seed {label} is empty");
        }
    }
}
