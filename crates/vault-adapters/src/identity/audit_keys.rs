//! Mesh **audit** key allowlist (F8).
//!
//! Audit signing keys must be disjoint from:
//! - **release** cosign / council materials
//! - **settlement** FROST shares / Intent signing path
//!
//! Full append-only audit pipeline is out of scope here — this module only
//! loads the allowlist and exposes membership / hygiene hooks used by ops
//! scripts (`scripts/gen_mesh_audit_keys.sh`, `scripts/verify_mesh_audit_sig.sh`).

use std::collections::BTreeSet;
use std::path::Path;

use crate::domain::DomainError;

/// Hex-encoded audit public keys permitted to sign mesh audit events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuditKeyAllowlist {
    pubkeys_hex: BTreeSet<String>,
}

impl MeshAuditKeyAllowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_hex_list<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut pubkeys_hex = BTreeSet::new();
        for k in keys {
            let t = k.as_ref().trim().to_ascii_lowercase();
            if !t.is_empty() {
                pubkeys_hex.insert(t);
            }
        }
        Self { pubkeys_hex }
    }

    /// Load from `VAULT_AUDIT_PUBKEY_ALLOWLIST` (csv) and/or `VAULT_AUDIT_PUBKEYS_PATH`
    /// (lines: `name hex` or bare `hex`).
    pub fn from_env() -> Result<Self, DomainError> {
        let mut keys = BTreeSet::new();
        if let Ok(csv) = std::env::var("VAULT_AUDIT_PUBKEY_ALLOWLIST") {
            for part in csv.split(',') {
                let t = part.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    keys.insert(t);
                }
            }
        }
        if let Ok(path) = std::env::var("VAULT_AUDIT_PUBKEYS_PATH") {
            if !path.is_empty() {
                Self::merge_file(&mut keys, Path::new(&path))?;
            }
        }
        Ok(Self { pubkeys_hex: keys })
    }

    fn merge_file(keys: &mut BTreeSet<String>, path: &Path) -> Result<(), DomainError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| DomainError::AuthRejected(format!("VAULT_AUDIT_PUBKEYS_PATH read {}: {e}", path.display())))?;
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let hex = line.split_whitespace().last().unwrap_or("").trim().to_ascii_lowercase();
            if !hex.is_empty() {
                keys.insert(hex);
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.pubkeys_hex.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pubkeys_hex.len()
    }

    pub fn contains(&self, pubkey_hex: &str) -> bool {
        self.pubkeys_hex.contains(&pubkey_hex.trim().to_ascii_lowercase())
    }

    /// Verify-hook: reject keys not on the mesh audit allowlist.
    pub fn require_allowlisted(&self, pubkey_hex: &str) -> Result<(), DomainError> {
        if self.is_empty() {
            return Err(DomainError::AuthRejected(
                "mesh audit pubkey allowlist empty (F8: set VAULT_AUDIT_PUBKEY_ALLOWLIST or VAULT_AUDIT_PUBKEYS_PATH)"
                    .into(),
            ));
        }
        if !self.contains(pubkey_hex) {
            return Err(DomainError::AuthRejected(format!(
                "pubkey not on mesh audit allowlist (audit keys ≠ release ≠ settlement): {pubkey_hex}"
            )));
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.pubkeys_hex.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_allowlisted_enforces_membership() {
        let al = MeshAuditKeyAllowlist::from_hex_list(["aabbcc", "ddeeff"]);
        assert!(al.require_allowlisted("AABBCC").is_ok());
        assert!(al.require_allowlisted("000000").is_err());
        assert!(MeshAuditKeyAllowlist::empty().require_allowlisted("aabbcc").is_err());
    }
}
