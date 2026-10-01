//! Versioned inert source bundle. No filesystem interpretation or build execution.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ContentHash, DomainError};

pub const SOURCE_BUNDLE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const SOURCE_BUNDLE_MAX_CONTENT_BYTES: usize = 2 * 1024 * 1024;
pub const SOURCE_BUNDLE_MAX_FILES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFileV1 {
    pub path: String,
    pub content_hex: String,
}

/// A flat archive of regular file bytes; links, modes and archive extensions
/// cannot be represented. The production/features fields are untrusted claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBundleV1 {
    pub format_version: u16,
    pub release_id: String,
    pub target_sequence: u64,
    pub protocol_version: u16,
    pub storage_version: u16,
    pub production: bool,
    pub features: BTreeSet<String>,
    pub files: Vec<SourceFileV1>,
}

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidRelease(message.into())
}

pub fn validate_release_id(id: &str) -> Result<(), DomainError> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)) {
        return Err(invalid("releaseId must be 1..128 ASCII letters, digits, hyphens or underscores"));
    }
    Ok(())
}

impl SourceBundleV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        if bytes.len() > SOURCE_BUNDLE_MAX_BYTES {
            return Err(invalid("source bundle exceeds byte limit"));
        }
        let mut bundle: Self = serde_json::from_slice(bytes).map_err(|_| invalid("invalid source bundle v1"))?;
        bundle.validate_and_normalize()?;
        Ok(bundle)
    }

    pub fn validate_and_normalize(&mut self) -> Result<(), DomainError> {
        validate_release_id(&self.release_id)?;
        if self.format_version != 1 || self.target_sequence == 0 {
            return Err(invalid("unsupported bundle format or zero targetSequence"));
        }
        if self.features.len() > 32 || self.features.iter().any(|f| f.len() > 64 || f.is_empty()) {
            return Err(invalid("invalid feature claims"));
        }
        if self.files.is_empty() || self.files.len() > SOURCE_BUNDLE_MAX_FILES {
            return Err(invalid("source bundle must contain 1..256 regular files"));
        }
        let mut total = 0usize;
        for file in &mut self.files {
            if file.path.len() > 240
                || file.path.split('/').any(|p| p.is_empty() || p == "." || p == ".." || p.eq_ignore_ascii_case(".git"))
                || !file.path.bytes().all(|c| c.is_ascii_alphanumeric() || b"/_-.".contains(&c))
            {
                return Err(invalid("unsafe source path"));
            }
            if file.content_hex.len() > 2 * 256 * 1024 {
                return Err(invalid("source file exceeds 256 KiB"));
            }
            let decoded = hex::decode(&file.content_hex).map_err(|_| invalid("invalid file contentHex"))?;
            total += decoded.len();
            if total > SOURCE_BUNDLE_MAX_CONTENT_BYTES {
                return Err(invalid("source content exceeds 2 MiB"));
            }
            file.content_hex = hex::encode(decoded);
        }
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        if self.files.windows(2).any(|w| w[0].path == w[1].path)
            || self.files.iter().any(|file| {
                file.path
                    .match_indices('/')
                    .any(|(i, _)| self.files.binary_search_by(|f| f.path.as_str().cmp(&file.path[..i])).is_ok())
            })
        {
            return Err(invalid("duplicate or conflicting source paths"));
        }
        Ok(())
    }

    /// Canonical v1 bytes: struct field order, sorted features/files, lowercase hex.
    /// Domain prefix prevents confusing this digest with legacy Hs/Hb artifacts.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DomainError> {
        let mut normalized = self.clone();
        normalized.validate_and_normalize()?;
        let mut bytes = b"vault-source-bundle-v1\n".to_vec();
        bytes.extend(serde_json::to_vec(&normalized).map_err(|_| invalid("bundle serialization failed"))?);
        if bytes.len() > SOURCE_BUNDLE_MAX_BYTES {
            return Err(invalid("canonical source bundle exceeds byte limit"));
        }
        Ok(bytes)
    }

    pub fn canonical_digest(&self) -> Result<ContentHash, DomainError> {
        Ok(ContentHash::from_bytes(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceArchiveReceiptV1 {
    pub format_version: u16,
    pub release_id: String,
    pub canonical_digest: String,
    pub target_sequence: u64,
    pub archived_at_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn bundle() -> SourceBundleV1 {
        SourceBundleV1 {
            format_version: 1,
            release_id: "r1".into(),
            target_sequence: 1,
            protocol_version: 1,
            storage_version: 1,
            production: true,
            features: BTreeSet::from(["production".into()]),
            files: vec![SourceFileV1 { path: "src/lib.rs".into(), content_hex: "6162".into() }],
        }
    }

    #[test]
    fn digest_binds_release_sequence_versions_and_content() {
        let original = bundle();
        let digest = original.canonical_digest().unwrap();
        for change in 0..5 {
            let mut other = original.clone();
            match change {
                0 => other.release_id = "r2".into(),
                1 => other.target_sequence = 2,
                2 => other.protocol_version = 2,
                3 => other.storage_version = 2,
                _ => other.files[0].content_hex = "63".into(),
            }
            assert_ne!(digest, other.canonical_digest().unwrap());
        }
    }

    #[test]
    fn rejects_paths_links_duplicates_and_bounds() {
        for path in ["../escape", "/absolute", "a/../b", "a\\b", "C:/x", "a//b", ".git/config", "a/./b", "a\0b"] {
            let mut b = bundle();
            b.files[0].path = path.into();
            assert!(b.canonical_bytes().is_err(), "{path}");
        }
        let mut b = bundle();
        b.files.push(b.files[0].clone());
        assert!(b.canonical_bytes().is_err());
        let mut b = bundle();
        b.files.push(SourceFileV1 { path: "src".into(), content_hex: "".into() });
        assert!(b.canonical_bytes().is_err());
        let mut json = serde_json::to_value(bundle()).unwrap();
        json["files"][0]["linkTarget"] = "../../secret".into();
        assert!(SourceBundleV1::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        assert!(SourceBundleV1::parse(&vec![b' '; SOURCE_BUNDLE_MAX_BYTES + 1]).is_err());
        let mut b = bundle();
        b.files[0].content_hex = "00".repeat(256 * 1024 + 1);
        assert!(b.canonical_bytes().is_err());
        let mut b = bundle();
        b.files = vec![b.files[0].clone(); 257];
        assert!(b.canonical_bytes().is_err());
    }

    #[test]
    fn canonicalization_ignores_json_and_file_order() {
        let mut a = bundle();
        a.files.push(SourceFileV1 { path: "a".into(), content_hex: "AB".into() });
        let mut b = a.clone();
        b.files.reverse();
        b.files[0].content_hex = "ab".into();
        assert_eq!(a.canonical_digest().unwrap(), b.canonical_digest().unwrap());
    }
}
