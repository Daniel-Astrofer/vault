//! Approval of exact Git archive bytes is independent of release/custody approval.

use crate::{validate_release_id, ContentHash};
use serde::{Deserialize, Serialize};

pub const GIT_BUNDLE_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitArchiveError {
    Invalid,
    NotFound,
    ApprovalRequired,
    Conflict,
    Corrupt,
    Unavailable,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitArchiveApprovalV2 {
    pub archive_version: u16,
    pub release_id: String,
    /// Operator-approved repository label, not an origin URL discovered from a pack.
    pub repository_id: String,
    pub commit: String,
    pub object_format: String,
    pub bundle_sha256: String,
    pub retention_pinned: bool,
}

impl GitArchiveApprovalV2 {
    pub fn validate(&self) -> Result<(), GitArchiveError> {
        validate_release_id(&self.release_id).map_err(|_| GitArchiveError::Invalid)?;
        validate_release_id(&self.repository_id).map_err(|_| GitArchiveError::Invalid)?;
        let oid_len = match self.object_format.as_str() {
            "sha1" => 40,
            "sha256" => 64,
            _ => return Err(GitArchiveError::Invalid),
        };
        if self.archive_version != 2
            || !self.retention_pinned
            || self.commit.len() != oid_len
            || !self.commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.commit.bytes().all(|b| b == b'0')
            || ContentHash::parse(&self.bundle_sha256).map_err(|_| GitArchiveError::Invalid)?.as_str()
                != self.bundle_sha256
        {
            return Err(GitArchiveError::Invalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitBundleVerificationV2 {
    pub commit_count: u64,
    pub bundle_version: u16,
    pub git_executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitArchiveReceiptV2 {
    pub approval: GitArchiveApprovalV2,
    pub verified_at_secs: u64,
    pub byte_length: u64,
    pub verification: GitBundleVerificationV2,
}

#[cfg(test)]
mod git_archive_tests {
    use super::*;

    fn approval() -> GitArchiveApprovalV2 {
        GitArchiveApprovalV2 {
            archive_version: 2,
            release_id: "cell-r1".into(),
            repository_id: "core".into(),
            commit: "a".repeat(40),
            object_format: "sha1".into(),
            bundle_sha256: ContentHash::from_bytes(b"bundle").as_str().into(),
            retention_pinned: true,
        }
    }

    #[test]
    fn git_archive_requires_pinned_canonical_identity() {
        let valid = approval();
        valid.validate().unwrap();
        for changed in [
            GitArchiveApprovalV2 { retention_pinned: false, ..valid.clone() },
            GitArchiveApprovalV2 { repository_id: "../core".into(), ..valid.clone() },
            GitArchiveApprovalV2 { commit: "0".repeat(40), ..valid.clone() },
            GitArchiveApprovalV2 { commit: "A".repeat(40), ..valid.clone() },
            GitArchiveApprovalV2 { object_format: "sha256".into(), ..valid.clone() },
            GitArchiveApprovalV2 { archive_version: 1, ..valid.clone() },
        ] {
            assert_eq!(changed.validate(), Err(GitArchiveError::Invalid));
        }
    }

    #[test]
    fn git_archive_refuses_unknown_approval_fields() {
        let mut json = serde_json::to_value(approval()).unwrap();
        json["acceptedRelease"] = true.into();
        assert!(serde_json::from_value::<GitArchiveApprovalV2>(json).is_err());
    }
}
