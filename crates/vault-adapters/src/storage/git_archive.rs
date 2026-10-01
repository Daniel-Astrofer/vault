//! Permanently pinned original Git bundle bytes. No GC, deletion or replacement.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use super::source_archive::{put_immutable, read_bounded_regular, reject_link_components};
use crate::application::GitArchiveStorePort;
use crate::domain::{
    validate_release_id, ContentHash, GitArchiveApprovalV2, GitArchiveError, GitArchiveReceiptV2, GIT_BUNDLE_MAX_BYTES,
};

pub struct PersistedGitArchives {
    root: PathBuf,
    writes: Mutex<()>,
}

impl PersistedGitArchives {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, GitArchiveError> {
        let root = root.into();
        for dir in ["approvals", "receipts", "bundles"] {
            let path = root.join(dir);
            reject_link_components(&path).map_err(|_| GitArchiveError::Unavailable)?;
            fs::create_dir_all(path).map_err(|_| GitArchiveError::Unavailable)?;
        }
        Ok(Self { root, writes: Mutex::new(()) })
    }

    fn record_path(&self, dir: &str, release_id: &str, repository_id: &str) -> Result<PathBuf, GitArchiveError> {
        validate_release_id(release_id).map_err(|_| GitArchiveError::Invalid)?;
        validate_release_id(repository_id).map_err(|_| GitArchiveError::Invalid)?;
        // Canonical tuple prevents ambiguous release/repository concatenations.
        let identity = serde_json::to_vec(&(release_id, repository_id)).map_err(|_| GitArchiveError::Invalid)?;
        Ok(self.root.join(dir).join(ContentHash::from_bytes(&identity).as_str()))
    }

    fn existing_record(&self, dir: &str, release_id: &str, repository_id: &str) -> Result<Vec<u8>, GitArchiveError> {
        let path = self.record_path(dir, release_id, repository_id)?;
        reject_link_components(&path).map_err(|_| GitArchiveError::Corrupt)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(GitArchiveError::NotFound),
            Err(_) => return Err(GitArchiveError::Unavailable),
            Ok(_) => (),
        }
        read_bounded_regular(&path, 8192).map_err(|_| GitArchiveError::Corrupt)
    }
}

impl GitArchiveStorePort for PersistedGitArchives {
    fn approve_git_archive(&self, approval: GitArchiveApprovalV2) -> Result<(), GitArchiveError> {
        approval.validate()?;
        let _guard = self.writes.lock().map_err(|_| GitArchiveError::Unavailable)?;
        match self.git_archive_approval(&approval.release_id, &approval.repository_id) {
            Ok(old) => return if old == approval { Ok(()) } else { Err(GitArchiveError::Conflict) },
            Err(GitArchiveError::ApprovalRequired) => (),
            Err(err) => return Err(err),
        }
        let path = self.record_path("approvals", &approval.release_id, &approval.repository_id)?;
        let bytes = serde_json::to_vec(&approval).map_err(|_| GitArchiveError::Invalid)?;
        put_immutable(&path, &bytes, 8192).map_err(|_| GitArchiveError::Unavailable)
    }

    fn git_archive_approval(
        &self,
        release_id: &str,
        repository_id: &str,
    ) -> Result<GitArchiveApprovalV2, GitArchiveError> {
        let bytes = self.existing_record("approvals", release_id, repository_id).map_err(|e| {
            if e == GitArchiveError::NotFound {
                GitArchiveError::ApprovalRequired
            } else {
                e
            }
        })?;
        let approval: GitArchiveApprovalV2 = serde_json::from_slice(&bytes).map_err(|_| GitArchiveError::Corrupt)?;
        approval.validate().map_err(|_| GitArchiveError::Corrupt)?;
        if approval.release_id != release_id || approval.repository_id != repository_id {
            return Err(GitArchiveError::Corrupt);
        }
        Ok(approval)
    }

    fn put_git_archive(
        &self,
        receipt: GitArchiveReceiptV2,
        bytes: &[u8],
    ) -> Result<GitArchiveReceiptV2, GitArchiveError> {
        receipt.approval.validate()?;
        if bytes.is_empty()
            || bytes.len() > GIT_BUNDLE_MAX_BYTES
            || receipt.byte_length != bytes.len() as u64
            || receipt.verified_at_secs == 0
            || receipt.verification.commit_count == 0
            || ![2, 3].contains(&receipt.verification.bundle_version)
            || ContentHash::parse(&receipt.verification.git_executable_sha256).is_err()
            || ContentHash::from_bytes(bytes).as_str() != receipt.approval.bundle_sha256
        {
            return Err(GitArchiveError::Invalid);
        }
        let _guard = self.writes.lock().map_err(|_| GitArchiveError::Unavailable)?;
        if self.git_archive_approval(&receipt.approval.release_id, &receipt.approval.repository_id)? != receipt.approval
        {
            return Err(GitArchiveError::Conflict);
        }
        match self.get_git_archive(&receipt.approval.release_id, &receipt.approval.repository_id) {
            Ok((old, raw)) => {
                return if old.approval == receipt.approval && raw == bytes {
                    Ok(old)
                } else {
                    Err(GitArchiveError::Conflict)
                }
            }
            Err(GitArchiveError::NotFound) => (),
            Err(err) => return Err(err),
        }
        put_immutable(&self.root.join("bundles").join(&receipt.approval.bundle_sha256), bytes, GIT_BUNDLE_MAX_BYTES)
            .map_err(|_| GitArchiveError::Unavailable)?;
        let path = self.record_path("receipts", &receipt.approval.release_id, &receipt.approval.repository_id)?;
        put_immutable(&path, &serde_json::to_vec(&receipt).map_err(|_| GitArchiveError::Invalid)?, 8192)
            .map_err(|_| GitArchiveError::Unavailable)?;
        Ok(receipt)
    }

    fn get_git_archive(
        &self,
        release_id: &str,
        repository_id: &str,
    ) -> Result<(GitArchiveReceiptV2, Vec<u8>), GitArchiveError> {
        let receipt: GitArchiveReceiptV2 =
            serde_json::from_slice(&self.existing_record("receipts", release_id, repository_id)?)
                .map_err(|_| GitArchiveError::Corrupt)?;
        if self.git_archive_approval(release_id, repository_id).map_err(|_| GitArchiveError::Corrupt)?
            != receipt.approval
            || receipt.verified_at_secs == 0
            || receipt.verification.commit_count == 0
            || ![2, 3].contains(&receipt.verification.bundle_version)
            || ContentHash::parse(&receipt.verification.git_executable_sha256).is_err()
        {
            return Err(GitArchiveError::Corrupt);
        }
        let bytes = read_bounded_regular(
            &self.root.join("bundles").join(&receipt.approval.bundle_sha256),
            GIT_BUNDLE_MAX_BYTES,
        )
        .map_err(|_| GitArchiveError::Corrupt)?;
        if bytes.len() as u64 != receipt.byte_length
            || ContentHash::from_bytes(&bytes).as_str() != receipt.approval.bundle_sha256
        {
            return Err(GitArchiveError::Corrupt);
        }
        Ok((receipt, bytes))
    }
}

#[cfg(test)]
mod git_archive_tests {
    use super::*;
    use crate::domain::GitBundleVerificationV2;
    use std::os::unix::fs::PermissionsExt;

    fn receipt(repository_id: &str, bytes: &[u8]) -> GitArchiveReceiptV2 {
        GitArchiveReceiptV2 {
            approval: GitArchiveApprovalV2 {
                archive_version: 2,
                release_id: "r1".into(),
                repository_id: repository_id.into(),
                commit: "a".repeat(40),
                object_format: "sha1".into(),
                bundle_sha256: ContentHash::from_bytes(bytes).as_str().into(),
                retention_pinned: true,
            },
            verified_at_secs: 100,
            byte_length: bytes.len() as u64,
            verification: GitBundleVerificationV2 {
                commit_count: 2,
                bundle_version: 2,
                git_executable_sha256: ContentHash::from_bytes(b"git").as_str().into(),
            },
        }
    }

    #[test]
    fn git_archive_multiple_repositories_survive_restart_and_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistedGitArchives::open(dir.path()).unwrap();
        for repo in ["core", "kfe", "node", "vault", "admin", "clients", "contracts", "shared", "web-page", "deploy"] {
            let raw = repo.as_bytes();
            let original = receipt(repo, raw);
            assert_eq!(store.put_git_archive(original.clone(), raw), Err(GitArchiveError::ApprovalRequired));
            store.approve_git_archive(original.approval.clone()).unwrap();
            store.put_git_archive(original.clone(), raw).unwrap();
            let mut retry = original.clone();
            retry.verified_at_secs += 1;
            assert_eq!(store.put_git_archive(retry, raw).unwrap(), original);
            let mut other = original.approval;
            other.commit = "b".repeat(40);
            assert_eq!(store.approve_git_archive(other), Err(GitArchiveError::Conflict));
        }
        drop(store);
        let reopened = PersistedGitArchives::open(dir.path()).unwrap();
        assert_eq!(reopened.get_git_archive("r1", "core").unwrap().1, b"core");
        assert_eq!(reopened.get_git_archive("r1", "vault").unwrap().1, b"vault");
        assert_eq!(reopened.get_git_archive("r1", "absent"), Err(GitArchiveError::NotFound));
    }

    #[test]
    fn git_archive_reads_rehash_blobs_and_reject_linked_storage() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistedGitArchives::open(dir.path()).unwrap();
        let original = receipt("core", b"original");
        store.approve_git_archive(original.approval.clone()).unwrap();
        store.put_git_archive(original.clone(), b"original").unwrap();
        let path = dir.path().join("bundles").join(&original.approval.bundle_sha256);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"tampered").unwrap();
        assert_eq!(store.get_git_archive("r1", "core"), Err(GitArchiveError::Corrupt));
        assert_eq!(store.put_git_archive(original, b"original"), Err(GitArchiveError::Corrupt));
        let parent = tempfile::tempdir().unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(PersistedGitArchives::open(link).is_err());
    }

    #[test]
    fn git_archive_tuple_identity_is_unambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistedGitArchives::open(dir.path()).unwrap();
        assert_ne!(
            store.record_path("approvals", "a-b", "c").unwrap(),
            store.record_path("approvals", "a", "b-c").unwrap()
        );
        assert_eq!(store.git_archive_approval("../r1", "core"), Err(GitArchiveError::Invalid));
    }
}
