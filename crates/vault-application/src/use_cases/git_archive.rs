use crate::ports::{ClockPort, GitArchiveStorePort, GitBundleVerifierPort};
use std::sync::Arc;
use vault_domain::{ContentHash, GitArchiveError, GitArchiveReceiptV2, GIT_BUNDLE_MAX_BYTES};

pub struct IngestGitArchive {
    store: Arc<dyn GitArchiveStorePort>,
    verifier: Arc<dyn GitBundleVerifierPort>,
    clock: Arc<dyn ClockPort>,
}

impl IngestGitArchive {
    pub fn new(
        store: Arc<dyn GitArchiveStorePort>,
        verifier: Arc<dyn GitBundleVerifierPort>,
        clock: Arc<dyn ClockPort>,
    ) -> Self {
        Self { store, verifier, clock }
    }

    pub fn execute(
        &self,
        release_id: &str,
        repository_id: &str,
        bytes: &[u8],
    ) -> Result<GitArchiveReceiptV2, GitArchiveError> {
        let approval = self.store.git_archive_approval(release_id, repository_id)?;
        approval.validate()?;
        if bytes.is_empty() || bytes.len() > GIT_BUNDLE_MAX_BYTES {
            return Err(GitArchiveError::Invalid);
        }
        if ContentHash::from_bytes(bytes).as_str() != approval.bundle_sha256 {
            return Err(GitArchiveError::Conflict);
        }
        // Corrupt existing evidence is never silently replaced; mirrors can retry
        // reads or use another independently pinned release ID after inspection.
        match self.store.get_git_archive(release_id, repository_id) {
            Ok((receipt, existing)) => {
                return if existing == bytes { Ok(receipt) } else { Err(GitArchiveError::Conflict) }
            }
            Err(GitArchiveError::NotFound) => (),
            Err(err) => return Err(err),
        }
        let verified_at_secs = self.clock.unix_now_secs();
        if verified_at_secs == 0 {
            return Err(GitArchiveError::Unavailable);
        }
        let verification = self.verifier.verify(&approval, bytes)?;
        self.store.put_git_archive(
            GitArchiveReceiptV2 { approval, verified_at_secs, byte_length: bytes.len() as u64, verification },
            bytes,
        )
    }
}
