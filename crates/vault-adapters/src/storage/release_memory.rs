//! Lab content-addressed blob + release/allowlist store.
//!
//! # Persistence honesty (#18)
//! Entirely in-memory. Restart loses candidates / blobs / allowlist.
//! Residual until durable release mesh storage lands — do not claim durability.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use super::sync_util::lock_mutex;
use crate::application::ports::{BlobStorePort, ReleaseStorePort};
use crate::domain::{AllowlistEntry, ContentHash, DomainError, ReleaseCandidate, ReleasePolicy};

pub struct InMemoryReleaseMesh {
    pub(crate) inner: Mutex<ReleaseMeshState>,
}

pub(crate) struct ReleaseMeshState {
    pub(crate) policy: ReleasePolicy,
    pub(crate) blobs: HashMap<String, Vec<u8>>,
    pub(crate) candidates: BTreeMap<String, ReleaseCandidate>,
    pub(crate) allowlist: Vec<AllowlistEntry>,
}

impl InMemoryReleaseMesh {
    pub fn new(policy: ReleasePolicy) -> Self {
        Self {
            inner: Mutex::new(ReleaseMeshState {
                policy,
                blobs: HashMap::new(),
                candidates: BTreeMap::new(),
                allowlist: Vec::new(),
            }),
        }
    }
}

impl BlobStorePort for InMemoryReleaseMesh {
    fn put(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError> {
        let mut g = lock_mutex(&self.inner, "release")?;
        g.blobs.insert(hash.as_str().to_string(), bytes.to_vec());
        Ok(())
    }

    fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, DomainError> {
        let g = lock_mutex(&self.inner, "release")?;
        g.blobs.get(hash.as_str()).cloned().ok_or_else(|| DomainError::UnknownBlob(hash.as_str().to_string()))
    }
}

impl ReleaseStorePort for InMemoryReleaseMesh {
    fn policy(&self) -> Result<ReleasePolicy, DomainError> {
        Ok(lock_mutex(&self.inner, "release")?.policy.clone())
    }

    fn put_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        let mut g = lock_mutex(&self.inner, "release")?;
        if g.candidates.contains_key(&candidate.id) {
            return Err(DomainError::InvalidRelease(format!("release already exists: {}", candidate.id)));
        }
        g.candidates.insert(candidate.id.clone(), candidate);
        Ok(())
    }

    fn get_candidate(&self, id: &str) -> Result<ReleaseCandidate, DomainError> {
        let g = lock_mutex(&self.inner, "release")?;
        g.candidates.get(id).cloned().ok_or_else(|| DomainError::UnknownRelease(id.to_string()))
    }

    fn save_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        let mut g = lock_mutex(&self.inner, "release")?;
        if !g.candidates.contains_key(&candidate.id) {
            return Err(DomainError::UnknownRelease(candidate.id));
        }
        g.candidates.insert(candidate.id.clone(), candidate);
        Ok(())
    }

    fn put_allowlist(&self, entry: AllowlistEntry) -> Result<(), DomainError> {
        let mut g = lock_mutex(&self.inner, "release")?;
        g.allowlist.retain(|e| e.release_id != entry.release_id);
        g.allowlist.push(entry);
        Ok(())
    }

    fn allowlist(&self) -> Result<Vec<AllowlistEntry>, DomainError> {
        Ok(lock_mutex(&self.inner, "release")?.allowlist.clone())
    }

    fn is_allowlisted_hb(&self, hb: &ContentHash) -> Result<bool, DomainError> {
        let g = lock_mutex(&self.inner, "release")?;
        Ok(g.allowlist.iter().any(|e| e.hb == *hb))
    }
}
