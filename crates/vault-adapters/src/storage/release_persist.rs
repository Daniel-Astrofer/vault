//! Durable release mesh snapshot under VAULT_DATA_DIR/release/.
//!
//! # Persistence honesty (#18)
//! Process-local atomic meta + blob files. Not an authenticated mesh release ledger.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::durable_fs::atomic_write_fsync;
use super::release_memory::InMemoryReleaseMesh;
use super::sync_util::lock_mutex;
use crate::application::ports::{BlobStorePort, ReleaseStorePort};
use crate::domain::{AllowlistEntry, ContentHash, DomainError, ReleaseCandidate, ReleasePhase, ReleasePolicy};

pub struct PersistedReleaseMesh {
    meta_path: PathBuf,
    blobs_dir: PathBuf,
    inner: InMemoryReleaseMesh,
}

impl PersistedReleaseMesh {
    pub fn open(root: impl Into<PathBuf>, policy: ReleasePolicy) -> Result<Self, DomainError> {
        let root = root.into();
        let meta_path = root.join("release_meta.json");
        let blobs_dir = root.join("blobs");
        fs::create_dir_all(&blobs_dir).map_err(|e| DomainError::ThresholdError(format!("release mkdir: {e}")))?;
        let mesh = InMemoryReleaseMesh::new(policy);
        if meta_path.exists() {
            hydrate_meta(&meta_path, &mesh)?;
        }
        if let Ok(entries) = fs::read_dir(&blobs_dir) {
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if let Ok(bytes) = fs::read(ent.path()) {
                    if let Ok(hash) = ContentHash::parse(&name) {
                        let _ = mesh.put(&hash, &bytes);
                    }
                }
            }
        }
        Ok(Self { meta_path, blobs_dir, inner: mesh })
    }

    fn persist_meta(&self) -> Result<(), DomainError> {
        let policy = self.inner.policy()?;
        let allowlist = self.inner.allowlist()?;
        let candidate_jsons = list_candidate_jsons(&self.inner)?;
        let al: Vec<String> = allowlist
            .iter()
            .map(|e| {
                format!(
                    r#"{{"release_id":"{}","hs":"{}","hb":"{}","activated_at_secs":{},"constitution_hash":"{}"}}"#,
                    escape(&e.release_id),
                    escape(e.hs.as_str()),
                    escape(e.hb.as_str()),
                    e.activated_at_secs,
                    escape(&e.constitution_hash)
                )
            })
            .collect();
        let json = format!(
            r#"{{"version":1,"policy":{{"council_n":{},"min_rebuilds":{},"vault_n":{},"timelock_secs":{},"lab_timelock_scale":{}}},"candidates":[{}],"allowlist":[{}]}}"#,
            policy.council_n,
            policy.min_rebuilds,
            policy.vault_n,
            policy.timelock_secs,
            policy.lab_timelock_scale,
            candidate_jsons.join(","),
            al.join(",")
        );
        atomic_write_fsync(&self.meta_path, json.as_bytes())
            .map_err(|e| DomainError::ThresholdError(format!("release meta persist: {e}")))
    }

    fn persist_blob(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError> {
        let path = self.blobs_dir.join(hash.as_str());
        atomic_write_fsync(&path, bytes).map_err(|e| DomainError::ThresholdError(format!("release blob persist: {e}")))
    }
}

impl BlobStorePort for PersistedReleaseMesh {
    fn put(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError> {
        self.inner.put(hash, bytes)?;
        self.persist_blob(hash, bytes)
    }

    fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, DomainError> {
        self.inner.get(hash)
    }
}

impl ReleaseStorePort for PersistedReleaseMesh {
    fn policy(&self) -> Result<ReleasePolicy, DomainError> {
        self.inner.policy()
    }

    fn put_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        self.inner.put_candidate(candidate)?;
        self.persist_meta()
    }

    fn get_candidate(&self, id: &str) -> Result<ReleaseCandidate, DomainError> {
        self.inner.get_candidate(id)
    }

    fn save_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        self.inner.save_candidate(candidate)?;
        self.persist_meta()
    }

    fn put_allowlist(&self, entry: AllowlistEntry) -> Result<(), DomainError> {
        self.inner.put_allowlist(entry)?;
        self.persist_meta()
    }

    fn allowlist(&self) -> Result<Vec<AllowlistEntry>, DomainError> {
        self.inner.allowlist()
    }

    fn is_allowlisted_hb(&self, hb: &ContentHash) -> Result<bool, DomainError> {
        self.inner.is_allowlisted_hb(hb)
    }
}

fn list_candidate_jsons(mesh: &InMemoryReleaseMesh) -> Result<Vec<String>, DomainError> {
    let g = lock_mutex(&mesh.inner, "release")?;
    Ok(g.candidates.values().map(candidate_json).collect())
}

fn candidate_json(c: &ReleaseCandidate) -> String {
    let council: Vec<String> = c.council_sigs.iter().map(|s| format!("\"{}\"", escape(s))).collect();
    let cosigns: Vec<String> = c.cosigns.iter().map(|s| format!("\"{}\"", escape(s))).collect();
    let rebuilds: Vec<String> = c
        .rebuilds
        .iter()
        .map(|(k, v)| format!(r#"{{"node":"{}","hb":"{}"}}"#, escape(k), escape(v.as_str())))
        .collect();
    let reject = c.reject_reason.as_ref().map(|s| format!("\"{}\"", escape(s))).unwrap_or_else(|| "null".into());
    format!(
        r#"{{"id":"{}","hs":"{}","hb":"{}","constitution_hash":"{}","created_at_secs":{},"phase":"{}","reject_reason":{},"council_sigs":[{}],"cosigns":[{}],"rebuilds":[{}]}}"#,
        escape(&c.id),
        escape(c.hs.as_str()),
        escape(c.hb.as_str()),
        escape(&c.constitution_hash),
        c.created_at_secs,
        c.phase.as_str(),
        reject,
        council.join(","),
        cosigns.join(","),
        rebuilds.join(",")
    )
}

fn hydrate_meta(path: &Path, mesh: &InMemoryReleaseMesh) -> Result<(), DomainError> {
    let raw = fs::read_to_string(path).map_err(|e| DomainError::ThresholdError(format!("release meta read: {e}")))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| DomainError::ThresholdError(format!("release meta json: {e}")))?;
    if let Some(arr) = v["candidates"].as_array() {
        for c in arr {
            let id = c["id"].as_str().unwrap_or("").to_string();
            let hs = ContentHash::parse(c["hs"].as_str().unwrap_or(""))?;
            let hb = ContentHash::parse(c["hb"].as_str().unwrap_or(""))?;
            let mut council = BTreeSet::new();
            if let Some(sigs) = c["council_sigs"].as_array() {
                for s in sigs {
                    if let Some(x) = s.as_str() {
                        council.insert(x.to_string());
                    }
                }
            }
            let mut cand = ReleaseCandidate::new(
                id,
                hs,
                hb,
                c["constitution_hash"].as_str().unwrap_or("").to_string(),
                council,
                c["created_at_secs"].as_u64().unwrap_or(0),
            )?;
            cand.phase = match c["phase"].as_str().unwrap_or("proposed") {
                "cosigning" => ReleasePhase::Cosigning,
                "allowlisted" => ReleasePhase::Allowlisted,
                "rejected" => ReleasePhase::Rejected,
                _ => ReleasePhase::Proposed,
            };
            cand.reject_reason = c["reject_reason"].as_str().map(|s| s.to_string());
            if let Some(cos) = c["cosigns"].as_array() {
                for s in cos {
                    if let Some(x) = s.as_str() {
                        cand.cosigns.insert(x.to_string());
                    }
                }
            }
            if let Some(rb) = c["rebuilds"].as_array() {
                for r in rb {
                    if let (Some(node), Some(h)) = (r["node"].as_str(), r["hb"].as_str()) {
                        cand.rebuilds.insert(node.to_string(), ContentHash::parse(h)?);
                    }
                }
            }
            let _ = mesh.put_candidate(cand);
        }
    }
    if let Some(arr) = v["allowlist"].as_array() {
        for e in arr {
            mesh.put_allowlist(AllowlistEntry {
                release_id: e["release_id"].as_str().unwrap_or("").to_string(),
                hs: ContentHash::parse(e["hs"].as_str().unwrap_or(""))?,
                hb: ContentHash::parse(e["hb"].as_str().unwrap_or(""))?,
                activated_at_secs: e["activated_at_secs"].as_u64().unwrap_or(0),
                constitution_hash: e["constitution_hash"].as_str().unwrap_or("").to_string(),
            })?;
        }
    }
    Ok(())
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
