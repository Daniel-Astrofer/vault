//! Immutable, bounded, inert source storage. Filesystem ownership remains an
//! operator boundary; this is local durable evidence, not a distributed ledger.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use rand::RngCore;

use super::{fsync_parent, lock_mutex, PersistedReleaseMesh};
use crate::application::SourceArchiveStorePort;
use crate::domain::{
    validate_release_id, ContentHash, DomainError, SourceArchiveReceiptV1, SourceBundleV1, SOURCE_BUNDLE_MAX_BYTES,
};

fn invalid(message: impl std::fmt::Display) -> DomainError {
    DomainError::InvalidRelease(message.to_string())
}

pub(crate) fn reject_link_components(path: &Path) -> Result<(), DomainError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(invalid("parent traversal in archive storage path"));
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(invalid("link in archive storage path")),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(invalid(format!("archive storage path: {e}"))),
        }
    }
    Ok(())
}

pub(crate) fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, DomainError> {
    reject_link_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| invalid(format!("archive read: {e}")))?;
    let meta = file.metadata().map_err(invalid)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit as u64 {
        return Err(invalid("archive is not a bounded regular file without links"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(invalid)?;
    if bytes.len() > limit {
        return Err(invalid("archive exceeds byte limit"));
    }
    Ok(bytes)
}

/// Publish complete bytes without replacing an existing inode. A retry must
/// match existing bytes exactly. Random create_new temporary files avoid races.
pub(crate) fn put_immutable(path: &Path, bytes: &[u8], limit: usize) -> Result<(), DomainError> {
    if bytes.len() > limit {
        return Err(invalid("archive exceeds byte limit"));
    }
    reject_link_components(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return if read_bounded_regular(path, limit)? == bytes {
            Ok(())
        } else {
            Err(invalid("immutable archive conflict"))
        };
    }
    let mut nonce = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let temp = path.with_extension(format!("{}.tmp", hex::encode(nonce)));
    let mut created = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(invalid)?;
        created = true;
        file.write_all(bytes).map_err(invalid)?;
        file.set_permissions(fs::Permissions::from_mode(0o400)).map_err(invalid)?;
        file.sync_all().map_err(invalid)?;
        match fs::hard_link(&temp, path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_bounded_regular(path, limit)? != bytes {
                    return Err(invalid("immutable archive conflict"));
                }
            }
            Err(e) => return Err(invalid(e)),
        }
        Ok(())
    })();
    // Only our exact random temporary path is removed, never an existing blob.
    let cleanup = if created { fs::remove_file(&temp) } else { Ok(()) };
    result?;
    cleanup.map_err(invalid)?;
    fsync_parent(path)?;
    Ok(())
}

impl SourceArchiveStorePort for PersistedReleaseMesh {
    fn put_source_archive(
        &self,
        receipt: SourceArchiveReceiptV1,
        canonical: &[u8],
    ) -> Result<SourceArchiveReceiptV1, DomainError> {
        validate_release_id(&receipt.release_id)?;
        let digest = ContentHash::parse(&receipt.canonical_digest)?;
        let bundle = SourceBundleV1::parse(
            canonical
                .strip_prefix(b"vault-source-bundle-v1\n")
                .ok_or_else(|| invalid("invalid source archive prefix"))?,
        )?;
        if receipt.format_version != 1
            || receipt.archived_at_secs == 0
            || bundle.release_id != receipt.release_id
            || bundle.target_sequence != receipt.target_sequence
            || ContentHash::from_bytes(canonical) != digest
            || bundle.canonical_bytes()? != canonical
        {
            return Err(invalid("source receipt binding mismatch"));
        }
        let _guard = lock_mutex(&self.archive_writes, "source archive")?;
        let path = self.archives_dir.join(ContentHash::from_bytes(receipt.release_id.as_bytes()).as_str());
        if fs::symlink_metadata(&path).is_ok() {
            let (existing, bytes) = self.get_source_archive(&receipt.release_id)?;
            if existing.canonical_digest != receipt.canonical_digest
                || existing.target_sequence != receipt.target_sequence
                || bytes != canonical
            {
                return Err(DomainError::ReleasePredicate(
                    "releaseId already bound to another immutable archive".into(),
                ));
            }
            return Ok(existing);
        }
        put_immutable(&self.blobs_dir.join(digest.as_str()), canonical, SOURCE_BUNDLE_MAX_BYTES)?;
        put_immutable(&path, &serde_json::to_vec(&receipt).map_err(invalid)?, 4096)?;
        Ok(receipt)
    }

    fn get_source_archive(&self, release_id: &str) -> Result<(SourceArchiveReceiptV1, Vec<u8>), DomainError> {
        validate_release_id(release_id)?;
        let path = self.archives_dir.join(ContentHash::from_bytes(release_id.as_bytes()).as_str());
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DomainError::UnknownRelease(release_id.into()))
            }
            Err(e) => return Err(invalid(e)),
            Ok(_) => (),
        }
        let receipt: SourceArchiveReceiptV1 =
            serde_json::from_slice(&read_bounded_regular(&path, 4096)?).map_err(invalid)?;
        if receipt.release_id != release_id || receipt.format_version != 1 {
            return Err(invalid("source receipt integrity failure"));
        }
        let digest = ContentHash::parse(&receipt.canonical_digest)?;
        let bytes = read_bounded_regular(&self.blobs_dir.join(digest.as_str()), SOURCE_BUNDLE_MAX_BYTES)?;
        if ContentHash::from_bytes(&bytes) != digest {
            return Err(DomainError::MeasurementMismatch);
        }
        Ok((receipt, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{BlobStorePort, ReleaseStorePort};
    use crate::domain::{ReleasePolicy, SourceFileV1};

    #[test]
    fn durable_archive_is_immutable_inert_and_separate_from_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let mesh = PersistedReleaseMesh::open(dir.path(), ReleasePolicy::lab_default(3)).unwrap();
        let mut bundle = SourceBundleV1 {
            format_version: 1,
            release_id: "r1".into(),
            target_sequence: 7,
            protocol_version: 1,
            storage_version: 1,
            production: true,
            features: ["production".into()].into(),
            files: vec![SourceFileV1 { path: "evil.sh".into(), content_hex: hex::encode(b"touch executed") }],
        };
        let canonical = bundle.canonical_bytes().unwrap();
        let receipt = SourceArchiveReceiptV1 {
            format_version: 1,
            release_id: "r1".into(),
            canonical_digest: ContentHash::from_bytes(&canonical).as_str().into(),
            target_sequence: 7,
            archived_at_secs: 100,
        };
        mesh.put_source_archive(receipt.clone(), &canonical).unwrap();
        let mut retry = receipt.clone();
        retry.archived_at_secs = 101;
        assert_eq!(mesh.put_source_archive(retry, &canonical).unwrap(), receipt);
        bundle.target_sequence = 8;
        let other = bundle.canonical_bytes().unwrap();
        let mut conflict = receipt.clone();
        conflict.target_sequence = 8;
        conflict.canonical_digest = ContentHash::from_bytes(&other).as_str().into();
        assert!(mesh.put_source_archive(conflict, &other).is_err());
        assert!(mesh.allowlist().unwrap().is_empty());
        assert!(mesh.get_candidate("r1").is_err());
        assert!(!dir.path().join("evil.sh").exists());
        drop(mesh);
        let reopened = PersistedReleaseMesh::open(dir.path(), ReleasePolicy::lab_default(3)).unwrap();
        assert_eq!(reopened.get_source_archive("r1").unwrap(), (receipt.clone(), canonical));
        let digest = ContentHash::parse(receipt.canonical_digest).unwrap();
        assert!(reopened.put(&digest, b"replacement").is_err());
        let blob = dir.path().join("blobs").join(digest.as_str());
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&blob, b"tamper").unwrap();
        assert!(reopened.get_source_archive("r1").is_err());
    }

    #[test]
    fn disk_links_and_special_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"secret").unwrap();
        let symlink = dir.path().join("symlink");
        std::os::unix::fs::symlink(&victim, &symlink).unwrap();
        assert!(read_bounded_regular(&symlink, 1024).is_err());
        assert!(put_immutable(&symlink, b"change", 1024).is_err());
        let hardlink = dir.path().join("hardlink");
        fs::hard_link(&victim, &hardlink).unwrap();
        assert!(read_bounded_regular(&hardlink, 1024).is_err());
        assert!(read_bounded_regular(dir.path(), 1024).is_err());
        assert!(read_bounded_regular(&victim, 1).is_err());
        let linked_dir = dir.path().join("linked-dir");
        std::os::unix::fs::symlink(dir.path(), &linked_dir).unwrap();
        assert!(PersistedReleaseMesh::open(&linked_dir, ReleasePolicy::lab_default(3)).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"secret");
    }

    #[test]
    fn unknown_snapshot_versions_and_false_blob_hashes_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("release_meta.json"), br#"{"version":2,"candidates":[],"allowlist":[]}"#).unwrap();
        assert!(PersistedReleaseMesh::open(dir.path(), ReleasePolicy::lab_default(3)).is_err());
        let mesh = crate::adapters::InMemoryReleaseMesh::new(ReleasePolicy::lab_default(3));
        let hash = ContentHash::from_bytes(b"source");
        assert!(mesh.put(&hash, b"different source").is_err());
        assert!(mesh.get(&hash).is_err());
        mesh.put(&hash, b"source").unwrap();
        mesh.put(&hash, b"source").unwrap();
        assert!(mesh.put(&hash, b"replacement").is_err());
        assert_eq!(mesh.get(&hash).unwrap(), b"source");
    }
}
