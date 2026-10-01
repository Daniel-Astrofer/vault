//! Linux-only, pinned Git plumbing in an empty bare repository. Never fetch,
//! clone, checkout, run hooks/filters, or initialize submodules.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::application::GitBundleVerifierPort;
use crate::domain::{
    ContentHash, GitArchiveApprovalV2, GitArchiveError, GitBundleVerificationV2, GIT_BUNDLE_MAX_BYTES,
};
use crate::storage::reject_link_components;

const MAX_OBJECTS: u32 = 50_000;
const OUTPUT_LIMIT: usize = 64 * 1024;

pub struct SafeGitBundleVerifier {
    executable: Option<(PathBuf, String)>,
    active: Mutex<()>,
}

impl SafeGitBundleVerifier {
    pub fn from_env() -> Self {
        let executable = std::env::var_os("VAULT_ARCHIVE_GIT_PATH")
            .zip(std::env::var("VAULT_ARCHIVE_GIT_SHA256").ok())
            .map(|(path, digest)| (PathBuf::from(path), digest));
        Self { executable, active: Mutex::new(()) }
    }

    /// The configured binary pin must be approved independently of archive input.
    pub fn pinned(path: PathBuf, sha256: String) -> Self {
        Self { executable: Some((path, sha256)), active: Mutex::new(()) }
    }

    fn executable(&self) -> Result<(File, String), GitArchiveError> {
        if !cfg!(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))) {
            return Err(GitArchiveError::Unavailable);
        }
        let (path, digest) = self.executable.as_ref().ok_or(GitArchiveError::Unavailable)?;
        if !path.is_absolute() || ContentHash::parse(digest).is_err() {
            return Err(GitArchiveError::Unavailable);
        }
        reject_link_components(path).map_err(|_| GitArchiveError::Unavailable)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| GitArchiveError::Unavailable)?;
        let meta = file.metadata().map_err(|_| GitArchiveError::Unavailable)?;
        if !meta.is_file()
            || meta.len() > GIT_BUNDLE_MAX_BYTES as u64
            || meta.permissions().mode() & 0o022 != 0
            || meta.permissions().mode() & 0o111 == 0
        {
            return Err(GitArchiveError::Unavailable);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(GIT_BUNDLE_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| GitArchiveError::Unavailable)?;
        if bytes.len() > GIT_BUNDLE_MAX_BYTES || ContentHash::from_bytes(&bytes).as_str() != digest {
            return Err(GitArchiveError::Unavailable);
        }
        // Execute this same open inode through /proc, avoiding a path-swap race.
        Ok((file, digest.clone()))
    }
}

struct BundleHeader {
    version: u16,
    offset: usize,
    tips: Vec<String>,
}

fn header(bytes: &[u8], approval: &GitArchiveApprovalV2) -> Result<BundleHeader, GitArchiveError> {
    if bytes.len() > GIT_BUNDLE_MAX_BYTES {
        return Err(GitArchiveError::Invalid);
    }
    let end = bytes.windows(2).position(|w| w == b"\n\n").ok_or(GitArchiveError::Invalid)?;
    if end > 16 * 1024 {
        return Err(GitArchiveError::Invalid);
    }
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| GitArchiveError::Invalid)?;
    let mut lines = text.split('\n');
    let version = match lines.next() {
        Some("# v2 git bundle") if approval.object_format == "sha1" => 2,
        Some("# v3 git bundle") => 3,
        _ => return Err(GitArchiveError::Invalid),
    };
    let mut format = version == 2;
    let mut names = BTreeSet::new();
    let mut tips = Vec::new();
    for line in lines {
        // Prerequisites and filter/unknown capabilities are never self-contained.
        if line.starts_with('-') {
            return Err(GitArchiveError::Invalid);
        }
        if line.starts_with('@') {
            if version != 3
                || format
                || !tips.is_empty()
                || line != format!("@object-format={}", approval.object_format)
            {
                return Err(GitArchiveError::Invalid);
            }
            format = true;
            continue;
        }
        let (oid, name) = line.split_once(' ').ok_or(GitArchiveError::Invalid)?;
        if !format
            || oid.len() != approval.commit.len()
            || !oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || name.len() > 240
            || !(name == "HEAD" || name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
            || name.split('/').any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with(".lock"))
            || name.contains("..")
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || !names.insert(name)
            || tips.len() >= 64
        {
            return Err(GitArchiveError::Invalid);
        }
        tips.push(oid.to_string());
    }
    if !tips.contains(&approval.commit) {
        return Err(GitArchiveError::Conflict);
    }
    let offset = end + 2;
    let pack = bytes.get(offset..offset + 12).ok_or(GitArchiveError::Invalid)?;
    if &pack[..4] != b"PACK"
        || ![2, 3].contains(&u32::from_be_bytes(pack[4..8].try_into().unwrap()))
        || u32::from_be_bytes(pack[8..12].try_into().unwrap()) > MAX_OBJECTS
    {
        return Err(GitArchiveError::Invalid);
    }
    Ok(BundleHeader { version, offset, tips })
}

fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>) -> Result<(), GitArchiveError> {
    let mut buf = [0; 8192];
    // Bound each polling cycle as well as total output, even for a noisy process.
    for _ in 0..8 {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) if bytes.len() + n <= OUTPUT_LIMIT => bytes.extend_from_slice(&buf[..n]),
            Ok(_) => return Err(GitArchiveError::Invalid),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(GitArchiveError::Unavailable),
        }
    }
    Ok(())
}

// Safety: pre_exec uses only fixed data and libc syscalls. Failure refuses the
// child. Network syscall denial is enforced rather than relying on Git policy.
fn child_limits() -> std::io::Result<()> {
    unsafe {
        for (resource, value) in [
            (libc::RLIMIT_CPU, 10),
            (libc::RLIMIT_AS, 256 * 1024 * 1024),
            (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
            (libc::RLIMIT_NOFILE, 64),
            (libc::RLIMIT_CORE, 0),
        ] {
            let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
            if libc::setrlimit(resource, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003e;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let arch = 0;
        let filter = [
            libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 4 }, // load arch
            libc::sock_filter { code: 0x15, jt: 1, jf: 0, k: arch },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x80000000 },
            libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 0 }, // load syscall
            libc::sock_filter { code: 0x35, jt: 0, jf: 1, k: 0x40000000 }, // refuse x32
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x80000000 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_socket as u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00050000 | libc::EACCES as u32 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_socketpair as u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00050000 | libc::EACCES as u32 },
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_connect as u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00050000 | libc::EACCES as u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x7fff0000 },
        ];
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
        if libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn run(binary: &File, scratch: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>, GitArchiveError> {
    let mut command = Command::new(format!("/proc/self/fd/{}", binary.as_raw_fd()));
    command
        .arg0("git")
        .env_clear()
        .current_dir(scratch)
        .env("PATH", "")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_EXEC_PATH", scratch.join("empty"))
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "pack.threads=1",
            "-c",
            "pack.windowMemory=16m",
            "-c",
            "core.deltaBaseCacheLimit=16m",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    unsafe {
        command.pre_exec(child_limits);
    }
    let mut child = command.spawn().map_err(|_| GitArchiveError::Unavailable)?;
    let mut out = child.stdout.take().ok_or(GitArchiveError::Unavailable)?;
    let mut err = child.stderr.take().ok_or(GitArchiveError::Unavailable)?;
    let result = (|| {
        for fd in [out.as_raw_fd(), err.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(GitArchiveError::Unavailable);
            }
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            drain(&mut out, &mut stdout)?;
            drain(&mut err, &mut stderr)?;
            if let Some(status) = child.try_wait().map_err(|_| GitArchiveError::Unavailable)? {
                drain(&mut out, &mut stdout)?;
                drain(&mut err, &mut stderr)?;
                #[cfg(test)]
                if !status.success() {
                    eprintln!("Git archive test command {args:?}: {}", String::from_utf8_lossy(&stderr));
                }
                return if status.success() { Ok(stdout) } else { Err(GitArchiveError::Invalid) };
            }
            if Instant::now() >= deadline {
                return Err(GitArchiveError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    // Kill the isolated group, including unexpected surviving descendants.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.wait();
    result
}

fn check_version(binary: &File, scratch: &Path, deadline: Instant) -> Result<(), GitArchiveError> {
    let output = run(binary, scratch, &["--version"], deadline).map_err(|_| GitArchiveError::Unavailable)?;
    let text = std::str::from_utf8(&output).map_err(|_| GitArchiveError::Unavailable)?;
    let version = text.strip_prefix("git version ").ok_or(GitArchiveError::Unavailable)?;
    let mut parts = version.split('.');
    let major = parts.next().and_then(|s| s.parse::<u32>().ok()).ok_or(GitArchiveError::Unavailable)?;
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).ok_or(GitArchiveError::Unavailable)?;
    if major != 2 || minor < 43 {
        return Err(GitArchiveError::Unavailable);
    }
    Ok(())
}

impl GitBundleVerifierPort for SafeGitBundleVerifier {
    fn available(&self) -> bool {
        let Ok(_guard) = self.active.try_lock() else {
            return false;
        };
        let Ok((binary, _)) = self.executable() else {
            return false;
        };
        let Ok(scratch) = tempfile::Builder::new().prefix("vault-git-capability-").tempdir() else {
            return false;
        };
        check_version(&binary, scratch.path(), Instant::now() + Duration::from_secs(2)).is_ok()
    }

    fn verify(
        &self,
        approval: &GitArchiveApprovalV2,
        bytes: &[u8],
    ) -> Result<GitBundleVerificationV2, GitArchiveError> {
        approval.validate()?;
        if ContentHash::from_bytes(bytes).as_str() != approval.bundle_sha256 {
            return Err(GitArchiveError::Conflict);
        }
        let _guard = self.active.try_lock().map_err(|_| GitArchiveError::Busy)?;
        let (binary, git_executable_sha256) = self.executable()?;
        let parsed = header(bytes, approval)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        let scratch =
            tempfile::Builder::new().prefix("vault-git-verify-").tempdir().map_err(|_| GitArchiveError::Unavailable)?;
        let root = scratch.path();
        fs::create_dir(root.join("empty")).map_err(|_| GitArchiveError::Unavailable)?;
        check_version(&binary, root, deadline)?;
        let format_arg = format!("--object-format={}", approval.object_format);
        run(&binary, root, &["init", "--bare", "--quiet", "--template=", &format_arg, "repo"], deadline)?;
        let pack_path = root.join("repo/objects/pack/pack-upload.pack");
        fs::write(&pack_path, &bytes[parsed.offset..]).map_err(|_| GitArchiveError::Unavailable)?;
        run(
            &binary,
            root,
            &[
                "--git-dir=repo",
                "index-pack",
                "--strict",
                "--threads=1",
                "--no-rev-index",
                "--max-input-size=33554432",
                "repo/objects/pack/pack-upload.pack",
            ],
            deadline,
        )?;
        let mut fsck = vec!["--git-dir=repo", "fsck", "--strict", "--full", "--no-reflogs", "--no-dangling"];
        fsck.extend(parsed.tips.iter().map(String::as_str));
        run(&binary, root, &fsck, deadline)?;
        let kind = run(&binary, root, &["--git-dir=repo", "cat-file", "-t", &approval.commit], deadline)?;
        if kind != b"commit\n" {
            return Err(GitArchiveError::Conflict);
        }
        let count = run(&binary, root, &["--git-dir=repo", "rev-list", "--count", &approval.commit], deadline)?;
        let commit_count = std::str::from_utf8(&count)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .ok_or(GitArchiveError::Invalid)?;
        Ok(GitBundleVerificationV2 { commit_count, bundle_version: parsed.version, git_executable_sha256 })
    }
}

#[cfg(test)]
mod git_archive_tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) -> Vec<u8> {
        let result = Command::new("/usr/bin/git")
            .current_dir(root)
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "archive-test")
            .env("GIT_AUTHOR_EMAIL", "archive@example.invalid")
            .env("GIT_COMMITTER_NAME", "archive-test")
            .env("GIT_COMMITTER_EMAIL", "archive@example.invalid")
            .args(args)
            .output()
            .unwrap();
        assert!(result.status.success(), "fixture git {:?}: {}", args, String::from_utf8_lossy(&result.stderr));
        result.stdout
    }

    fn fixture() -> (tempfile::TempDir, Vec<u8>, GitArchiveApprovalV2, SafeGitBundleVerifier) {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "--quiet", "--template=", "."]);
        fs::write(dir.path().join("source.sh"), b"#!/bin/sh\ntouch MUST_NOT_EXECUTE\n").unwrap();
        git(dir.path(), &["add", "source.sh"]);
        git(dir.path(), &["commit", "--quiet", "-m", "first"]);
        fs::write(dir.path().join("README"), b"history").unwrap();
        git(dir.path(), &["add", "README"]);
        git(dir.path(), &["commit", "--quiet", "-m", "second"]);
        let commit = String::from_utf8(git(dir.path(), &["rev-parse", "HEAD"])).unwrap().trim().to_string();
        git(dir.path(), &["bundle", "create", "history.bundle", "HEAD"]);
        let bytes = fs::read(dir.path().join("history.bundle")).unwrap();
        let binary = fs::canonicalize("/usr/bin/git").unwrap();
        let pin = ContentHash::from_bytes(&fs::read(&binary).unwrap()).as_str().to_string();
        let verifier = SafeGitBundleVerifier::pinned(binary, pin);
        let approval = GitArchiveApprovalV2 {
            archive_version: 2,
            release_id: "r1".into(),
            repository_id: "core".into(),
            commit,
            object_format: "sha1".into(),
            bundle_sha256: ContentHash::from_bytes(&bytes).as_str().into(),
            retention_pinned: true,
        };
        (dir, bytes, approval, verifier)
    }

    #[test]
    fn git_archive_verifies_real_complete_history_without_checkout_or_source_execution() {
        let (dir, bytes, approval, verifier) = fixture();
        assert!(verifier.available(), "integration requires independently pinned Git >=2.43 and Linux sandbox");
        let result = verifier.verify(&approval, &bytes).unwrap();
        assert_eq!(result.commit_count, 2);
        assert_eq!(result.bundle_version, 2);
        assert!(!dir.path().join("MUST_NOT_EXECUTE").exists());
        let mut truncated = bytes.clone();
        truncated.truncate(bytes.len() - 10);
        let mut changed = approval.clone();
        changed.bundle_sha256 = ContentHash::from_bytes(&truncated).as_str().into();
        assert_eq!(verifier.verify(&changed, &truncated), Err(GitArchiveError::Invalid));
        changed = approval.clone();
        changed.commit = "a".repeat(40);
        assert_eq!(verifier.verify(&changed, &bytes), Err(GitArchiveError::Conflict));
    }

    #[test]
    fn git_archive_refuses_partial_history_unknown_capabilities_and_wrong_binary_pin() {
        let (dir, bytes, approval, _) = fixture();
        let binary = fs::canonicalize("/usr/bin/git").unwrap();
        let bad = SafeGitBundleVerifier::pinned(binary, ContentHash::from_bytes(b"not-git").as_str().into());
        assert!(!bad.available());
        assert_eq!(bad.verify(&approval, &bytes), Err(GitArchiveError::Unavailable));
        git(dir.path(), &["bundle", "create", "partial.bundle", "HEAD", "^HEAD~1"]);
        let partial = fs::read(dir.path().join("partial.bundle")).unwrap();
        let mut pinned = approval.clone();
        pinned.bundle_sha256 = ContentHash::from_bytes(&partial).as_str().into();
        assert!(header(&partial, &pinned).is_err());
        let bad_header =
            format!("# v3 git bundle\n@object-format=sha1\n@filter=blob:none\n{} HEAD\n\nPACK", approval.commit);
        assert!(header(bad_header.as_bytes(), &approval).is_err());
    }
}
