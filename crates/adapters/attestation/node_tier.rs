//! Host-device discovery for the node-tier domain policy.

use std::path::Path;

use crate::domain::VaultNodeTier;

/// Probe Linux TEE device nodes. SEV wins when both SEV and SGX are present.
pub fn detect_tee_devices() -> Option<VaultNodeTier> {
    detect_tee_at_paths(&[
        Path::new("/dev/sev-guest"),
        Path::new("/dev/sev"),
        Path::new("/dev/sgx_enclave"),
        Path::new("/dev/sgx/enclave"),
        Path::new("/dev/isgx"),
    ])
}

/// Testable implementation of host-device discovery.
pub fn detect_tee_at_paths(paths: &[&Path]) -> Option<VaultNodeTier> {
    let mut sgx = false;
    for path in paths.iter().filter(|path| path.exists()) {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let parent =
            path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        if name.contains("sev") {
            return Some(VaultNodeTier::Sev);
        }
        if name.contains("sgx") || name == "isgx" || parent == "sgx" {
            sgx = true;
        }
    }
    sgx.then_some(VaultNodeTier::Sgx)
}
