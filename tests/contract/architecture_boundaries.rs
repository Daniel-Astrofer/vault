//! Guards against reversing the Clean Architecture dependency direction.

use std::fs;
use std::path::Path;

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("architecture source must be readable")
}

fn rust_sources(root: impl AsRef<Path>) -> Vec<std::path::PathBuf> {
    fn collect(path: &Path, result: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(path).expect("architecture directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                collect(&path, result);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                result.push(path);
            }
        }
    }

    let mut result = Vec::new();
    collect(root.as_ref(), &mut result);
    result
}

#[test]
fn domain_has_no_runtime_or_bitcoin_dependency() {
    let manifest = read("crates/domain/Cargo.toml");
    for forbidden in ["axum", "tokio", "reqwest", "rustls", "bitcoin", "frost", "tracing", "log ="] {
        assert!(
            !manifest.contains(forbidden),
            "vault-domain must not depend on {forbidden}; move that work behind an application port or adapter"
        );
    }
}

#[test]
fn domain_source_is_technology_free() {
    let forbidden = [
        "crate::adapters",
        "vault_core",
        "axum::",
        "tokio::",
        "reqwest::",
        "rustls::",
        "bitcoin::",
        "std::fs",
        "std::env",
        "std::net",
        "std::path",
        "tracing::",
        "log::",
    ];
    for path in rust_sources("crates/domain") {
        let source = read(&path);
        for import in forbidden {
            assert!(!source.contains(import), "{} imports {import}", path.display());
        }
    }
}

#[test]
fn application_does_not_depend_on_core_adapters_or_bootstrap() {
    let manifest = read("crates/application/Cargo.toml");
    assert!(!manifest.contains("vault-core"));
    let forbidden = ["crate::adapters", "crate::bootstrap", "vault_core::", "axum::", "tokio::", "reqwest::"];
    for path in rust_sources("crates/application") {
        let source = read(&path);
        for import in forbidden {
            assert!(!source.contains(import), "{} imports {import}", path.display());
        }
    }
}

#[test]
fn clean_architecture_directories_are_present() {
    for directory in [
        "crates/domain/identity",
        "crates/domain/signing",
        "crates/application/use_cases",
        "crates/application/ports",
        "crates/adapters/attestation/tee",
        "crates/adapters/frost",
        "crates/adapters/storage",
        "crates/api/routes",
        "crates/bootstrap/runtime",
        "crates/identity-core/identity",
        "crates/identityd/daemon",
        "crates/signer/protocol",
        "crates/signer/signing",
        "crates/signer/session",
        "crates/signer/transport",
    ] {
        assert!(Path::new(directory).is_dir(), "missing architectural directory: {directory}");
    }
}
