use std::path::{Path, PathBuf};
use std::process::Command;

fn tempfile_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kerosene-vault-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temporary test directory");
    dir
}

fn ceremony_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/ceremony/gen_mtls_certs.sh")
}

#[test]
fn keeps_short_operational_names_and_uses_member_ids_for_spiffe() {
    let root = tempfile_dir("ceremony-member-spiffe");
    let certs = root.join("certs");
    let member_a = "a".repeat(64);
    let members = format!("{},{},{}", member_a, "b".repeat(64), "c".repeat(64));

    let status = Command::new("bash")
        .env("VAULT_CEREMONY_MTLS_OUT", &certs)
        .env("VAULT_MTLS_NODE_IDS", "node-vault-1,node-vault-2,node-vault-3")
        .env("VAULT_MTLS_NODE_MEMBER_IDS", &members)
        .env("VAULT_MTLS_TRUST_DOMAIN", "kerosene.test")
        .arg(ceremony_script())
        .status()
        .expect("run ceremony certificate generator");
    assert!(status.success(), "ceremony certificate generation failed: {status}");

    let cert = certs.join("nodes/node-vault-1/client.crt");
    assert!(cert.is_file(), "certificate path must use the operational node name");
    let output = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(&cert)
        .args(["-noout", "-subject", "-ext", "subjectAltName"])
        .output()
        .expect("inspect generated certificate");
    assert!(output.status.success(), "openssl failed: {}", String::from_utf8_lossy(&output.stderr));
    let certificate = String::from_utf8(output.stdout).expect("openssl output is UTF-8");
    assert!(certificate.contains("CN=node-vault-1-client"));
    assert!(certificate.contains(&format!("URI:spiffe://kerosene.test/vault/{member_a}")));
}

#[test]
fn rejects_incomplete_member_id_mapping_before_creating_a_ca() {
    let root = tempfile_dir("ceremony-member-spiffe-invalid");
    let certs = root.join("certs");

    let output = Command::new("bash")
        .env("VAULT_CEREMONY_MTLS_OUT", &certs)
        .env("VAULT_MTLS_NODE_IDS", "node-vault-1,node-vault-2,node-vault-3")
        .env("VAULT_MTLS_NODE_MEMBER_IDS", "member-a,member-b")
        .arg(ceremony_script())
        .output()
        .expect("run ceremony certificate generator");
    assert!(!output.status.success(), "incomplete identity mapping must fail closed");
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 3 entries"));
    assert!(!Path::new(&certs).join("ca.key").exists(), "validation must precede CA generation");
}
