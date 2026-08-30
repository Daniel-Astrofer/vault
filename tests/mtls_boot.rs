//! mTLS boot path: rustls server config + optional Axum listen with client cert.
//! Lab static_token remains the default; this exercises the Gate visualize path.
#![cfg(not(feature = "production"))]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kerosene_vault::adapters::{build_mtls_server_config, build_router};
use kerosene_vault::bootstrap::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig, VaultRuntime};
use kerosene_vault::domain::{AttestationMode, BitcoinNetwork, NodeId};

fn gen_lab_certs(dir: &Path) {
    std::fs::create_dir_all(dir).expect("tmpdir");
    let status = Command::new("bash")
        .env("VAULT_LAB_MTLS_OUT", dir)
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/gen_lab_mtls_certs.sh"))
        .status()
        .expect("run gen_lab_mtls_certs.sh");
    assert!(status.success(), "cert generation failed: {status}");
}

fn lab_mtls_cfg(listen: &str, certs: &Path, data_dir: &Path) -> VaultConfig {
    VaultConfig {
        node_id: NodeId::new("vault-mtls-1").unwrap(),
        node_tier: kerosene_vault::domain::VaultNodeTier::Domestic,
        tee_available: false,
        attestation_mode: AttestationMode::Sim,
        listen_addr: listen.into(),
        lab_root: "kerosene-lab-mtls".into(),
        seed_peers: vec![],
        peer_tiers: std::collections::BTreeMap::new(),
        peer_tier_quotes: std::collections::BTreeMap::new(),
        peer_tier_require_quote: false,
        refuse_sim: false,
        genesis_n: Some(2),
        online_count: Some(2),
        online_static: false,
        psbt_policy: kerosene_vault::domain::PsbtPolicy::lab_defaults(),
        lab_timelock_scale: 0,
        lab_timelock_env_set: false,
        lab_council_n: 3,
        lab_min_rebuilds: 3,
        hardened: false,
        attestation_staging_stub: false,
        ceremony_mode: CeremonyMode::Lab,
        open_economy: false,
        miner_payout_cadence: kerosene_vault::domain::MinerPayoutCadence::Manual,
        miner_payout_frequency: kerosene_vault::domain::MinerPayoutCadence::Daily,
        seating_policy_timeout_hours: 24,
        bitcoin_network: BitcoinNetwork::Testnet3,
        auth_mode: AuthMode::MutualTls,
        vault_token: None,
        users_destination_allowlist: vec![],
        miners_destination_allowlist: vec![],
        allow_manual_reshare: false,
        lab_allow_raw_sighash: false,
        tls_cert_path: Some(certs.join("vault-server.crt").display().to_string()),
        tls_key_path: Some(certs.join("vault-server.key").display().to_string()),
        tls_client_ca_path: Some(certs.join("ca.crt").display().to_string()),
        tls_client_cert_path: Some(certs.join("vault-client.crt").display().to_string()),
        tls_client_key_path: Some(certs.join("vault-client.key").display().to_string()),
        tls_verify_policy: kerosene_vault::adapters::TlsPeerVerifyPolicy::Hostname,
        audit_key_allowlist: kerosene_vault::adapters::MeshAuditKeyAllowlist::empty(),
        share_store_mode: ShareStoreMode::AeadDisk,
        share_passphrase: Some("kerosene-vault-lab-passphrase".into()),
        share_tpm_seal: false,
        share_tpm_stub: false,
        share_tpm_clear_fallback: false,
        secure_boot_pcr_policy: None,
        data_dir: Some(data_dir.display().to_string()),
        anti_nonce_shared_dir: None,
        measurement_pin_hex: None,
        dealer_requested: false,
        dkg_mode: DkgMode::DistributedWire,
        reshare_policy: kerosene_vault::domain::ResharePolicy::Manual,
        governance_reward_sats: 0,
        governance_reward_bps: 0,
        transport: kerosene_vault::adapters::VaultTransport::Clearnet,
        peer_http: kerosene_vault::adapters::PeerHttpSettings::clearnet_defaults(),
        clearnet_publish: false,
        admin_unix_socket_path: None,
    }
}

#[test]
fn mtls_server_config_loads_from_lab_certs() {
    let root = tempfile_dir("mtls-cfg");
    let certs = root.join("certs");
    gen_lab_certs(&certs);
    let cfg = build_mtls_server_config(
        &certs.join("vault-server.crt"),
        &certs.join("vault-server.key"),
        &certs.join("ca.crt"),
    )
    .expect("build_mtls_server_config");
    assert!(!cfg.alpn_protocols.is_empty());
}

#[test]
fn mtls_runtime_boots_in_lab_visualize() {
    let root = tempfile_dir("mtls-runtime");
    let certs = root.join("certs");
    let data = root.join("data");
    gen_lab_certs(&certs);
    let cfg = lab_mtls_cfg("127.0.0.1:0", &certs, &data);
    assert!(cfg.validate_hygiene().is_ok());
    let runtime = VaultRuntime::build(cfg).expect("VaultRuntime::build with mTLS");
    assert_eq!(runtime.auth.mode_name(), "mtls");
    assert!(!runtime.auth.is_static_token());
    assert!(runtime.auth.authorize(None).is_ok());
    assert!(runtime.auth.authorize(Some("token")).is_err());
}

#[tokio::test]
async fn mtls_axum_health_requires_client_cert() {
    let root = tempfile_dir("mtls-serve");
    let certs = root.join("certs");
    let data = root.join("data");
    gen_lab_certs(&certs);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);

    let cfg = lab_mtls_cfg(&addr.to_string(), &certs, &data);
    let runtime = Arc::new(VaultRuntime::build(cfg).expect("runtime"));
    let app = build_router(runtime.clone());

    let (cert, key, ca) = runtime.config.require_mtls_paths().unwrap();
    let server_config = build_mtls_server_config(Path::new(cert), Path::new(key), Path::new(ca)).unwrap();
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let acceptor =
        kerosene_vault::adapters::PeerCertAcceptor::new(axum_server::tls_rustls::RustlsAcceptor::new(rustls_config));

    let serve = tokio::spawn(async move {
        axum_server::bind(addr).acceptor(acceptor).serve(app.into_make_service()).await.expect("serve");
    });

    // Wait briefly for bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client_pem = concat_pem(&certs.join("vault-client.crt"), &certs.join("vault-client.key"));
    let identity = reqwest::Identity::from_pem(&client_pem).expect("client identity");
    let ca_cert = reqwest::Certificate::from_pem(&std::fs::read(certs.join("ca.crt")).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let url = format!("https://{addr}/v1/health");
    let resp = client.get(&url).send().await.expect("health with client cert");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("vault-mtls-1") || body.contains("ready") || body.contains("status"));

    // No client cert → handshake / request must fail.
    let plain = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(certs.join("ca.crt")).unwrap()).unwrap())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let no_cert = plain.get(&url).send().await;
    assert!(no_cert.is_err(), "expected TLS failure without client cert, got {no_cert:?}");

    serve.abort();
}

fn concat_pem(cert: &Path, key: &Path) -> Vec<u8> {
    let mut out = std::fs::read(cert).unwrap();
    out.push(b'\n');
    out.extend(std::fs::read(key).unwrap());
    out
}

fn tempfile_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kerosene-vault-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn rotate_lab_mtls_refreshes_spiffe_tree_and_java_materials() {
    let root = tempfile_dir("mtls-rotate");
    let certs = root.join("certs");
    gen_lab_certs(&certs);

    let before = std::fs::read(certs.join("vault-client.crt")).expect("client crt");
    assert!(certs.join("spiffe/kfe/svid.pem").is_file());
    assert!(certs.join("vault-client.pkcs8.key").is_file());
    assert!(certs.join("kfe-client.p12").is_file());

    let status = Command::new("bash")
        .env("VAULT_LAB_MTLS_OUT", &certs)
        .env("VAULT_LAB_MTLS_TTL_HOURS", "24")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/rotate_lab_mtls_certs.sh"))
        .status()
        .expect("run rotate_lab_mtls_certs.sh");
    assert!(status.success(), "rotation failed: {status}");

    let after = std::fs::read(certs.join("vault-client.crt")).expect("rotated client crt");
    assert_ne!(before, after, "leaf cert should change on rotation");
    assert!(certs.join("rotation.json").is_file());
    let meta = std::fs::read_to_string(certs.join("rotation.json")).unwrap();
    assert!(meta.contains("spiffe://kerosene.lab/kfe"));
    // `rotation.json` points `trust_bundle` at a separate temp output directory
    // used during trust-bundle regeneration (not necessarily `VAULT_LAB_MTLS_OUT`).
    assert!(meta.contains("\"trust_bundle\": \""));
    assert!(meta.contains("/spiffe/trust-bundle.pem"));
    assert!(certs.join("spiffe/vault/vault-1/svid.pem").is_file());
    assert!(certs.join("spiffe/trust-bundle.pem").is_file());
}

#[allow(dead_code)]
fn _addr_type_check(a: SocketAddr) -> SocketAddr {
    a
}
