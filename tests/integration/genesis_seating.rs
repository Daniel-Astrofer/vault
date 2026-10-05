//! Genesis seating wired into runtime ledger + DKG roster (production-native path).

use kerosene_vault::bootstrap::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig, VaultRuntime};
use kerosene_vault::domain::{AttestationMode, BitcoinNetwork, NodeId, ResharePolicy, VaultNodeTier};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn lab_mtls_certs() -> &'static PathBuf {
    static CERTS: OnceLock<PathBuf> = OnceLock::new();

    CERTS.get_or_init(|| {
        let unique =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let certs = std::env::temp_dir().join(format!("kerosene-vault-genesis-mtls-{}-{unique}", std::process::id()));
        let output = Command::new("bash")
            .env("VAULT_LAB_MTLS_OUT", &certs)
            .env("VAULT_MTLS_NODE_IDS", "vault-home,vault-1,vault-zzz")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/lab/gen_mtls_certs.sh"))
            .output()
            .expect("run lab mTLS certificate generator");
        assert!(
            output.status.success(),
            "lab mTLS certificate generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        certs
    })
}

fn base_lab(node_id: &str) -> VaultConfig {
    // The runtime persists a share-store to `data_dir`; ensure it exists to avoid
    // filesystem rename failures on fresh test runs.
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let data_dir = std::env::temp_dir().join(format!("kerosene-vault-test-data-{}-{}", std::process::id(), unique));
    let _ = fs::create_dir_all(&data_dir);
    let node_certs = lab_mtls_certs().join("nodes").join(node_id);
    VaultConfig {
        node_id: NodeId::new(node_id).unwrap(),
        node_tier: VaultNodeTier::Domestic,
        tee_available: false,
        attestation_mode: AttestationMode::Sim,
        listen_addr: "127.0.0.1:0".into(),
        lab_root: format!("lab-seat-{}", std::process::id()),
        seed_peers: vec![
            ("vault-epyc".into(), "127.0.0.1:7702".into()),
            ("vault-home-2".into(), "127.0.0.1:7703".into()),
        ],
        peer_tiers: BTreeMap::from([("vault-epyc".into(), VaultNodeTier::Sev)]),
        peer_tier_quotes: std::collections::BTreeMap::new(),
        peer_tier_require_quote: false,
        refuse_sim: false,
        genesis_n: Some(2),
        online_count: Some(2),
        online_static: false,
        psbt_policy: kerosene_vault::domain::PsbtPolicy::lab_defaults(),
        lab_timelock_scale: 0,
        lab_timelock_env_set: false,
        lab_council_n: 2,
        lab_min_rebuilds: 1,
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
        tls_cert_path: Some(node_certs.join("server.crt").display().to_string()),
        tls_key_path: Some(node_certs.join("server.key").display().to_string()),
        tls_client_ca_path: Some(lab_mtls_certs().join("ca.crt").display().to_string()),
        tls_client_cert_path: Some(node_certs.join("client.crt").display().to_string()),
        tls_client_key_path: Some(node_certs.join("client.key").display().to_string()),
        tls_verify_policy: kerosene_vault::adapters::TlsPeerVerifyPolicy::Hostname,
        audit_key_allowlist: kerosene_vault::adapters::MeshAuditKeyAllowlist::empty(),
        share_store_mode: ShareStoreMode::AeadDisk,
        share_passphrase: Some("pass".into()),
        share_tpm_seal: false,
        share_tpm_stub: false,
        share_tpm_clear_fallback: false,
        secure_boot_pcr_policy: None,
        // set below from unique test dir
        anti_nonce_shared_dir: None,
        measurement_pin_hex: None,
        dealer_requested: false,
        dkg_mode: DkgMode::DistributedWire,
        reshare_policy: ResharePolicy::Manual,
        governance_reward_sats: 0,
        governance_reward_bps: 0,
        transport: kerosene_vault::adapters::VaultTransport::Clearnet,
        peer_http: kerosene_vault::adapters::PeerHttpSettings::clearnet_defaults(),
        clearnet_publish: false,
        admin_unix_socket_path: None,
        data_dir: Some(data_dir.display().to_string()),
    }
}

#[test]
fn runtime_seats_sev_before_domestic_for_genesis_roster() {
    let rt = VaultRuntime::build(base_lab("vault-home")).expect("build");
    let ids: Vec<_> = rt.genesis_roster.iter().map(|n| n.as_str()).collect();
    assert_eq!(ids, vec!["vault-epyc", "vault-home"]);
    let health = rt.get_health.execute().unwrap();
    assert_eq!(health.node_tier, "domestic");
    assert!(!health.tee_available);
    assert_eq!(health.genesis_roster, vec!["vault-epyc", "vault-home"]);
}

#[test]
fn all_domestic_genesis_seats_normally() {
    let mut cfg = base_lab("vault-1");
    cfg.seed_peers = vec![("vault-2".into(), "127.0.0.1:7702".into()), ("vault-3".into(), "127.0.0.1:7703".into())];
    cfg.peer_tiers.clear();
    cfg.genesis_n = Some(3);
    cfg.online_count = Some(3);
    let rt = VaultRuntime::build(cfg).unwrap();
    assert_eq!(rt.genesis_roster.len(), 3);
    assert_eq!(rt.genesis_roster[0].as_str(), "vault-1");
}

#[test]
fn unseated_local_node_fails_closed() {
    let mut cfg = base_lab("vault-zzz");
    // Local is lowest priority domestic; SEV + another domestic fill n=2.
    cfg.seed_peers =
        vec![("vault-epyc".into(), "127.0.0.1:7702".into()), ("vault-aaa".into(), "127.0.0.1:7703".into())];
    cfg.peer_tiers = BTreeMap::from([("vault-epyc".into(), VaultNodeTier::Sev)]);
    cfg.genesis_n = Some(2);
    let err = match VaultRuntime::build(cfg) {
        Ok(_) => panic!("expected seating fail-closed"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("not seated"), "expected seating fail-closed, got {msg}");
}
