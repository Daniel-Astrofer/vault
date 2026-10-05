use std::collections::BTreeMap;
use std::fs;

use crate::adapters::{
    detect_tee_devices, peer_addr_is_onion, MeshAuditKeyAllowlist, PeerHttpSettings, TlsPeerVerifyPolicy,
    VaultTransport,
};
use crate::domain::{
    resolve_node_tier, seat_genesis_by_tier, AttestationMode, BitcoinNetwork, DomainError, GovernanceRewardConfig,
    NodeId, ResharePolicy, SeatingCandidate, VaultNodeTier,
};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Deployment ceremony profile controlling allowed security features.
pub enum CeremonyMode {
    /// Local development and explicitly lab-only settings.
    Lab,
    /// Pre-production validation with production-like authentication requirements.
    Staging,
    /// Hardened production ceremony.
    Production,
}

impl CeremonyMode {
    /// Parses a ceremony mode name, accepting `prod` as a production alias.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "lab" => Some(Self::Lab),
            "staging" => Some(Self::Staging),
            "production" | "prod" => Some(Self::Production),
            _ => None,
        }
    }

    /// Returns the canonical lowercase profile name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lab => "lab",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// API authentication mechanism selected for the Vault service.
pub enum AuthMode {
    /// Static shared token authentication, restricted to lab configurations.
    StaticToken,
    /// Mutual TLS identity authentication.
    MutualTls,
}

impl AuthMode {
    /// Parses token and mTLS aliases, ignoring case and surrounding whitespace.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "static" | "token" | "static_token" => Some(Self::StaticToken),
            "mtls" | "mutual_tls" => Some(Self::MutualTls),
            _ => None,
        }
    }

    /// Returns the canonical configuration label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticToken => "static_token",
            Self::MutualTls => "mtls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Persistence and protection strategy for secret shares.
pub enum ShareStoreMode {
    /// Host-disk AEAD store using a passphrase-derived encryption key.
    AeadDisk,
    /// TEE-backed seal store that fails closed when no supported hardware path exists.
    TeeSeal,
}

/// DKG path selection. Dealer is lab-only (`dealer_lab` feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgMode {
    /// Trusted-dealer single-process (lab visualize only).
    DealerLab,
    /// Multi-round FROST DKG without dealer — in-process N-party sim (lab/single-node).
    Distributed,
    /// Multi-round FROST DKG over HTTP between vault peers (no dealer).
    DistributedWire,
}

impl DkgMode {
    /// Parses supported dealer, in-process distributed, and wire DKG aliases.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dealer" | "dealer_lab" => Some(Self::DealerLab),
            "distributed" | "dkg_distributed" => Some(Self::Distributed),
            "distributed_wire" | "wire" | "over_wire" => Some(Self::DistributedWire),
            _ => None,
        }
    }

    /// Returns the canonical DKG mode name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DealerLab => "dealer_lab",
            Self::Distributed => "distributed",
            Self::DistributedWire => "distributed_wire",
        }
    }

    /// Reports whether this mode uses dealerless distributed key generation.
    pub fn is_distributed(self) -> bool {
        matches!(self, Self::Distributed | Self::DistributedWire)
    }
}

impl ShareStoreMode {
    /// Parses the AEAD disk and TEE-seal mode aliases.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "aead" | "disk" | "aead_disk" => Some(Self::AeadDisk),
            "tee" | "tee_seal" => Some(Self::TeeSeal),
            _ => None,
        }
    }

    /// Returns the canonical share-store mode name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AeadDisk => "aead_disk",
            Self::TeeSeal => "tee_seal",
        }
    }
}

#[derive(Debug, Clone)]
/// Validated runtime configuration assembled from environment variables.
pub struct VaultConfig {
    /// Stable identifier for this Vault node.
    pub node_id: NodeId,
    /// Honest hardware tier (`domestic` | `sev` | `sgx`).
    pub node_tier: VaultNodeTier,
    /// True when a TEE guest/enclave device node is present (not the same as TPM).
    pub tee_available: bool,
    /// Attestation mechanism used by this node.
    pub attestation_mode: AttestationMode,
    /// Local network socket address used by the service listener.
    pub listen_addr: String,
    /// Attestation root material; must be explicitly configured outside lab.
    pub lab_root: String,
    /// Configured seed peer ID and endpoint pairs.
    pub seed_peers: Vec<(String, String)>,
    /// Optional per-peer tier overlay (`VAULT_PEER_TIERS=id=sev,...`); default domestic.
    pub peer_tiers: BTreeMap<String, VaultNodeTier>,
    /// Attestation quote blobs proving elevated `VAULT_PEER_TIERS` claims
    /// (`VAULT_PEER_TIER_QUOTES=id=hex,...`). Required outside lab for sev/sgx seating.
    pub peer_tier_quotes: BTreeMap<String, String>,
    /// When true (default outside lab), TEE peer tiers without quotes are seated as domestic.
    pub peer_tier_require_quote: bool,
    /// Whether simulation attestation modes are rejected.
    pub refuse_sim: bool,
    /// Explicit genesis n; defaults to len(local+seeds) when unset.
    pub genesis_n: Option<usize>,
    /// Online vaults for fail-stop (lab ceiling). Defaults to genesis_n.
    /// When peers are configured, probed liveness is used unless `VAULT_ONLINE_STATIC=1`.
    pub online_count: Option<usize>,
    /// Lab-only: skip peer health probe and use `online_count` / n as StaticOnlineCount.
    pub online_static: bool,
    /// PSBT fee / locktime / RBF policy (High #13).
    pub psbt_policy: crate::domain::PsbtPolicy,
    /// Lab: scales NORMAL release timelock (`0` = immediate).
    pub lab_timelock_scale: u64,
    /// True when `LAB_TIMELOCK_SCALE` env was present (forbidden in hardened builds).
    pub lab_timelock_env_set: bool,
    /// Lab council size for release personal quorum.
    pub lab_council_n: usize,
    /// Minimum independent rebuilds before cosign.
    pub lab_min_rebuilds: usize,
    /// Production / staging / refuse-sim: lock lab-only HTTP and flags (§13.5 / F8).
    pub hardened: bool,
    /// Staging-only TEE stub quotes (never for production ceremony).
    pub attestation_staging_stub: bool,
    /// Ceremony profile used to enforce production/staging hygiene.
    pub ceremony_mode: CeremonyMode,
    /// `VAULT_ECONOMY=open` enables live p%=1% miner splits (F9); default lab dry-run.
    pub open_economy: bool,
    /// `VAULT_MINER_PAYOUT_CADENCE=manual|daily|weekly|epoch` (gate only; no auto scheduler).
    pub miner_payout_cadence: crate::domain::MinerPayoutCadence,
    /// `VAULT_MINER_PAYOUT_FREQUENCY=daily|weekly|epoch` (constitution-level mesh default).
    /// Override at genesis; subsequent changes require quorum amendment. Default: daily.
    pub miner_payout_frequency: crate::domain::MinerPayoutCadence,
    /// `VAULT_SEATING_POLICY` — TEE admission timeout in hours for post-genesis seating.
    /// After timeout, domestic nodes may be admitted as fallback. Default: 24h.
    pub seating_policy_timeout_hours: u64,
    /// Bitcoin network used for addresses and transaction validation.
    pub bitcoin_network: BitcoinNetwork,
    /// API authentication mode.
    pub auth_mode: AuthMode,
    /// Optional legacy token value; production mTLS configuration leaves this unset.
    pub vault_token: Option<String>,
    /// Explicit USERS withdraw destinations (`VAULT_USERS_DESTINATION_ALLOWLIST`, comma-separated).
    /// Soft "any parseable address" is refused — destinations must be listed here and/or lab defaults.
    pub users_destination_allowlist: Vec<String>,
    /// Explicit MINERS payout destinations (`VAULT_MINERS_DESTINATION_ALLOWLIST`).
    /// Open-economy gate admits registered eligible operators + this list — never the Intent dest alone.
    pub miners_destination_allowlist: Vec<String>,
    /// Allow `POST /v1/reshare/trigger` outside lab (`VAULT_ALLOW_MANUAL_RESHARE=1`).
    pub allow_manual_reshare: bool,
    /// Lab-only: permit raw `/v1/bitcoin/sign-sighash` (`VAULT_LAB_ALLOW_RAW_SIGHASH=1`).
    pub lab_allow_raw_sighash: bool,
    /// PEM server certificate (`VAULT_TLS_CERT_PATH`) — required when `auth_mode=mtls`.
    pub tls_cert_path: Option<String>,
    /// PEM server private key (`VAULT_TLS_KEY_PATH`) — required when `auth_mode=mtls`.
    pub tls_key_path: Option<String>,
    /// PEM client CA bundle (`VAULT_TLS_CLIENT_CA_PATH`) — required when `auth_mode=mtls`.
    pub tls_client_ca_path: Option<String>,
    /// PEM client certificate for outbound peer calls (`VAULT_TLS_CLIENT_CERT_PATH`) — mTLS peer DKG.
    pub tls_client_cert_path: Option<String>,
    /// PEM client private key for outbound peer calls (`VAULT_TLS_CLIENT_KEY_PATH`) — mTLS peer DKG.
    pub tls_client_key_path: Option<String>,
    /// Outbound peer server-cert verify (`VAULT_TLS_VERIFY_MODE`): hostname | spiffe | onion_or_spiffe.
    pub tls_verify_policy: TlsPeerVerifyPolicy,
    /// F8 mesh audit pubkey allowlist (≠ release ≠ settlement). See `docs/AUDIT_KEYS.md`.
    pub audit_key_allowlist: MeshAuditKeyAllowlist,
    /// Selected secret-share storage backend.
    pub share_store_mode: ShareStoreMode,
    /// Optional passphrase used by disk AEAD storage.
    pub share_passphrase: Option<String>,
    /// Wrap AEAD passphrase with TPM seal (`VAULT_SHARE_TPM_SEAL=1`). Off by default.
    pub share_tpm_seal: bool,
    /// Lab mock TPM seal (`VAULT_SHARE_TPM_STUB=1`); refused when hardened/production.
    pub share_tpm_stub: bool,
    /// Lab-only clear passphrase if TPM unavailable (`VAULT_SHARE_TPM_CLEAR_FALLBACK=1`).
    pub share_tpm_clear_fallback: bool,
    /// Path to expected TPM PCR policy file (`VAULT_SECURE_BOOT_PCR_POLICY`).
    /// Used to verify measured boot chain integrity before unsealing shares.
    pub secure_boot_pcr_policy: Option<String>,
    /// Share / anti-nonce disk root (`VAULT_DATA_DIR`); lab default under `lab_root`.
    pub data_dir: Option<String>,
    /// Deprecated/ignored: anti-nonce uses quorum HTTP prepare among `VAULT_SEED_PEERS`
    /// (`VAULT_ANTI_NONCE_SHARED_DIR` kept for env back-compat only).
    pub anti_nonce_shared_dir: Option<String>,
    /// Optional hex measurement pin (`VAULT_MEASUREMENT_PIN`); else constitution hash pin.
    pub measurement_pin_hex: Option<String>,
    /// Request dealer DKG (only honored when `dealer_lab` feature is compiled).
    pub dealer_requested: bool,
    /// Explicit DKG mode (`VAULT_DKG_MODE`).
    pub dkg_mode: DkgMode,
    /// FROST reshare cadence (`VAULT_RESHARE_POLICY=daily|manual`).
    pub reshare_policy: ResharePolicy,
    /// Fixed sats bounty per governance job (`VAULT_GOVERNANCE_REWARD_SATS`).
    pub governance_reward_sats: u64,
    /// Optional bps of current miner pool added to job bounty (`VAULT_GOVERNANCE_REWARD_BPS`).
    pub governance_reward_bps: u32,
    /// Mesh transport: `clearnet` (lab LAN) or `tor` (SOCKS → onion peers).
    pub transport: VaultTransport,
    /// Outbound HTTP settings for peer DKG / anti-nonce (SOCKS, timeouts, retries).
    pub peer_http: PeerHttpSettings,
    /// Explicit clearnet publish flag — refused for production ceremony over Tor.
    pub clearnet_publish: bool,
    /// Optional Unix domain socket path for the admin API
    /// (`VAULT_ADMIN_UNIX_SOCKET`, e.g. `/run/kerosene/vault-admin.sock`).
    pub admin_unix_socket_path: Option<String>,
}

impl VaultConfig {
    /// Loads environment variables, applies production defaults, and validates security hygiene.
    ///
    /// Missing required identity/root settings and forbidden legacy or lab-only
    /// flags return configuration errors instead of silently weakening policy.
    pub fn from_env() -> Result<Self, DomainError> {
        let node_id = NodeId::new(
            std::env::var("VAULT_NODE_ID")
                .map_err(|_| DomainError::AttestationRejected("VAULT_NODE_ID is required".into()))?,
        )?;

        let tier_raw = std::env::var("VAULT_NODE_TIER").ok();
        let (node_tier, tee_available) = resolve_node_tier(tier_raw.as_deref(), detect_tee_devices())?;

        let kerosene_env = std::env::var("KEROSENE_ENV").unwrap_or_else(|_| "production".into());
        if !kerosene_env.eq_ignore_ascii_case("production") {
            return Err(DomainError::LabFlagForbidden(
                "KEROSENE_ENV must be production; alternate runtime profiles were removed".into(),
            ));
        }
        let refuse_sim = true;
        let hardened = true;
        if std::env::var_os("ATTESTATION_STAGING_STUB").is_some() {
            return Err(DomainError::LabFlagForbidden("ATTESTATION_STAGING_STUB was removed".into()));
        }
        let attestation_staging_stub = false;

        let ceremony_raw = std::env::var("VAULT_CEREMONY_MODE").unwrap_or_else(|_| "production".into());
        if !ceremony_raw.eq_ignore_ascii_case("production") {
            return Err(DomainError::LabFlagForbidden(
                "VAULT_CEREMONY_MODE must be production; alternate ceremony modes were removed".into(),
            ));
        }
        let ceremony_mode = CeremonyMode::Production;

        let mode_default = match node_tier {
            VaultNodeTier::Domestic if matches!(ceremony_mode, CeremonyMode::Lab) && !hardened => "sim",
            VaultNodeTier::Domestic => "software",
            VaultNodeTier::Sev => "sev",
            VaultNodeTier::Sgx => "sgx",
        };
        let mode_raw = std::env::var("ATTESTATION_MODE").unwrap_or_else(|_| mode_default.to_string());
        let attestation_mode = AttestationMode::parse(&mode_raw)
            .ok_or_else(|| DomainError::AttestationRejected(format!("unknown ATTESTATION_MODE={mode_raw}")))?;

        let listen_default = "127.0.0.1:7701";
        let listen_addr = std::env::var("VAULT_LISTEN_ADDR").unwrap_or_else(|_| listen_default.into());
        if std::env::var_os("LAB_ATTESTATION_ROOT").is_some() {
            return Err(DomainError::LabFlagForbidden(
                "LAB_ATTESTATION_ROOT was removed; configure VAULT_ATTESTATION_ROOT".into(),
            ));
        }
        let lab_root = std::env::var("VAULT_ATTESTATION_ROOT")
            .map_err(|_| DomainError::AttestationRejected("VAULT_ATTESTATION_ROOT is required".into()))?;

        let node_directory_configured = std::env::var_os("VAULT_KEROSENE_NODE_URL").is_some();
        let mut seed_peers =
            if node_directory_configured { discover_vault_peers_from_node(false)? } else { Vec::new() };
        if !node_directory_configured {
            let raw = std::env::var("VAULT_SEED_PEERS").unwrap_or_default();
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (id, addr) = part
                    .split_once('=')
                    .ok_or_else(|| DomainError::AttestationRejected(format!("bad VAULT_SEED_PEERS entry: {part}")))?;
                seed_peers.push((id.trim().to_string(), addr.trim().to_string()));
            }
        }

        let mut peer_tiers = BTreeMap::new();
        if let Ok(raw) = std::env::var("VAULT_PEER_TIERS") {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (id, tier_s) = part
                    .split_once('=')
                    .ok_or_else(|| DomainError::AttestationRejected(format!("bad VAULT_PEER_TIERS entry: {part}")))?;
                let tier = VaultNodeTier::parse(tier_s).ok_or_else(|| {
                    DomainError::AttestationRejected(format!("unknown tier in VAULT_PEER_TIERS: {tier_s}"))
                })?;
                peer_tiers.insert(id.trim().to_string(), tier);
            }
        }
        let mut peer_tier_quotes = BTreeMap::new();
        if let Ok(raw) = std::env::var("VAULT_PEER_TIER_QUOTES") {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (id, quote) = part.split_once('=').ok_or_else(|| {
                    DomainError::AttestationRejected(format!("bad VAULT_PEER_TIER_QUOTES entry: {part}"))
                })?;
                peer_tier_quotes.insert(id.trim().to_string(), quote.trim().to_string());
            }
        }
        let peer_tier_require_quote = true;
        if matches!(std::env::var("VAULT_PEER_TIER_REQUIRE_QUOTE").as_deref(), Ok("0" | "false" | "no")) {
            return Err(DomainError::AttestationRejected("VAULT_PEER_TIER_REQUIRE_QUOTE cannot be disabled".into()));
        }

        let genesis_n = match std::env::var("VAULT_GENESIS_N") {
            Ok(raw) => {
                let value = raw
                    .parse::<usize>()
                    .map_err(|_| DomainError::ThresholdError("VAULT_GENESIS_N must be the integer 3".into()))?;
                if value != 3 {
                    return Err(DomainError::ThresholdError(
                        "the production Vault constitution is fixed to three members with threshold two".into(),
                    ));
                }
                Some(3)
            }
            Err(_) => Some(3),
        };
        if std::env::var_os("VAULT_ONLINE_COUNT").is_some() || std::env::var_os("VAULT_ONLINE_STATIC").is_some() {
            return Err(DomainError::LabFlagForbidden(
                "static online counts were removed; quorum readiness comes from authenticated peers".into(),
            ));
        }
        let online_count = None;
        let online_static = false;
        let mut psbt_policy = crate::domain::PsbtPolicy::lab_defaults();
        if let Ok(s) = std::env::var("VAULT_PSBT_MAX_FEE_SATS") {
            if let Ok(n) = s.parse::<u64>() {
                psbt_policy.max_fee_sats = n;
            }
        }
        if let Ok(s) = std::env::var("VAULT_PSBT_MAX_FEE_RATE_SAT_VB") {
            if let Ok(n) = s.parse::<u64>() {
                psbt_policy.max_fee_rate_sat_vb = n;
            }
        }
        if let Ok(s) = std::env::var("VAULT_PSBT_MAX_LOCKTIME") {
            if let Ok(n) = s.parse::<u32>() {
                psbt_policy.max_locktime = n;
            }
        }
        if let Ok(s) = std::env::var("VAULT_PSBT_RBF_POLICY") {
            if let Some(p) = crate::domain::RbfPolicy::parse(&s) {
                psbt_policy.rbf = p;
            }
        }
        let forbidden_release_env = ["LAB_TIMELOCK_SCALE", "LAB_COUNCIL_N", "LAB_MIN_REBUILDS"]
            .into_iter()
            .find(|name| std::env::var_os(name).is_some());
        if let Some(name) = forbidden_release_env {
            return Err(DomainError::LabFlagForbidden(format!("{name} was removed")));
        }
        let lab_timelock_env_set = false;
        let lab_timelock_scale = 1;
        let lab_council_n = 3;
        let lab_min_rebuilds = 3;
        let open_economy = matches!(std::env::var("VAULT_ECONOMY").as_deref(), Ok("open" | "OPEN" | "v1_open"));
        let miner_payout_cadence = std::env::var("VAULT_MINER_PAYOUT_CADENCE")
            .ok()
            .and_then(|s| crate::domain::MinerPayoutCadence::parse(&s))
            .unwrap_or(crate::domain::MinerPayoutCadence::Manual);

        let miner_payout_frequency = std::env::var("VAULT_MINER_PAYOUT_FREQUENCY")
            .ok()
            .and_then(|s| crate::domain::MinerPayoutCadence::parse(&s))
            .unwrap_or(crate::domain::MinerPayoutCadence::Daily);

        let seating_policy_timeout_hours =
            std::env::var("VAULT_SEATING_POLICY").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(24);

        let btc_raw = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet3".into());
        let bitcoin_network = BitcoinNetwork::parse(&btc_raw)
            .ok_or_else(|| DomainError::BitcoinNetworkMismatch(format!("unknown BITCOIN_NETWORK={btc_raw}")))?;
        if bitcoin_network != BitcoinNetwork::Testnet3 {
            return Err(DomainError::BitcoinNetworkMismatch(
                "the production runtime is fixed to BITCOIN_NETWORK=testnet3".into(),
            ));
        }

        let users_destination_allowlist = std::env::var("VAULT_USERS_DESTINATION_ALLOWLIST")
            .ok()
            .map(|raw| raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>())
            .unwrap_or_default();
        let miners_destination_allowlist = std::env::var("VAULT_MINERS_DESTINATION_ALLOWLIST")
            .ok()
            .map(|raw| raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>())
            .unwrap_or_default();
        let allow_manual_reshare = env_flag("VAULT_ALLOW_MANUAL_RESHARE");
        if std::env::var_os("VAULT_LAB_ALLOW_RAW_SIGHASH").is_some() {
            return Err(DomainError::LabFlagForbidden("raw sighash signing was removed".into()));
        }
        let lab_allow_raw_sighash = false;

        let auth_raw = std::env::var("VAULT_AUTH_MODE").unwrap_or_else(|_| "mtls".into());
        let auth_mode = AuthMode::parse(&auth_raw)
            .ok_or_else(|| DomainError::AuthRejected(format!("unknown VAULT_AUTH_MODE={auth_raw}")))?;
        if auth_mode != AuthMode::MutualTls {
            return Err(DomainError::AuthRejected("VAULT_AUTH_MODE must be mtls".into()));
        }
        if std::env::var_os("VAULT_API_TOKEN").is_some() || std::env::var_os("VAULT_TOKEN").is_some() {
            return Err(DomainError::AuthRejected("static Vault tokens were removed; use mTLS identity".into()));
        }
        let vault_token = None;
        let tls_cert_path = env_nonempty_first(&["VAULT_TLS_CERT_PATH"]);
        let tls_key_path = env_nonempty_first(&["VAULT_TLS_KEY_PATH"]);
        let tls_client_ca_path = env_nonempty_first(&["VAULT_TLS_CLIENT_CA_PATH"]);
        let tls_client_cert_path = env_nonempty_first(&["VAULT_TLS_CLIENT_CERT_PATH"]);
        let tls_client_key_path = env_nonempty_first(&["VAULT_TLS_CLIENT_KEY_PATH"]);

        let store_raw = std::env::var("VAULT_SHARE_STORE").unwrap_or_else(|_| match node_tier {
            VaultNodeTier::Domestic => "aead_disk".into(),
            VaultNodeTier::Sev | VaultNodeTier::Sgx if hardened => "tee_seal".into(),
            VaultNodeTier::Sev | VaultNodeTier::Sgx => "aead_disk".into(),
        });
        let share_store_mode = ShareStoreMode::parse(&store_raw)
            .ok_or_else(|| DomainError::ShareStoreForbidden(format!("unknown VAULT_SHARE_STORE={store_raw}")))?;
        // Lab P0: VAULT_DATA_PASSPHRASE (preferred); VAULT_SHARE_PASSPHRASE legacy alias.
        let share_passphrase = env_nonempty_first(&["VAULT_DATA_PASSPHRASE", "VAULT_SHARE_PASSPHRASE"]);
        let share_tpm_seal = env_flag("VAULT_SHARE_TPM_SEAL");
        let share_tpm_stub = env_flag("VAULT_SHARE_TPM_STUB");
        let share_tpm_clear_fallback = env_flag("VAULT_SHARE_TPM_CLEAR_FALLBACK");
        let secure_boot_pcr_policy = env_nonempty_first(&["VAULT_SECURE_BOOT_PCR_POLICY"]);
        let data_dir = env_nonempty_first(&["VAULT_DATA_DIR"]);
        let anti_nonce_shared_dir = env_nonempty_first(&["VAULT_ANTI_NONCE_SHARED_DIR"]);
        let measurement_pin_hex = env_nonempty_first(&["VAULT_MEASUREMENT_PIN"]);

        if std::env::var_os("VAULT_DKG").is_some() {
            return Err(DomainError::LabFlagForbidden(
                "VAULT_DKG alias was removed; only distributed_wire is supported".into(),
            ));
        }
        let dkg_raw = std::env::var("VAULT_DKG_MODE").unwrap_or_else(|_| "distributed_wire".into());
        let dkg_mode = DkgMode::parse(&dkg_raw)
            .ok_or_else(|| DomainError::AttestationRejected(format!("unknown VAULT_DKG_MODE={dkg_raw}")))?;
        if dkg_mode != DkgMode::DistributedWire {
            return Err(DomainError::DealerForbidden("VAULT_DKG_MODE must be distributed_wire".into()));
        }
        let dealer_requested = false;
        let reshare_policy = match std::env::var("VAULT_RESHARE_POLICY") {
            Ok(raw) => ResharePolicy::parse(&raw).ok_or_else(|| {
                DomainError::InvalidConstitution(format!("unknown VAULT_RESHARE_POLICY={raw} (want daily|manual)"))
            })?,
            Err(_) => ResharePolicy::Manual,
        };
        let governance_reward_sats =
            std::env::var("VAULT_GOVERNANCE_REWARD_SATS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let governance_reward_bps =
            std::env::var("VAULT_GOVERNANCE_REWARD_BPS").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

        let transport_raw = std::env::var("VAULT_TRANSPORT").unwrap_or_else(|_| "tor".into());
        let transport = VaultTransport::parse(&transport_raw)
            .ok_or_else(|| DomainError::AttestationRejected(format!("unknown VAULT_TRANSPORT={transport_raw}")))?;
        if !transport.is_tor() {
            return Err(DomainError::LabFlagForbidden("VAULT_TRANSPORT must be tor".into()));
        }

        let mut peer_http =
            if transport.is_tor() { PeerHttpSettings::tor_defaults() } else { PeerHttpSettings::clearnet_defaults() };
        peer_http.transport = transport;
        if let Some(socks) = env_nonempty_first(&["VAULT_SOCKS_PROXY", "VAULT_TOR_SOCKS"]) {
            peer_http.socks_proxy = Some(PeerHttpSettings::normalize_socks_proxy(&socks));
        } else if !transport.is_tor() {
            peer_http.socks_proxy = None;
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_TIMEOUT_SECS") {
            if let Ok(secs) = s.parse::<u64>() {
                peer_http.timeout = Duration::from_secs(secs.max(1));
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_CONNECT_TIMEOUT_SECS") {
            if let Ok(secs) = s.parse::<u64>() {
                peer_http.connect_timeout = Duration::from_secs(secs.max(1));
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_MAX_RETRIES") {
            if let Ok(n) = s.parse::<u32>() {
                peer_http.max_retries = n.max(1);
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_RETRY_BASE_MS") {
            if let Ok(ms) = s.parse::<u64>() {
                peer_http.retry_base_ms = ms;
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_RETRY_JITTER_MS") {
            if let Ok(ms) = s.parse::<u64>() {
                peer_http.retry_jitter_ms = ms;
            }
        }
        let clearnet_publish = env_flag("VAULT_CLEARNET_PUBLISH");
        let admin_unix_socket_path = env_nonempty_first(&["VAULT_ADMIN_UNIX_SOCKET"]);
        let tls_verify_policy = resolve_tls_verify_policy(transport, node_id.as_str(), &seed_peers)?;
        let audit_key_allowlist = MeshAuditKeyAllowlist::from_env()?;

        let cfg = Self {
            node_id,
            node_tier,
            tee_available,
            attestation_mode,
            listen_addr,
            lab_root,
            seed_peers,
            peer_tiers,
            peer_tier_quotes,
            peer_tier_require_quote,
            refuse_sim,
            genesis_n,
            online_count,
            online_static,
            psbt_policy,
            lab_timelock_scale,
            lab_timelock_env_set,
            lab_council_n,
            lab_min_rebuilds,
            hardened,
            attestation_staging_stub,
            ceremony_mode,
            open_economy,
            miner_payout_cadence,
            miner_payout_frequency,
            seating_policy_timeout_hours,
            bitcoin_network,
            auth_mode,
            vault_token,
            users_destination_allowlist,
            miners_destination_allowlist,
            allow_manual_reshare,
            lab_allow_raw_sighash,
            tls_cert_path,
            tls_key_path,
            tls_client_ca_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_verify_policy,
            audit_key_allowlist,
            share_store_mode,
            share_passphrase,
            share_tpm_seal,
            share_tpm_stub,
            share_tpm_clear_fallback,
            secure_boot_pcr_policy,
            data_dir,
            anti_nonce_shared_dir,
            measurement_pin_hex,
            dealer_requested,
            dkg_mode,
            reshare_policy,
            governance_reward_sats,
            governance_reward_bps,
            transport,
            peer_http,
            clearnet_publish,
            admin_unix_socket_path,
        };
        cfg.validate_hygiene()?;
        Ok(cfg)
    }

    /// Builds the domain reward configuration from the two configured reward values.
    pub fn governance_reward_config(&self) -> GovernanceRewardConfig {
        GovernanceRewardConfig {
            reward_sats: self.governance_reward_sats,
            reward_bps_of_pool: self.governance_reward_bps,
        }
    }

    /// Rejects laboratory attestation modes when simulation is forbidden.
    pub fn validate_attestation_policy(&self) -> Result<(), DomainError> {
        if self.refuse_sim && self.attestation_mode.is_lab_only() {
            return Err(DomainError::SimAttestationForbidden);
        }
        Ok(())
    }

    /// Prod/staging refuse: sim, lab timelock env, dealer, static token, fake TEE claims.
    /// Domestic AEAD + software attestation is allowed; staging stub and sev-without-HW are not.
    /// Validates the combined attestation, ceremony, DKG, storage, auth, and network policy.
    pub fn validate_hygiene(&self) -> Result<(), DomainError> {
        self.validate_attestation_policy()?;
        if self.hardened {
            if self.attestation_mode.is_lab_only() {
                return Err(DomainError::LabFlagForbidden("ATTESTATION_MODE=sim".into()));
            }
            if self.lab_timelock_env_set {
                return Err(DomainError::LabFlagForbidden("LAB_TIMELOCK_SCALE".into()));
            }
        }
        if self.ceremony_mode == CeremonyMode::Production && self.attestation_staging_stub {
            return Err(DomainError::LabFlagForbidden("ATTESTATION_STAGING_STUB in production ceremony".into()));
        }
        if cfg!(feature = "production") && self.attestation_staging_stub {
            return Err(DomainError::LabFlagForbidden(
                "ATTESTATION_STAGING_STUB refused under production feature".into(),
            ));
        }
        if matches!(self.ceremony_mode, CeremonyMode::Staging | CeremonyMode::Production)
            && self.attestation_mode.is_lab_only()
        {
            return Err(DomainError::LabFlagForbidden("ATTESTATION_MODE=sim".into()));
        }

        // Honest tier / mode: refuse advertising SEV/SGX without HW (stub is staging-only).
        self.validate_tee_claims()?;

        // High #14: production software ceremony should pin measurement (honest, stronger).
        if self.ceremony_mode == CeremonyMode::Production
            && self.attestation_mode == AttestationMode::Software
            && self.measurement_pin_hex.is_none()
        {
            return Err(DomainError::AttestationRejected(
                "production ATTESTATION_MODE=software requires VAULT_MEASUREMENT_PIN (software ≠ TEE; pin binds measurement)"
                    .into(),
            ));
        }

        if matches!(self.ceremony_mode, CeremonyMode::Staging | CeremonyMode::Production) {
            if self.dealer_requested {
                return Err(DomainError::DealerForbidden("dealer DKG refused in staging/production (ToB 2024)".into()));
            }
            if !matches!(self.dkg_mode, DkgMode::DistributedWire) {
                return Err(DomainError::DealerForbidden(
                    "staging/production ceremony requires VAULT_DKG_MODE=distributed_wire (real FROST over-wire; not dealer or in-process sim)".into(),
                ));
            }
            if self.auth_mode == AuthMode::StaticToken {
                return Err(DomainError::AuthRejected("static token refused in staging/production; use mTLS".into()));
            }
            // F8: production ceremony requires mesh audit pubkey allowlist (≠ release ≠ settlement).
            // Ops dry-run before keygen: VAULT_SKIP_AUDIT_KEYS_CHECK=1 (forbidden for go-live).
            if self.ceremony_mode == CeremonyMode::Production
                && self.audit_key_allowlist.is_empty()
                && !env_flag("VAULT_SKIP_AUDIT_KEYS_CHECK")
            {
                return Err(DomainError::AuthRejected(
                    "production ceremony requires mesh audit keys (VAULT_AUDIT_PUBKEY_ALLOWLIST or VAULT_AUDIT_PUBKEYS_PATH); audit ≠ release ≠ settlement — see docs/AUDIT_KEYS.md"
                        .into(),
                ));
            }
            if self.share_store_mode == ShareStoreMode::AeadDisk && self.node_tier.is_tee() {
                return Err(DomainError::TeeRequired(
                    "TEE-tier node requires VAULT_SHARE_STORE=tee_seal (not host AEAD)".into(),
                ));
            }
        }
        if self.auth_mode == AuthMode::MutualTls {
            self.require_mtls_paths()?;
            self.require_mtls_client_identity()?;
        }
        self.validate_tpm_seal_hygiene()?;
        self.validate_transport_hygiene()?;
        self.validate_listen_bind()?;
        self.validate_lab_passphrase_defaults()?;
        self.validate_lab_root_honesty()?;
        Ok(())
    }

    /// Staging/production must not default-bind all interfaces (#27).
    pub fn validate_listen_bind(&self) -> Result<(), DomainError> {
        let addr = self.listen_addr.trim();
        let is_all = addr.starts_with("0.0.0.0") || addr.starts_with("[::]");
        let protected_staging_bind = self.ceremony_mode == CeremonyMode::Staging
            && self.auth_mode == AuthMode::MutualTls
            && !self.clearnet_publish;
        if is_all && (self.ceremony_mode == CeremonyMode::Production || (self.hardened && !protected_staging_bind)) {
            return Err(DomainError::LabFlagForbidden(
                "VAULT_LISTEN_ADDR all-interface bind requires staging mTLS with no clearnet publish; production requires loopback/onion-only"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Default share passphrase only in lab ceremony (#22).
    pub fn validate_lab_passphrase_defaults(&self) -> Result<(), DomainError> {
        let using_default =
            self.share_passphrase.as_deref().map(|p| p == "kerosene-vault-lab-passphrase").unwrap_or(true);
        if using_default
            && self.share_store_mode == ShareStoreMode::AeadDisk
            && !matches!(self.ceremony_mode, CeremonyMode::Lab)
        {
            return Err(DomainError::ShareStoreForbidden(
                "VAULT_DATA_PASSPHRASE required outside lab (no default passphrase)".into(),
            ));
        }
        if using_default
            && self.share_store_mode == ShareStoreMode::AeadDisk
            && (self.hardened || cfg!(feature = "production"))
        {
            return Err(DomainError::ShareStoreForbidden(
                "default lab passphrase refused under hardened/production".into(),
            ));
        }
        Ok(())
    }

    /// Default `LAB_ATTESTATION_ROOT` is lab-only deterministic DKG entropy (#17).
    pub fn validate_lab_root_honesty(&self) -> Result<(), DomainError> {
        if self.lab_root == "kerosene-lab-root" && !matches!(self.ceremony_mode, CeremonyMode::Lab) {
            return Err(DomainError::LabFlagForbidden(
                "LAB_ATTESTATION_ROOT must be set explicitly outside lab (default is deterministic lab DKG entropy)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// TPM seal optional for domestic AEAD. Stub/clear-fallback lab-only. TPM ≠ SEV.
    pub fn validate_tpm_seal_hygiene(&self) -> Result<(), DomainError> {
        if self.share_tpm_clear_fallback {
            if self.hardened || matches!(self.ceremony_mode, CeremonyMode::Production) || cfg!(feature = "production") {
                return Err(DomainError::LabFlagForbidden("VAULT_SHARE_TPM_CLEAR_FALLBACK".into()));
            }
            if !self.share_tpm_seal {
                return Err(DomainError::ShareStoreForbidden(
                    "VAULT_SHARE_TPM_CLEAR_FALLBACK requires VAULT_SHARE_TPM_SEAL=1".into(),
                ));
            }
        }
        if self.share_tpm_stub {
            if matches!(self.ceremony_mode, CeremonyMode::Staging | CeremonyMode::Production)
                || cfg!(feature = "production")
            {
                return Err(DomainError::LabFlagForbidden("VAULT_SHARE_TPM_STUB refused outside lab".into()));
            }
            if self.hardened {
                return Err(DomainError::LabFlagForbidden("VAULT_SHARE_TPM_STUB".into()));
            }
            if !self.share_tpm_seal {
                return Err(DomainError::ShareStoreForbidden(
                    "VAULT_SHARE_TPM_STUB requires VAULT_SHARE_TPM_SEAL=1".into(),
                ));
            }
        }
        if self.share_tpm_seal && self.share_store_mode != ShareStoreMode::AeadDisk {
            return Err(DomainError::ShareStoreForbidden(
                "VAULT_SHARE_TPM_SEAL applies only to VAULT_SHARE_STORE=aead_disk (TEE uses tee_seal; TPM ≠ SEV)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Production ceremony requires private Tor mesh (onion peers + SOCKS); refuse clearnet publish.
    /// Staging/production Tor also requires mTLS (lab Tor smoke may keep static_token).
    pub fn validate_transport_hygiene(&self) -> Result<(), DomainError> {
        if self.transport.is_tor() {
            let socks = self.peer_http.socks_proxy.as_deref().unwrap_or("");
            if socks.is_empty() {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_TRANSPORT=tor requires VAULT_SOCKS_PROXY (e.g. socks5h://127.0.0.1:9050)".into(),
                ));
            }
            for (id, addr) in &self.seed_peers {
                if !peer_addr_is_onion(addr) {
                    return Err(DomainError::AttestationRejected(format!(
                        "VAULT_TRANSPORT=tor requires onion VAULT_SEED_PEERS (peer {id}={addr})"
                    )));
                }
            }
            if matches!(self.ceremony_mode, CeremonyMode::Staging | CeremonyMode::Production)
                && self.auth_mode != AuthMode::MutualTls
            {
                return Err(DomainError::AuthRejected(
                    "VAULT_TRANSPORT=tor under staging/production requires VAULT_AUTH_MODE=mtls (static_token refused)"
                        .into(),
                ));
            }
            if self.auth_mode == AuthMode::MutualTls && matches!(self.tls_verify_policy, TlsPeerVerifyPolicy::Hostname)
            {
                return Err(DomainError::AuthRejected(
                    "VAULT_TRANSPORT=tor with mTLS requires VAULT_TLS_VERIFY_MODE=onion_or_spiffe|spiffe (not hostname-only)"
                        .into(),
                ));
            }
        }

        if self.ceremony_mode == CeremonyMode::Production {
            if !self.transport.is_tor() {
                return Err(DomainError::LabFlagForbidden(
                    "production ceremony requires VAULT_TRANSPORT=tor (private Tor mesh; not clearnet LAN)".into(),
                ));
            }
            if self.auth_mode != AuthMode::MutualTls {
                return Err(DomainError::AuthRejected("production ceremony requires VAULT_AUTH_MODE=mtls".into()));
            }
            if self.clearnet_publish {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_CLEARNET_PUBLISH refused in production ceremony (do not expose vault ports on clearnet)"
                        .into(),
                ));
            }
            let isolated_future_roster = self.seed_peers.is_empty() && self.genesis_n.unwrap_or_default() >= 3;
            if self.seed_peers.len() != 2 && !isolated_future_roster {
                return Err(DomainError::AttestationRejected(
                    "production requires exactly two remote VAULT_SEED_PEERS for the fixed 2-of-3 quorum, or an explicit VAULT_GENESIS_N >= 3 for isolated bootstrap".into(),
                ));
            }
        }
        Ok(())
    }

    /// Refuse fake SEV/SGX claims: no device and no staging stub (stub never in production).
    pub fn validate_tee_claims(&self) -> Result<(), DomainError> {
        if self.node_tier.is_domestic() && self.attestation_mode.is_tee() {
            return Err(DomainError::AttestationRejected(
                "domestic tier cannot advertise ATTESTATION_MODE=sev|sgx (use software)".into(),
            ));
        }
        let claims_tee = self.node_tier.is_tee() || self.attestation_mode.is_tee();
        if !claims_tee {
            return Ok(());
        }
        if self.attestation_staging_stub {
            if matches!(self.ceremony_mode, CeremonyMode::Production) || cfg!(feature = "production") {
                return Err(DomainError::LabFlagForbidden(
                    "ATTESTATION_STAGING_STUB cannot back a TEE claim in production".into(),
                ));
            }
            return Ok(());
        }
        if !self.tee_available {
            return Err(DomainError::AttestationRejected(
                "TEE claim (VAULT_NODE_TIER or ATTESTATION_MODE=sev|sgx) without HW device; use domestic/software or set ATTESTATION_STAGING_STUB=1 for staging only".into(),
            ));
        }
        if cfg!(feature = "production") && !cfg!(feature = "tee_hw") {
            return Err(DomainError::AttestationRejected(
                "production TEE claim requires --features tee_hw (or run domestic/software ceremony)".into(),
            ));
        }
        Ok(())
    }

    /// Returns the configured tier for a peer, defaulting to domestic when absent.
    pub fn peer_tier(&self, peer_id: &str) -> VaultNodeTier {
        let claimed = self.peer_tiers.get(peer_id).copied().unwrap_or(VaultNodeTier::Domestic);
        if !claimed.is_tee() {
            return claimed;
        }
        // High #15: refuse elevated seating without attestation quote proof.
        if self.peer_tier_require_quote {
            let has_quote = self.peer_tier_quotes.get(peer_id).map(|q| !q.trim().is_empty()).unwrap_or(false);
            if !has_quote {
                return VaultNodeTier::Domestic;
            }
        }
        claimed
    }

    /// Candidates for genesis seating: local + seed peers (pads added by caller if needed).
    pub fn seating_candidates(&self) -> Result<Vec<SeatingCandidate>, DomainError> {
        let mut candidates = vec![SeatingCandidate { id: self.node_id.clone(), tier: self.node_tier }];
        for (id, _) in &self.seed_peers {
            candidates.push(SeatingCandidate { id: NodeId::new(id.clone())?, tier: self.peer_tier(id) });
        }
        Ok(candidates)
    }

    /// Target genesis size (`VAULT_GENESIS_N` or local+seeds, min 2).
    pub fn effective_genesis_n(&self) -> usize {
        self.genesis_n.unwrap_or_else(|| self.seed_peers.len().saturating_add(1).max(2))
    }

    /// SEV-priority seating for genesis / wire DKG roster (§3.1).
    pub fn seat_genesis(&self) -> Result<Vec<NodeId>, DomainError> {
        let mut candidates = self.seating_candidates()?;
        let n = self.effective_genesis_n();
        while candidates.len() < n {
            candidates.push(SeatingCandidate {
                id: NodeId::new(format!("vault-pad-{}", candidates.len()))?,
                tier: VaultNodeTier::Domestic,
            });
        }
        Ok(seat_genesis_by_tier(&candidates, n))
    }

    /// Paths for rustls mTLS serve (`VAULT_TLS_*`).
    pub fn require_mtls_paths(&self) -> Result<(&str, &str, &str), DomainError> {
        let cert = self.tls_cert_path.as_deref().filter(|s| !s.is_empty());
        let key = self.tls_key_path.as_deref().filter(|s| !s.is_empty());
        let ca = self.tls_client_ca_path.as_deref().filter(|s| !s.is_empty());
        match (cert, key, ca) {
            (Some(c), Some(k), Some(a)) => Ok((c, k, a)),
            _ => Err(DomainError::AuthRejected(
                "mTLS requires VAULT_TLS_CERT_PATH, VAULT_TLS_KEY_PATH, and VAULT_TLS_CLIENT_CA_PATH".into(),
            )),
        }
    }

    /// Outbound peer client identity (`VAULT_TLS_CLIENT_CERT_PATH` / `VAULT_TLS_CLIENT_KEY_PATH`).
    pub fn require_mtls_client_identity(&self) -> Result<(&str, &str, &str), DomainError> {
        let cert = self.tls_client_cert_path.as_deref().filter(|s| !s.is_empty());
        let key = self.tls_client_key_path.as_deref().filter(|s| !s.is_empty());
        let ca = self.tls_client_ca_path.as_deref().filter(|s| !s.is_empty());
        match (cert, key, ca) {
            (Some(c), Some(k), Some(a)) => Ok((c, k, a)),
            _ => Err(DomainError::AuthRejected(
                "mTLS peer auth requires VAULT_TLS_CLIENT_CERT_PATH, VAULT_TLS_CLIENT_KEY_PATH, and VAULT_TLS_CLIENT_CA_PATH"
                    .into(),
            )),
        }
    }

    /// Returns the effective release timelock after applying lab scaling rules.
    pub fn effective_lab_timelock_scale(&self) -> u64 {
        if self.hardened {
            1
        } else {
            self.lab_timelock_scale
        }
    }

    /// Reports whether lab-only HTTP endpoints are enabled for this configuration.
    pub fn lab_endpoints_enabled(&self) -> bool {
        !self.hardened
    }

    /// Returns the effective token only when the selected authentication mode uses one.
    pub fn effective_vault_token(&self) -> Option<&str> {
        self.vault_token.as_deref().or(if matches!(self.ceremony_mode, CeremonyMode::Lab) && !self.hardened {
            // Compatibility fallback for isolated tests only. Production
            // configuration rejects static-token authentication.
            // Lab-only (#33): shared static token is by design for visualize.
            Some("kerosene-vault-lab-only")
        } else {
            None
        })
    }

    /// Lab AEAD passphrase default — never outside lab ceremony (#22).
    pub fn effective_share_passphrase(&self) -> Option<String> {
        if let Some(p) = self.share_passphrase.clone() {
            return Some(p);
        }
        if matches!(self.ceremony_mode, CeremonyMode::Lab) && !self.hardened {
            Some("kerosene-vault-lab-passphrase".into())
        } else {
            None
        }
    }

    /// Resolves the configured data directory or its runtime default.
    pub fn effective_data_dir(&self) -> std::path::PathBuf {
        if let Some(dir) = self.data_dir.as_deref() {
            std::path::PathBuf::from(dir)
        } else {
            std::path::PathBuf::from(&self.lab_root).join("vault-data")
        }
    }

    /// Resolves the optional legacy shared anti-nonce directory setting.
    pub fn effective_anti_nonce_shared_dir(&self) -> Option<std::path::PathBuf> {
        self.anti_nonce_shared_dir.as_deref().map(std::path::PathBuf::from)
    }
}

#[derive(Debug, Deserialize)]
struct NodeMembershipManifest {
    network_id: String,
    plane: String,
    members: Vec<NodeManifestMember>,
}

#[derive(Debug, Deserialize)]
struct NodeManifestMember {
    member_id: String,
    endpoint: String,
}

fn discover_vault_peers_from_node(staging_allows_empty: bool) -> Result<Vec<(String, String)>, DomainError> {
    let base = std::env::var("VAULT_KEROSENE_NODE_URL")
        .map_err(|_| DomainError::AttestationRejected("VAULT_KEROSENE_NODE_URL is required".into()))?;
    let identity_path = std::env::var("VAULT_KEROSENE_NODE_CLIENT_IDENTITY_PEM").map_err(|_| {
        DomainError::AuthRejected("VAULT_KEROSENE_NODE_CLIENT_IDENTITY_PEM is required for Node mTLS".into())
    })?;
    let ca_path = std::env::var("VAULT_KEROSENE_NODE_CA_PATH")
        .map_err(|_| DomainError::AuthRejected("VAULT_KEROSENE_NODE_CA_PATH is required for Node mTLS".into()))?;
    let identity = reqwest::Identity::from_pem(
        &fs::read(&identity_path).map_err(|error| DomainError::AuthRejected(format!("read Node identity: {error}")))?,
    )
    .map_err(|error| DomainError::AuthRejected(format!("parse Node identity: {error}")))?;
    let ca = reqwest::Certificate::from_pem(
        &fs::read(&ca_path).map_err(|error| DomainError::AuthRejected(format!("read Node CA: {error}")))?,
    )
    .map_err(|error| DomainError::AuthRejected(format!("parse Node CA: {error}")))?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .identity(identity)
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| DomainError::AuthRejected(format!("build Node client: {error}")))?;
    let endpoint = format!("{}/v1/membership/current", base.trim_end_matches('/'));
    let response = client
        .get(endpoint)
        .send()
        .map_err(|error| DomainError::AttestationRejected(format!("Node discovery failed: {error}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND
        && (staging_allows_empty || env_flag("VAULT_KEROSENE_NODE_ALLOW_EMPTY"))
    {
        return Ok(Vec::new());
    }
    let response = response
        .error_for_status()
        .map_err(|error| DomainError::AttestationRejected(format!("Node membership unavailable: {error}")))?;
    let manifest: NodeMembershipManifest = response
        .json()
        .map_err(|error| DomainError::AttestationRejected(format!("invalid Node membership response: {error}")))?;
    let expected_network = std::env::var("VAULT_KEROSENE_NETWORK_ID").unwrap_or_else(|_| "kerosene-staging".into());
    if manifest.network_id != expected_network || manifest.plane != "vault" {
        return Err(DomainError::AttestationRejected("Node membership network or plane mismatch".into()));
    }
    let local_member = std::env::var("VAULT_KEROSENE_NODE_MEMBER_ID").unwrap_or_default();
    let service_port = std::env::var("VAULT_KEROSENE_SERVICE_PORT")
        .unwrap_or_else(|_| "7801".into())
        .parse::<u16>()
        .map_err(|_| DomainError::AttestationRejected("invalid VAULT_KEROSENE_SERVICE_PORT".into()))?;

    manifest
        .members
        .into_iter()
        .filter(|member| member.member_id != local_member)
        .map(|member| {
            vault_service_endpoint(&member.endpoint, service_port).map(|endpoint| (member.member_id, endpoint))
        })
        .collect()
}

fn vault_service_endpoint(node_endpoint: &str, service_port: u16) -> Result<String, DomainError> {
    let mut endpoint = reqwest::Url::parse(node_endpoint)
        .map_err(|_| DomainError::AttestationRejected("Node returned an invalid endpoint".into()))?;
    let host = endpoint.host_str().unwrap_or_default();
    let onion_label = host.strip_suffix(".onion").unwrap_or_default();
    let is_v3_onion = onion_label.len() == 56
        && onion_label.bytes().all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte));
    if endpoint.scheme() != "https"
        || !is_v3_onion
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(DomainError::AttestationRejected("Node returned a non-onion Vault member".into()));
    }
    endpoint.set_path("");
    endpoint
        .set_port(Some(service_port))
        .map_err(|_| DomainError::AttestationRejected("could not derive Vault service port".into()))?;
    Ok(endpoint.to_string().trim_end_matches('/').into())
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "TRUE" | "yes" | "YES"))
}

fn env_nonempty_first(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn resolve_tls_verify_policy(
    transport: VaultTransport,
    node_id: &str,
    seed_peers: &[(String, String)],
) -> Result<TlsPeerVerifyPolicy, DomainError> {
    let trust = env_nonempty_first(&["VAULT_MTLS_TRUST_DOMAIN"]).unwrap_or_else(|| "kerosene.lab".into());
    // Explicit override: comma-separated SPIFFE allowlist (unique per vault / SPIRE).
    let allowed = if let Some(raw) = env_nonempty_first(&["VAULT_TLS_PEER_SPIFFE_ID", "VAULT_MTLS_SPIFFE_VAULT"]) {
        raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>()
    } else {
        // Unique per-vault SPIFFE by default (#23): local + seed peers + shared lab alias.
        let mut ids = vec![format!("spiffe://{trust}/vault/{node_id}")];
        for (peer_id, _) in seed_peers {
            ids.push(format!("spiffe://{trust}/vault/{peer_id}"));
        }
        ids.push(format!("spiffe://{trust}/vault/server"));
        ids.sort();
        ids.dedup();
        ids
    };
    let default_mode = if transport.is_tor() { "onion_or_spiffe" } else { "hostname" };
    let raw = std::env::var("VAULT_TLS_VERIFY_MODE").unwrap_or_else(|_| default_mode.into());
    TlsPeerVerifyPolicy::parse(&raw, &allowed).ok_or_else(|| {
        DomainError::AuthRejected(format!("unknown VAULT_TLS_VERIFY_MODE={raw} (or empty SPIFFE allowlist)"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_vault_service_from_verified_node_onion_host() {
        let onion = "a".repeat(56);
        let node = format!("https://{onion}.onion:8800");

        assert_eq!(vault_service_endpoint(&node, 7801).unwrap(), format!("https://{onion}.onion:7801"));
    }

    #[test]
    fn refuses_clearnet_or_malformed_node_member_endpoint() {
        assert!(vault_service_endpoint("https://vault.internal:8800", 7801).is_err());
        assert!(vault_service_endpoint("http://aaaaaaaa.onion:8800", 7801).is_err());
        assert!(vault_service_endpoint("https://aaaaaaaa.onion:8800", 7801).is_err());
    }

    fn base() -> VaultConfig {
        VaultConfig {
            node_id: NodeId::new("v1").unwrap(),
            node_tier: VaultNodeTier::Domestic,
            tee_available: false,
            attestation_mode: AttestationMode::Sim,
            listen_addr: "127.0.0.1:0".into(),
            lab_root: "x".into(),
            seed_peers: vec![],
            peer_tiers: BTreeMap::new(),
            peer_tier_quotes: BTreeMap::new(),
            peer_tier_require_quote: false,
            refuse_sim: false,
            genesis_n: None,
            online_count: None,
            online_static: false,
            psbt_policy: crate::domain::PsbtPolicy::lab_defaults(),
            lab_timelock_scale: 0,
            lab_timelock_env_set: false,
            lab_council_n: 3,
            lab_min_rebuilds: 3,
            hardened: false,
            attestation_staging_stub: false,
            ceremony_mode: CeremonyMode::Lab,
            open_economy: false,
            miner_payout_cadence: crate::domain::MinerPayoutCadence::Manual,
            miner_payout_frequency: crate::domain::MinerPayoutCadence::Daily,
            seating_policy_timeout_hours: 24,
            bitcoin_network: BitcoinNetwork::Testnet3,
            auth_mode: AuthMode::StaticToken,
            vault_token: Some("t".into()),
            users_destination_allowlist: vec![],
            miners_destination_allowlist: vec![],
            allow_manual_reshare: false,
            lab_allow_raw_sighash: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_verify_policy: TlsPeerVerifyPolicy::Hostname,
            audit_key_allowlist: MeshAuditKeyAllowlist::empty(),
            share_store_mode: ShareStoreMode::AeadDisk,
            share_passphrase: Some("pass".into()),
            share_tpm_seal: false,
            share_tpm_stub: false,
            share_tpm_clear_fallback: false,
            secure_boot_pcr_policy: None,
            data_dir: None,
            anti_nonce_shared_dir: None,
            measurement_pin_hex: None,
            dealer_requested: true,
            dkg_mode: DkgMode::DealerLab,
            reshare_policy: ResharePolicy::Manual,
            governance_reward_sats: 0,
            governance_reward_bps: 0,
            transport: VaultTransport::Clearnet,
            peer_http: PeerHttpSettings::clearnet_defaults(),
            clearnet_publish: false,
            admin_unix_socket_path: None,
        }
    }

    fn with_mtls_paths(mut cfg: VaultConfig) -> VaultConfig {
        cfg.tls_cert_path = Some("/lab/certs/vault-server.crt".into());
        cfg.tls_key_path = Some("/lab/certs/vault-server.key".into());
        cfg.tls_client_ca_path = Some("/lab/certs/ca.crt".into());
        cfg.tls_client_cert_path = Some("/lab/certs/vault-client.crt".into());
        cfg.tls_client_key_path = Some("/lab/certs/vault-client.key".into());
        cfg
    }

    fn with_tor_mesh(mut cfg: VaultConfig) -> VaultConfig {
        cfg.transport = VaultTransport::Tor;
        cfg.peer_http = PeerHttpSettings::tor_defaults();
        cfg.clearnet_publish = false;
        cfg.tls_verify_policy =
            TlsPeerVerifyPolicy::OnionOrSpiffe { allowed: vec!["spiffe://kerosene.lab/vault/server".into()] };
        cfg.audit_key_allowlist = MeshAuditKeyAllowlist::from_hex_list(["aa".repeat(32)]);
        cfg.seed_peers = vec![
            ("vault-2".into(), "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:7701".into()),
            ("vault-3".into(), "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:7701".into()),
        ];
        cfg.genesis_n = Some(3);
        cfg
    }

    fn with_audit_keys(mut cfg: VaultConfig) -> VaultConfig {
        cfg.audit_key_allowlist = MeshAuditKeyAllowlist::from_hex_list(["bb".repeat(32)]);
        cfg
    }

    #[test]
    fn hardened_rejects_sim() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.attestation_mode = AttestationMode::Sim;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::SimAttestationForbidden) | Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn hardened_rejects_lab_timelock_env() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.lab_timelock_env_set = true;
        cfg.ceremony_mode = CeremonyMode::Lab;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert_eq!(cfg.validate_hygiene(), Err(DomainError::LabFlagForbidden("LAB_TIMELOCK_SCALE".into())));
    }

    #[test]
    fn lab_allows_sim_and_zero_timelock() {
        let cfg = base();
        assert!(cfg.validate_hygiene().is_ok());
        assert_eq!(cfg.effective_lab_timelock_scale(), 0);
        assert!(cfg.lab_endpoints_enabled());
    }

    #[test]
    fn production_ceremony_rejects_staging_stub() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert_eq!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden("ATTESTATION_STAGING_STUB in production ceremony".into()))
        );
    }

    #[test]
    fn staging_allows_sev_with_stub() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Staging;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        if cfg!(feature = "production") {
            assert!(matches!(cfg.validate_hygiene(), Err(DomainError::LabFlagForbidden(_))));
        } else {
            assert!(cfg.validate_hygiene().is_ok());
        }
    }

    #[test]
    fn production_refuses_static_token_and_tee_disk_share() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.measurement_pin_hex = Some("aa".repeat(32));
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::StaticToken;
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::AuthRejected(_))));
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        // Production hygiene checks audit key allowlist first; ensure it's non-empty
        // so we hit the `TeeRequired` branch asserted below.
        cfg.audit_key_allowlist = MeshAuditKeyAllowlist::from_hex_list(["aa"]);
        let result = cfg.validate_hygiene();
        if cfg!(feature = "production") && !cfg!(feature = "tee_hw") {
            assert!(matches!(result, Err(DomainError::AttestationRejected(_))));
        } else {
            assert!(matches!(result, Err(DomainError::TeeRequired(_))));
        }
    }

    #[test]
    fn production_allows_domestic_software_and_aead() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.measurement_pin_hex = Some("aa".repeat(32));
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_software_requires_measurement_pin() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::AttestationRejected(_))));
        cfg.measurement_pin_hex = Some("bb".repeat(32));
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_requires_mesh_audit_keys() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.audit_key_allowlist = MeshAuditKeyAllowlist::empty();
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.measurement_pin_hex = Some("af".repeat(32));
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::AuthRejected(msg)) if msg.contains("audit keys")
        ));
        cfg = with_audit_keys(cfg);
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_allows_isolated_tor_bootstrap_with_explicit_future_roster() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg = with_audit_keys(cfg);
        cfg.seed_peers.clear();
        cfg.genesis_n = Some(3);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.measurement_pin_hex = Some("dd".repeat(32));

        assert!(cfg.validate_hygiene().is_ok());

        cfg.genesis_n = None;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::AttestationRejected(msg))
                if msg.contains("VAULT_GENESIS_N")
        ));
    }

    #[test]
    fn production_refuses_clearnet_transport() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_audit_keys(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.transport = VaultTransport::Clearnet;
        cfg.peer_http = PeerHttpSettings::clearnet_defaults();
        cfg.seed_peers = vec![("vault-2".into(), "vault-2:7701".into())];
        cfg.measurement_pin_hex = Some("cc".repeat(32));
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::LabFlagForbidden(_))));
    }

    #[test]
    fn production_refuses_clearnet_publish_flag() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.clearnet_publish = true;
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.measurement_pin_hex = Some("dd".repeat(32));
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::LabFlagForbidden(_))));
    }

    #[test]
    fn tor_transport_refuses_non_onion_peers() {
        let mut cfg = base();
        cfg.transport = VaultTransport::Tor;
        cfg.peer_http = PeerHttpSettings::tor_defaults();
        cfg.seed_peers = vec![("vault-2".into(), "vault-2:7701".into())];
        assert!(matches!(cfg.validate_transport_hygiene(), Err(DomainError::AttestationRejected(_))));
    }

    #[test]
    fn production_refuses_in_process_distributed_dkg() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        cfg.measurement_pin_hex = Some("ee".repeat(32));
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::DealerForbidden(_))));
    }

    #[test]
    fn seat_genesis_prefers_sev_peers() {
        let mut cfg = base();
        cfg.node_id = NodeId::new("vault-home").unwrap();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.seed_peers = vec![("vault-epyc".into(), "epyc:7701".into()), ("vault-home-2".into(), "h2:7701".into())];
        cfg.peer_tiers.insert("vault-epyc".into(), VaultNodeTier::Sev);
        cfg.genesis_n = Some(2);
        let seats = cfg.seat_genesis().unwrap();
        assert_eq!(seats.len(), 2);
        assert_eq!(seats[0].as_str(), "vault-epyc");
        assert_eq!(seats[1].as_str(), "vault-home");
    }

    #[test]
    fn production_rejects_sev_claim_without_hw() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.attestation_staging_stub = false;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::AttestationRejected(_))));
    }

    #[test]
    fn production_rejects_stub_as_sev() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.attestation_staging_stub = true;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::LabFlagForbidden(_))));
    }

    #[test]
    fn peer_tee_tier_without_quote_seats_as_domestic() {
        let mut cfg = base();
        cfg.peer_tiers.insert("vault-epyc".into(), VaultNodeTier::Sev);
        cfg.peer_tier_require_quote = true;
        assert_eq!(cfg.peer_tier("vault-epyc"), VaultNodeTier::Domestic);
        cfg.peer_tier_quotes.insert("vault-epyc".into(), "deadbeef".into());
        assert_eq!(cfg.peer_tier("vault-epyc"), VaultNodeTier::Sev);
    }

    #[test]
    fn domestic_cannot_advertise_sev_mode() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.tee_available = true;
        assert!(matches!(cfg.validate_tee_claims(), Err(DomainError::AttestationRejected(_))));
    }

    #[test]
    fn mtls_requires_tls_paths() {
        let mut cfg = base();
        cfg.auth_mode = AuthMode::MutualTls;
        assert!(matches!(cfg.validate_hygiene(), Err(DomainError::AuthRejected(_))));
        cfg = with_mtls_paths(cfg);
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn staging_and_production_still_refuse_static_token() {
        for mode in [CeremonyMode::Staging, CeremonyMode::Production] {
            let mut cfg = base();
            cfg.node_tier = VaultNodeTier::Domestic;
            cfg.attestation_mode = AttestationMode::Software;
            cfg.ceremony_mode = mode;
            cfg.refuse_sim = true;
            cfg.hardened = true;
            cfg.auth_mode = AuthMode::StaticToken;
            cfg.share_store_mode = ShareStoreMode::AeadDisk;
            cfg.dealer_requested = false;
            cfg.dkg_mode = DkgMode::DistributedWire;
            cfg.measurement_pin_hex = Some("ff".repeat(32));
            cfg.share_passphrase = Some("explicit-prod-pass".into());
            assert!(
                matches!(cfg.validate_hygiene(), Err(DomainError::AuthRejected(_))),
                "static_token must be refused in {:?}",
                mode
            );
        }
    }

    #[test]
    fn lab_allows_tpm_seal_stub() {
        let mut cfg = base();
        cfg.share_tpm_seal = true;
        cfg.share_tpm_stub = true;
        if cfg!(feature = "production") {
            assert!(matches!(cfg.validate_tpm_seal_hygiene(), Err(DomainError::LabFlagForbidden(_))));
        } else {
            assert!(cfg.validate_tpm_seal_hygiene().is_ok());
            assert!(cfg.validate_hygiene().is_ok());
        }
    }

    #[test]
    fn hardened_rejects_tpm_clear_fallback() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.share_tpm_seal = true;
        cfg.share_tpm_clear_fallback = true;
        assert!(matches!(cfg.validate_tpm_seal_hygiene(), Err(DomainError::LabFlagForbidden(_))));
    }

    #[test]
    fn tpm_seal_refused_for_tee_store() {
        let mut cfg = base();
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.share_tpm_seal = true;
        assert!(matches!(cfg.validate_tpm_seal_hygiene(), Err(DomainError::ShareStoreForbidden(_))));
    }
}
