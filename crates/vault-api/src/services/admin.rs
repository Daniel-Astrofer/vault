//! Admin read-only service for local vault introspection.
//!
//! All methods are idempotent and never mutate state. Responses use the
//! canonical kerosene-contracts types where available.
//!
//! # Security
//! - NO share, nonce, passphrase, seed, private key, or private certificate
//!   is ever included in any response.
//! - Server-side authorization is enforced by the caller (admin API middleware).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kerosene_contracts::{
    AdminErrorEnvelopeV1, AuditReferenceV1, DiscoveryPlane, NodeAdminStatusV1, VaultAdminStatusV1,
    ADMIN_CONTRACT_VERSION,
};

use crate::application::ports::PeerDirectoryPort;
use crate::bootstrap::VaultRuntime;

/// Read-only administrative service for vault introspection.
///
/// Constructed with a reference to the fully initialized `VaultRuntime`.
/// Each method returns the appropriate contract type or JSON value.
#[derive(Clone)]
pub struct AdminService {
    runtime: Arc<VaultRuntime>,
}

impl AdminService {
    pub fn new(runtime: Arc<VaultRuntime>) -> Self {
        Self { runtime }
    }

    /// Returns a reference to the underlying runtime (for admin API handlers).
    pub fn runtime(&self) -> &Arc<VaultRuntime> {
        &self.runtime
    }

    /// Local vault status and financial readiness.
    pub fn status(&self, request_id: &str) -> VaultAdminStatusV1 {
        let online = self.runtime.online.online_count();
        let t = self.runtime.threshold.group().t;
        VaultAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.to_string(),
            request_id: request_id.to_string(),
            local_ready: true,
            financial_ready: online >= t,
            node_id: self.runtime.config.node_id.as_str().to_string(),
            ceremony_mode: self.runtime.config.ceremony_mode.as_str().to_string(),
            bitcoin_network: self.runtime.config.bitcoin_network.as_str().to_string(),
        }
    }

    /// Node health and version.
    pub fn health(&self, request_id: &str) -> NodeAdminStatusV1 {
        let online = self.runtime.online.online_count();
        let t = self.runtime.threshold.group().t;
        NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.to_string(),
            request_id: request_id.to_string(),
            network_id: self.runtime.config.node_id.as_str().to_string(),
            plane: DiscoveryPlane::Vault,
            local_ready: true,
            member_ready: online > 0,
            quorum_ready: online >= t,
            financial_ready: online >= t,
            live_members: online as u64,
            threshold: t as u16,
        }
    }

    /// Observed roster and quorum information.
    ///
    /// Returns genesis roster members, threshold parameters, and peer/liveness
    /// counts. NO share identifiers, nonces, or key material are exposed.
    pub fn roster(&self, request_id: &str) -> serde_json::Value {
        let online = self.runtime.online.online_count();
        let group = self.runtime.threshold.group();
        let peers = self.runtime.peers.list_peers().ok();
        let peer_count = peers.as_ref().map(|p| p.len()).unwrap_or(0);

        let genesis: Vec<String> = self.runtime.genesis_roster.iter().map(|n| n.as_str().to_string()).collect();

        serde_json::json!({
            "contract_version": ADMIN_CONTRACT_VERSION,
            "request_id": request_id,
            "node_id": self.runtime.config.node_id.as_str(),
            "genesis_roster": genesis,
            "n": group.n,
            "t": group.t,
            "online": online,
            "peer_count": peer_count,
            "threshold_met": online >= group.t,
        })
    }

    /// Ceremony state inspection.
    ///
    /// Returns ceremony parameters and installation status of cryptographic
    /// material. NO shares, nonces, passphrases, or private keys are exposed.
    pub fn ceremony(&self, request_id: &str) -> serde_json::Value {
        let group = self.runtime.threshold.group();

        serde_json::json!({
            "contract_version": ADMIN_CONTRACT_VERSION,
            "request_id": request_id,
            "ceremony_mode": self.runtime.config.ceremony_mode.as_str(),
            "dkg_mode": self.runtime.config.dkg_mode.as_str(),
            "attestation_mode": self.runtime.config.attestation_mode.as_str(),
            "tee_available": self.runtime.config.tee_available,
            "node_tier": self.runtime.config.node_tier.as_str(),
            "n": group.n,
            "t": group.t,
            "online": self.runtime.online.online_count(),
            "genesis_members": self.runtime.genesis_roster.len(),
            "frost_installed": self.runtime.frost.is_some(),
            "frost_tr_installed": self.runtime.frost_tr.is_some(),
            "frost_tr_channels_installed": self.runtime.frost_tr_channels.is_some(),
            "bitcoin_network": self.runtime.config.bitcoin_network.as_str(),
            "auth_mode": self.runtime.config.auth_mode.as_str(),
            "share_store_mode": self.runtime.config.share_store_mode.as_str(),
            "hardened": self.runtime.config.hardened,
            "open_economy": self.runtime.config.open_economy,
        })
    }

    /// Protocol and release compatibility.
    ///
    /// Returns the contract version, enabled features, and signing scheme
    /// information for compatibility checks.
    pub fn compatibility(&self, request_id: &str) -> serde_json::Value {
        let features = build_feature_list();

        serde_json::json!({
            "contract_version": ADMIN_CONTRACT_VERSION,
            "request_id": request_id,
            "admin_api_version": "0.1.0",
            "node_id": self.runtime.config.node_id.as_str(),
            "ceremony_mode": self.runtime.config.ceremony_mode.as_str(),
            "node_tier": self.runtime.config.node_tier.as_str(),
            "attestation_mode": self.runtime.config.attestation_mode.as_str(),
            "dkg_mode": self.runtime.config.dkg_mode.as_str(),
            "signing_scheme": "frost-secp256k1",
            "bitcoin_network": self.runtime.config.bitcoin_network.as_str(),
            "features": features,
            "transport": self.runtime.config.transport.as_str(),
        })
    }

    /// Audit reference and request ID.
    ///
    /// Generates an opaque audit event identifier tied to the caller's
    /// request ID. Never contains PII or secret material.
    pub fn audit_reference(&self, request_id: &str) -> AuditReferenceV1 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let event_id = format!("vault-admin-{now:x}-{}", rand_byte_prefix());

        AuditReferenceV1 { event_id, request_id: request_id.to_string(), occurred_at: iso_timestamp() }
    }
}

/// Build a consistent error envelope response.
pub fn admin_error(request_id: &str, code: &str, message: impl std::fmt::Display) -> AdminErrorEnvelopeV1 {
    AdminErrorEnvelopeV1 {
        contract_version: ADMIN_CONTRACT_VERSION.to_string(),
        code: code.to_string(),
        message: message.to_string(),
        request_id: request_id.to_string(),
        details: serde_json::Value::Null,
    }
}

/// Generate a request ID from the X-Request-Id header or a fallback.
pub fn resolve_request_id(header_value: Option<&str>) -> String {
    header_value
        .and_then(|v| {
            let trimmed = v.trim();
            if !trimmed.is_empty() && trimmed.len() <= 128 {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(fallback_request_id)
}

fn fallback_request_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("vault-admin-{now:x}")
}

fn rand_byte_prefix() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    hex::encode(&now.to_le_bytes()[..4])
}

fn iso_timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    let (year, month, day) = days_to_date(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", year, month, day, hours, minutes, seconds, nanos / 1_000_000)
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn build_feature_list() -> Vec<&'static str> {
    let mut f = Vec::new();
    if cfg!(feature = "production") {
        f.push("production");
    }
    if cfg!(feature = "dealer_lab") {
        f.push("dealer_lab");
    }
    if cfg!(feature = "hybrid") {
        f.push("hybrid");
    }
    if cfg!(feature = "tee_hw") {
        f.push("tee_hw");
    }
    if cfg!(feature = "tpm") {
        f.push("tpm");
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_to_date_epoch() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_date_known() {
        // 2026-07-30 ≈ 20669 days since epoch
        let days = 20669;
        let (y, m, d) = days_to_date(days);
        assert_eq!(y, 2026);
        assert_eq!(m, 7);
        assert_eq!(d, 30);
    }

    #[test]
    fn request_id_from_header() {
        let id = resolve_request_id(Some("my-req-42"));
        assert_eq!(id, "my-req-42");
    }

    #[test]
    fn request_id_fallback() {
        let id = resolve_request_id(None);
        assert!(id.starts_with("vault-admin-"));
    }

    #[test]
    fn request_id_rejects_empty() {
        let id = resolve_request_id(Some(""));
        assert!(id.starts_with("vault-admin-"));
    }

    #[test]
    fn request_id_rejects_oversized() {
        let long = "a".repeat(200);
        let id = resolve_request_id(Some(&long));
        assert!(id.starts_with("vault-admin-"));
    }

    #[test]
    fn admin_error_envelope_format() {
        let env = admin_error("req-1", "ERR_TEST", "something went wrong");
        assert_eq!(env.contract_version, ADMIN_CONTRACT_VERSION);
        assert_eq!(env.code, "ERR_TEST");
        assert_eq!(env.message, "something went wrong");
        assert_eq!(env.request_id, "req-1");
    }

    #[test]
    fn iso_timestamp_format() {
        let ts = iso_timestamp();
        assert!(ts.len() >= 24, "timestamp too short: {ts}");
        assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
        assert_eq!(&ts[4..5], "-", "expected date separator: {ts}");
        assert_eq!(&ts[7..8], "-", "expected date separator: {ts}");
        assert_eq!(&ts[10..11], "T", "expected T separator: {ts}");
    }

    #[test]
    fn feature_list_basic() {
        let features = build_feature_list();
        assert!(features.iter().all(|f| !f.is_empty()));
    }
}
