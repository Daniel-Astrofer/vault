//! Authenticated mesh caller identity (app-layer principal).
//!
//! Binds verified mTLS leaf SPIFFE URI / DNS SAN → `VAULT_NODE_ID` + role
//! (`kfe` vs `vault`). Route authorization is by role — a CA leaf alone is not
//! full power. Lab `static_token` uses an omnipotent local principal.

use std::collections::HashSet;

use crate::domain::DomainError;

/// Mesh caller role derived from SPIFFE path / cert identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRole {
    /// Settlement / sign / Intent requestor (kfe).
    Kfe,
    /// Vault peer (DKG, day vote, anti-nonce, FROST co-sign).
    Vault,
}

impl MeshRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kfe => "kfe",
            Self::Vault => "vault",
        }
    }
}

/// Resolved app-layer principal after mTLS (or lab token) authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPrincipal {
    pub role: MeshRole,
    pub node_id: String,
    pub spiffe_id: Option<String>,
    /// Lab static_token: may call any protected route.
    pub lab_omnipotent: bool,
}

impl MeshPrincipal {
    pub fn lab_omnipotent(local_node_id: &str) -> Self {
        Self { role: MeshRole::Vault, node_id: local_node_id.to_string(), spiffe_id: None, lab_omnipotent: true }
    }

    pub fn allows_route(&self, class: RouteClass) -> bool {
        if self.lab_omnipotent {
            return true;
        }
        match class {
            RouteClass::KfeSettlement => matches!(self.role, MeshRole::Kfe),
            RouteClass::VaultPeer => matches!(self.role, MeshRole::Vault),
            RouteClass::SharedOps => matches!(self.role, MeshRole::Kfe | MeshRole::Vault),
            RouteClass::AdminRead => matches!(self.role, MeshRole::Vault),
        }
    }
}

/// Route classes for role authorization (Critical #3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    /// `/v1/sign`, `/v1/bitcoin/*`, `/v1/intent` (settlement).
    KfeSettlement,
    /// `/v1/dkg/*`, `/v1/day/vote`, peer prepare, FROST co-sign peer.
    VaultPeer,
    /// `/v1/day/advance`, `/v1/day/current`, `/v1/reshare/trigger`.
    SharedOps,
    /// Read-only administrative diagnostics. Never grants signing authority.
    AdminRead,
}

/// Map HTTP path to route class. Returns `None` for public / unclassified.
pub fn route_class_for_path(path: &str) -> Option<RouteClass> {
    let p = path.split('?').next().unwrap_or(path);
    if p.starts_with("/v1/admin/") {
        return Some(RouteClass::AdminRead);
    }
    if p.starts_with("/v1/sign")
        || p.starts_with("/v1/financial-quorum")
        || p.starts_with("/v1/bitcoin/")
        || (p.starts_with("/v1/intent") && !p.starts_with("/v1/intent/consume/"))
        || p.starts_with("/sign/")
        || p.starts_with("/intent/")
    {
        return Some(RouteClass::KfeSettlement);
    }
    if p.starts_with("/v1/dkg/")
        || p == "/v1/day/vote"
        || p.starts_with("/v1/anti-nonce/")
        || p.starts_with("/v1/intent/consume/")
        || p.starts_with("/v1/frost/")
    {
        return Some(RouteClass::VaultPeer);
    }
    if p == "/v1/day/advance"
        || p == "/v1/day/current"
        || p == "/v1/reshare/trigger"
        || p.starts_with("/release/")
        || p.starts_with("/epoch/")
        || p == "/ledger"
        || p == "/threshold"
        || p.starts_with("/economy/")
        || p == "/health"
    {
        return Some(RouteClass::SharedOps);
    }
    None
}

/// Parse SPIFFE URI → role + optional vault node id from path.
///
/// Accepted shapes:
/// - `spiffe://{td}/kfe` → Kfe
/// - `spiffe://{td}/vault/{node_id}` → Vault + node_id
/// - `spiffe://{td}/vault/server` → Vault, node_id unresolved (use DNS SAN)
pub fn parse_spiffe_principal(uri: &str) -> Result<(MeshRole, Option<String>), DomainError> {
    let uri = uri.trim();
    if !uri.starts_with("spiffe://") {
        return Err(DomainError::AuthRejected(format!("not a SPIFFE URI: {uri}")));
    }
    let rest = &uri["spiffe://".len()..];
    let mut parts = rest.split('/');
    let _td = parts.next().unwrap_or("");
    let kind = parts.next().unwrap_or("");
    match kind {
        "kfe" => Ok((MeshRole::Kfe, Some("kfe".into()))),
        "vault" => {
            let leaf = parts.next().unwrap_or("");
            if leaf.is_empty() {
                return Err(DomainError::AuthRejected("SPIFFE vault path missing node segment".into()));
            }
            if leaf == "server" {
                Ok((MeshRole::Vault, None))
            } else {
                Ok((MeshRole::Vault, Some(leaf.to_string())))
            }
        }
        _ => Err(DomainError::AuthRejected(format!("unknown SPIFFE workload path: {uri}"))),
    }
}

/// Build principal from leaf cert URI SANs + DNS SANs.
///
/// Prefers SPIFFE URI. For `…/vault/server`, binds node id from a DNS SAN that
/// is in `allowed_vault_ids` (or equals `local_node_id`).
pub fn principal_from_cert_sans(
    uri_sans: &[String],
    dns_sans: &[String],
    local_node_id: &str,
    allowed_vault_ids: &HashSet<String>,
) -> Result<MeshPrincipal, DomainError> {
    let spiffe = uri_sans.iter().find(|u| u.starts_with("spiffe://")).cloned().ok_or_else(|| {
        DomainError::AuthRejected("client cert missing SPIFFE URI SAN (required for mesh principal)".into())
    })?;
    let (role, path_node) = parse_spiffe_principal(&spiffe)?;
    let node_id = match role {
        MeshRole::Kfe => path_node.unwrap_or_else(|| "kfe".into()),
        MeshRole::Vault => {
            if let Some(id) = path_node {
                if !allowed_vault_ids.contains(&id) && id != local_node_id {
                    return Err(DomainError::AuthRejected(format!("SPIFFE vault node {id} is not a known mesh node")));
                }
                id
            } else {
                // Generic vault/server SVID — bind via DNS SAN.
                let matched: Vec<_> = dns_sans
                    .iter()
                    .filter(|d| allowed_vault_ids.contains(d.as_str()) || d.as_str() == local_node_id)
                    .cloned()
                    .collect();
                match matched.as_slice() {
                    [one] => one.clone(),
                    [] => {
                        return Err(DomainError::AuthRejected(
                            "vault/server SVID has no DNS SAN matching a known VAULT_NODE_ID".into(),
                        ));
                    }
                    _ => {
                        return Err(DomainError::AuthRejected(
                            "vault/server SVID DNS SAN ambiguous among mesh node ids".into(),
                        ));
                    }
                }
            }
        }
    };
    Ok(MeshPrincipal { role, node_id, spiffe_id: Some(spiffe), lab_omnipotent: false })
}

/// Resolve the authenticated caller for mesh vote / gossip endpoints.
///
/// Priority:
/// 1. Verified `MeshPrincipal` from mTLS (when present)
/// 2. `mtls_peer_node_id` hook (compat header — only when principal absent)
/// 3. `X-Vault-Node-Id` header when it is in `allowed_node_ids` (lab static_token)
/// 4. `local_node_id` (kfe self-vote path under lab token)
///
/// Optional body `claimed` must match the resolved identity (anti-spoof).
pub fn resolve_mesh_caller_identity(
    local_node_id: &str,
    allowed_node_ids: &HashSet<String>,
    header_node_id: Option<&str>,
    claimed: Option<&str>,
    mtls_peer_node_id: Option<&str>,
) -> Result<String, DomainError> {
    resolve_mesh_caller_identity_with_principal(
        local_node_id,
        allowed_node_ids,
        header_node_id,
        claimed,
        mtls_peer_node_id,
        None,
    )
}

pub fn resolve_mesh_caller_identity_with_principal(
    local_node_id: &str,
    allowed_node_ids: &HashSet<String>,
    header_node_id: Option<&str>,
    claimed: Option<&str>,
    mtls_peer_node_id: Option<&str>,
    principal: Option<&MeshPrincipal>,
) -> Result<String, DomainError> {
    let identity = if let Some(p) = principal.filter(|p| !p.lab_omnipotent) {
        if p.role != MeshRole::Vault {
            return Err(DomainError::AuthRejected("day/vote requires vault peer principal (not kfe)".into()));
        }
        if !allowed_node_ids.contains(&p.node_id) && p.node_id != local_node_id {
            return Err(DomainError::AuthRejected(format!("mTLS principal {} is not a known mesh node", p.node_id)));
        }
        p.node_id.clone()
    } else if let Some(peer) = mtls_peer_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        if !allowed_node_ids.contains(peer) && peer != local_node_id {
            return Err(DomainError::AuthRejected(format!("mTLS peer identity {peer} is not a known mesh node")));
        }
        peer.to_string()
    } else if let Some(hdr) = header_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        if !allowed_node_ids.contains(hdr) && hdr != local_node_id {
            return Err(DomainError::AuthRejected(format!("X-Vault-Node-Id {hdr} is not a known mesh node")));
        }
        hdr.to_string()
    } else {
        local_node_id.to_string()
    };

    if let Some(raw) = claimed.map(str::trim).filter(|s| !s.is_empty()) {
        if raw != identity {
            return Err(DomainError::AuthRejected(format!(
                "voter {raw} does not match authenticated vault identity {identity}"
            )));
        }
    }
    Ok(identity)
}

/// Require DKG `sender_node_id` equals authenticated TLS vault peer (Critical #4).
pub fn bind_dkg_sender_to_peer(
    sender_node_id: &str,
    principal: Option<&MeshPrincipal>,
    lab_static_token: bool,
) -> Result<(), DomainError> {
    let sender = sender_node_id.trim();
    if sender.is_empty() {
        return Err(DomainError::AuthRejected("DKG sender_node_id required".into()));
    }
    if lab_static_token {
        return Ok(());
    }
    let Some(p) = principal else {
        return Err(DomainError::AuthRejected("DKG ingest requires authenticated mTLS vault principal".into()));
    };
    if p.lab_omnipotent {
        return Ok(());
    }
    if p.role != MeshRole::Vault {
        return Err(DomainError::AuthRejected("DKG peer rounds require vault role (not kfe)".into()));
    }
    if p.node_id != sender {
        return Err(DomainError::AuthRejected(format!(
            "DKG sender_node_id {sender} does not match TLS peer identity {}",
            p.node_id
        )));
    }
    Ok(())
}

/// Build the allowed voter / peer id set (local + seed peers).
pub fn mesh_allowed_node_ids(
    local_node_id: &str,
    seed_peer_ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert(local_node_id.to_string());
    for id in seed_peer_ids {
        let id = id.as_ref().trim();
        if !id.is_empty() {
            set.insert(id.to_string());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> HashSet<String> {
        mesh_allowed_node_ids("vault-1", ["vault-2", "vault-3"])
    }

    #[test]
    fn defaults_to_local_without_hooks() {
        assert_eq!(resolve_mesh_caller_identity("vault-1", &allowed(), None, None, None).unwrap(), "vault-1");
    }

    #[test]
    fn accepts_known_peer_header() {
        assert_eq!(
            resolve_mesh_caller_identity("vault-1", &allowed(), Some("vault-2"), None, None).unwrap(),
            "vault-2"
        );
    }

    #[test]
    fn rejects_unknown_header_spoof() {
        let err = resolve_mesh_caller_identity("vault-1", &allowed(), Some("vault-evil"), None, None).unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
    }

    #[test]
    fn mtls_hook_wins_over_header() {
        assert_eq!(
            resolve_mesh_caller_identity("vault-1", &allowed(), Some("vault-2"), None, Some("vault-3"),).unwrap(),
            "vault-3"
        );
    }

    #[test]
    fn rejects_claimed_mismatch() {
        let err = resolve_mesh_caller_identity("vault-1", &allowed(), None, Some("vault-2"), None).unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn parses_kfe_and_vault_spiffe() {
        assert_eq!(parse_spiffe_principal("spiffe://kerosene.lab/kfe").unwrap(), (MeshRole::Kfe, Some("kfe".into())));
        assert_eq!(
            parse_spiffe_principal("spiffe://kerosene.lab/vault/vault-2").unwrap(),
            (MeshRole::Vault, Some("vault-2".into()))
        );
        assert_eq!(parse_spiffe_principal("spiffe://kerosene.lab/vault/server").unwrap(), (MeshRole::Vault, None));
    }

    #[test]
    fn vault_server_svid_binds_dns_san() {
        let p = principal_from_cert_sans(
            &["spiffe://kerosene.lab/vault/server".into()],
            &["localhost".into(), "vault-2".into()],
            "vault-1",
            &allowed(),
        )
        .unwrap();
        assert_eq!(p.role, MeshRole::Vault);
        assert_eq!(p.node_id, "vault-2");
        assert!(!p.allows_route(RouteClass::KfeSettlement));
        assert!(p.allows_route(RouteClass::VaultPeer));
        assert!(p.allows_route(RouteClass::AdminRead));
    }

    #[test]
    fn kfe_cannot_hit_vault_peer_routes() {
        let p = principal_from_cert_sans(
            &["spiffe://kerosene.lab/kfe".into()],
            &["localhost".into()],
            "vault-1",
            &allowed(),
        )
        .unwrap();
        assert!(p.allows_route(RouteClass::KfeSettlement));
        assert!(!p.allows_route(RouteClass::VaultPeer));
        assert!(!p.allows_route(RouteClass::AdminRead));
    }

    #[test]
    fn dkg_sender_must_match_tls_peer() {
        let p = MeshPrincipal {
            role: MeshRole::Vault,
            node_id: "vault-2".into(),
            spiffe_id: Some("spiffe://kerosene.lab/vault/vault-2".into()),
            lab_omnipotent: false,
        };
        assert!(bind_dkg_sender_to_peer("vault-2", Some(&p), false).is_ok());
        let err = bind_dkg_sender_to_peer("vault-evil", Some(&p), false).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn route_class_maps_settlement_and_peer() {
        assert_eq!(route_class_for_path("/v1/bitcoin/sign-psbt"), Some(RouteClass::KfeSettlement));
        assert_eq!(route_class_for_path("/v1/dkg/round1"), Some(RouteClass::VaultPeer));
        assert_eq!(route_class_for_path("/v1/day/advance"), Some(RouteClass::SharedOps));
        assert_eq!(route_class_for_path("/v1/admin/status"), Some(RouteClass::AdminRead));
    }
}
