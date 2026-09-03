//! Over-wire Taproot FROST co-sign (Critical #1 / #2).
//!
//! Each vault holds **one** local TR share. The coordinator collects peer
//! round1 commitments and round2 signature shares over authenticated HTTP,
//! then aggregates. In-process multi-share signing is dealer_lab-only.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{EvenY, KeyPackage, Tweak};
use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{FrostTrShareSlot, FrostTrShareState};
use crate::application::AntiNoncePort;
use crate::domain::DomainError;
use crate::{build_mtls_rustls_client_config, PeerHttpSettings, TlsPeerVerifyPolicy};

pub struct AttributedWireSignature {
    pub signature: Signature,
    pub participant_node_ids: Vec<String>,
}

struct SigningNoncesGuard {
    nonces: SigningNonces,
}

impl SigningNoncesGuard {
    fn new(nonces: SigningNonces) -> Self {
        Self { nonces }
    }
}

impl Drop for SigningNoncesGuard {
    fn drop(&mut self) {
        self.nonces.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrCommitRequest {
    pub session_id: String,
    pub message_hex: String,
    pub coordinator_node_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrCommitResponse {
    pub node_id: String,
    pub identifier_hex: String,
    pub commitments_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrSignShareRequest {
    pub session_id: String,
    pub signing_package_hex: String,
    /// Only these peer node ids should produce signature shares (trimmed set).
    #[serde(default)]
    pub participant_node_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrSignShareResponse {
    pub node_id: String,
    pub identifier_hex: String,
    pub signature_share_hex: String,
}

struct PendingTrRound {
    nonces: SigningNonces,
    message: Vec<u8>,
}

/// Ephemeral round1 nonces awaiting round2 (peer co-sign helper).
pub struct TrCosignPeerState {
    local_node_id: String,
    shares: Arc<FrostTrShareSlot>,
    pending: Mutex<BTreeMap<String, PendingTrRound>>,
    anti_nonce: Option<Box<dyn AntiNoncePort>>,
}

impl TrCosignPeerState {
    pub fn new(local_node_id: impl Into<String>, shares: Arc<FrostTrShareSlot>) -> Self {
        Self { local_node_id: local_node_id.into(), shares, pending: Mutex::new(BTreeMap::new()), anti_nonce: None }
    }

    pub fn with_anti_nonce(mut self, anti: Box<dyn AntiNoncePort>) -> Self {
        self.anti_nonce = Some(anti);
        self
    }

    fn local_key_package(snap: &FrostTrShareState) -> Result<(Identifier, KeyPackage), DomainError> {
        if snap.key_packages.len() != 1 {
            return Err(DomainError::ThresholdError(format!(
                "wire co-sign peer requires exactly 1 local TR share (have {})",
                snap.key_packages.len()
            )));
        }
        let (id, kp) = snap
            .key_packages
            .iter()
            .next()
            .ok_or_else(|| DomainError::ThresholdError("missing local TR share".into()))?;
        Ok((*id, kp.clone()))
    }

    pub fn handle_commit(&self, req: &TrCommitRequest) -> Result<TrCommitResponse, DomainError> {
        let message = hex::decode(req.message_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("co-sign message hex: {e}")))?;
        let snap = self.shares.snapshot()?;
        let (id, kp) = Self::local_key_package(&snap)?;
        let kp = kp.into_even_y(None).tweak(None::<&[u8]>);
        let mut rng = OsRng;
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        let commitments_hex = hex::encode(
            commitments.serialize().map_err(|e| DomainError::ThresholdError(format!("commit serialize: {e}")))?,
        );
        self.pending
            .lock()
            .expect("tr cosign pending")
            .insert(req.session_id.clone(), PendingTrRound { nonces, message });
        Ok(TrCommitResponse {
            node_id: self.local_node_id.clone(),
            identifier_hex: hex::encode(id.serialize()),
            commitments_hex,
        })
    }

    pub fn handle_sign_share(&self, req: &TrSignShareRequest) -> Result<Option<TrSignShareResponse>, DomainError> {
        if !req.participant_node_ids.is_empty() && !req.participant_node_ids.iter().any(|id| id == &self.local_node_id)
        {
            // Not in trimmed signing set — drop pending nonces if any.
            let mut pending = self.pending.lock().expect("tr cosign pending");
            if let Some(mut entry) = pending.remove(&req.session_id) {
                entry.nonces.zeroize();
            }
            return Ok(None);
        }
        let mut pending = self.pending.lock().expect("tr cosign pending");
        let entry = pending.remove(&req.session_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("no pending TR co-sign round for session {}", req.session_id))
        })?;
        let PendingTrRound { mut nonces, message } = entry;
        let _nonces_guard = SigningNoncesGuard::new(nonces);
        let pkg_bytes = hex::decode(req.signing_package_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("signing package hex: {e}")))?;
        let signing_package = SigningPackage::deserialize(&pkg_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("signing package deserialize: {e}")))?;
        if signing_package.message() != message.as_slice() {
            return Err(DomainError::ThresholdError("co-sign signing package message mismatch".into()));
        }
        // Anti-nonce: refuse sign_share if session already consumed at this vault.
        if let Some(ref anti) = self.anti_nonce {
            if anti.is_consumed(&req.session_id)? {
                return Err(DomainError::SessionConsumed(req.session_id.clone()));
            }
            anti.observe_remote(&req.session_id)?;
        }
        let snap = self.shares.snapshot()?;
        let (id, kp) = Self::local_key_package(&snap)?;
        if !signing_package.signing_commitments().contains_key(&id) {
            return Ok(None);
        }
        let kp = kp.into_even_y(None).tweak(None::<&[u8]>);
        let share = frost::round2::sign(&signing_package, &_nonces_guard.nonces, &kp)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr peer round2: {e}")))?;
        let share_hex = hex::encode(share.serialize());
        Ok(Some(TrSignShareResponse {
            node_id: self.local_node_id.clone(),
            identifier_hex: hex::encode(id.serialize()),
            signature_share_hex: share_hex,
        }))
    }
}

/// Outbound peer co-sign transport (mTLS or lab token).
pub trait TrCosignTransport: Send + Sync {
    fn collect_commitments(&self, req: &TrCommitRequest) -> Result<Vec<TrCommitResponse>, DomainError>;
    fn collect_signature_shares(&self, req: &TrSignShareRequest) -> Result<Vec<TrSignShareResponse>, DomainError>;
}

pub struct NoopTrCosignTransport;

impl TrCosignTransport for NoopTrCosignTransport {
    fn collect_commitments(&self, _req: &TrCommitRequest) -> Result<Vec<TrCommitResponse>, DomainError> {
        Ok(vec![])
    }
    fn collect_signature_shares(&self, _req: &TrSignShareRequest) -> Result<Vec<TrSignShareResponse>, DomainError> {
        Ok(vec![])
    }
}

pub struct HttpTrCosignTransport {
    peers: Vec<(String, String)>,
    auth_token: Option<String>,
    peer_http: PeerHttpSettings,
    tls: Option<rustls::ClientConfig>,
}

impl HttpTrCosignTransport {
    pub fn with_peer_http(
        peers: Vec<(String, String)>,
        auth_token: Option<String>,
        peer_http: PeerHttpSettings,
    ) -> Self {
        Self { peers, auth_token, peer_http, tls: None }
    }

    pub fn with_mtls(
        peers: Vec<(String, String)>,
        peer_http: PeerHttpSettings,
        client_cert_path: &Path,
        client_key_path: &Path,
        ca_path: &Path,
        verify: &TlsPeerVerifyPolicy,
    ) -> Result<Self, DomainError> {
        let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
        Ok(Self { peers, auth_token: None, peer_http, tls: Some(tls) })
    }

    fn build_blocking_client(&self) -> Result<reqwest::blocking::Client, DomainError> {
        let mut builder = self.peer_http.apply_blocking_builder(reqwest::blocking::Client::builder())?;
        if let Some(tls) = self.tls.clone() {
            builder = builder.use_preconfigured_tls(tls);
        }
        builder.build().map_err(|e| DomainError::ThresholdError(format!("TR co-sign http client: {e}")))
    }

    fn post_peer<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        base: &str,
        path: &str,
        body: &T,
    ) -> Result<R, DomainError> {
        let url = format!("{base}{path}");
        let client = self.build_blocking_client()?;
        let token = self.auth_token.clone();
        let res = post_json_with_retry_blocking(
            &client,
            &self.peer_http,
            &url,
            |req| {
                if let Some(t) = &token {
                    req.header("X-Vault-Token", t)
                } else {
                    req
                }
            },
            body,
        )?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().unwrap_or_default();
            return Err(DomainError::ThresholdError(format!("TR co-sign peer {url} failed ({status}): {text}")));
        }
        res.json().map_err(|e| DomainError::ThresholdError(format!("TR co-sign peer decode: {e}")))
    }
}

impl TrCosignTransport for HttpTrCosignTransport {
    fn collect_commitments(&self, req: &TrCommitRequest) -> Result<Vec<TrCommitResponse>, DomainError> {
        let mut out = Vec::new();
        for (id, base) in &self.peers {
            let resp: TrCommitResponse = self
                .post_peer(base, "/v1/frost/tr/commit", req)
                .map_err(|e| DomainError::ThresholdError(format!("TR commit from {id}: {e}")))?;
            out.push(resp);
        }
        Ok(out)
    }

    fn collect_signature_shares(&self, req: &TrSignShareRequest) -> Result<Vec<TrSignShareResponse>, DomainError> {
        let mut out = Vec::new();
        for (id, base) in &self.peers {
            if !req.participant_node_ids.is_empty() && !req.participant_node_ids.iter().any(|p| p == id) {
                continue;
            }
            let resp: TrSignShareResponse = self
                .post_peer(base, "/v1/frost/tr/sign-share", req)
                .map_err(|e| DomainError::ThresholdError(format!("TR sign-share from {id}: {e}")))?;
            out.push(resp);
        }
        Ok(out)
    }
}

fn post_json_with_retry_blocking<T: Serialize>(
    http: &reqwest::blocking::Client,
    settings: &PeerHttpSettings,
    url: &str,
    auth: impl Fn(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
    body: &T,
) -> Result<reqwest::blocking::Response, DomainError> {
    // Mirror async retry budget with blocking client (same settings).
    let mut attempt = 0u32;
    let max = settings.max_retries.max(1);
    loop {
        attempt += 1;
        let req = auth(http.post(url).json(body));
        match req.send() {
            Ok(res) => return Ok(res),
            Err(_e) if attempt < max => {
                let sleep_ms = settings.retry_base_ms + (attempt as u64).saturating_mul(settings.retry_jitter_ms / 2);
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
            Err(e) => {
                return Err(DomainError::ThresholdError(format!("TR co-sign HTTP {url}: {e}")));
            }
        }
    }
}

/// Coordinate TR FROST signature using local share + peer co-sign over wire.
pub fn sign_raw_wire(
    shares: &FrostTrShareSlot,
    transport: &dyn TrCosignTransport,
    local_node_id: &str,
    session_id: &str,
    message: &[u8],
) -> Result<Signature, DomainError> {
    Ok(sign_raw_wire_attributed(shares, transport, local_node_id, session_id, message)?.signature)
}

pub fn sign_raw_wire_attributed(
    shares: &FrostTrShareSlot,
    transport: &dyn TrCosignTransport,
    local_node_id: &str,
    session_id: &str,
    message: &[u8],
) -> Result<AttributedWireSignature, DomainError> {
    let snap = shares.snapshot()?;
    if snap.key_packages.len() != 1 {
        return Err(DomainError::ThresholdError(format!(
            "distributed_wire TR sign requires exactly 1 local share (have {}); multi-share in-process sign is dealer_lab only",
            snap.key_packages.len()
        )));
    }
    let min_signers = snap.min_signers;
    let (local_id, local_kp) = snap
        .key_packages
        .iter()
        .next()
        .map(|(i, k)| (*i, k.clone()))
        .ok_or_else(|| DomainError::ThresholdError("missing local TR share".into()))?;

    let local_kp_tweaked = local_kp.clone().into_even_y(None).tweak(None::<&[u8]>);
    let mut rng = OsRng;
    let (mut local_nonces, local_commitments) = frost::round1::commit(local_kp_tweaked.signing_share(), &mut rng);
    let mut local_nonces_guard = SigningNoncesGuard::new(local_nonces);

    let commit_req = TrCommitRequest {
        session_id: session_id.to_string(),
        message_hex: hex::encode(message),
        coordinator_node_id: local_node_id.to_string(),
    };
    let peer_commits = transport.collect_commitments(&commit_req)?;

    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let mut peer_id_by_identifier: BTreeMap<Identifier, String> = BTreeMap::new();
    commitments_map.insert(local_id, local_commitments);
    for peer in &peer_commits {
        let id_bytes = hex::decode(peer.identifier_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("peer identifier hex: {e}")))?;
        let id = Identifier::deserialize(&id_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("peer identifier: {e}")))?;
        let c_bytes = hex::decode(peer.commitments_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("peer commitments hex: {e}")))?;
        let c = SigningCommitments::deserialize(&c_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("peer commitments: {e}")))?;
        commitments_map.insert(id, c);
        peer_id_by_identifier.insert(id, peer.node_id.clone());
    }

    if commitments_map.len() < min_signers {
        return Err(DomainError::FailStop { online: commitments_map.len(), need: min_signers });
    }

    // Trim to min_signers deterministically (local + lowest ids).
    if commitments_map.len() > min_signers {
        let mut ids: Vec<Identifier> = commitments_map.keys().copied().collect();
        ids.sort_by_key(|i| i.serialize());
        let mut keep = BTreeMap::new();
        keep.insert(local_id, commitments_map.remove(&local_id).unwrap());
        for id in ids {
            if keep.len() >= min_signers {
                break;
            }
            if id == local_id {
                continue;
            }
            if let Some(c) = commitments_map.remove(&id) {
                keep.insert(id, c);
            }
        }
        commitments_map = keep;
    }

    let selected_peer_nodes: std::collections::HashSet<String> =
        commitments_map.keys().filter_map(|id| peer_id_by_identifier.get(id).cloned()).collect();

    let mut message_buf = message.to_vec();
    let signing_package = SigningPackage::new(commitments_map, &message_buf);
    let pkg_hex = hex::encode(
        signing_package
            .serialize()
            .map_err(|e| DomainError::ThresholdError(format!("signing package serialize: {e}")))?,
    );

    let local_share = frost::round2::sign(&signing_package, &local_nonces_guard.nonces, &local_kp_tweaked)
        .map_err(|e| DomainError::ThresholdError(format!("frost-tr local round2: {e}")))?;
    local_nonces_guard.nonces.zeroize();

    let share_req = TrSignShareRequest {
        session_id: session_id.to_string(),
        signing_package_hex: pkg_hex,
        participant_node_ids: selected_peer_nodes.iter().cloned().collect(),
    };
    let peer_shares = transport.collect_signature_shares(&share_req)?;

    let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    let mut participant_node_ids = vec![local_node_id.to_string()];
    signature_shares.insert(local_id, local_share);
    for peer in &peer_shares {
        let id_bytes = hex::decode(peer.identifier_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("peer identifier hex: {e}")))?;
        let id = Identifier::deserialize(&id_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("peer identifier: {e}")))?;
        if !signing_package.signing_commitments().contains_key(&id) {
            continue; // peer not in trimmed set
        }
        let s_bytes = hex::decode(peer.signature_share_hex.trim())
            .map_err(|e| DomainError::ThresholdError(format!("peer sig share hex: {e}")))?;
        let s = SignatureShare::deserialize(&s_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("peer sig share: {e}")))?;
        signature_shares.insert(id, s);
        if let Some(node_id) = peer_id_by_identifier.get(&id) {
            participant_node_ids.push(node_id.clone());
        }
    }

    if signature_shares.len() < min_signers {
        return Err(DomainError::FailStop { online: signature_shares.len(), need: min_signers });
    }

    let pubkey_tweaked = snap.pubkey_package.clone().into_even_y(None).tweak(None::<&[u8]>);
    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_tweaked)
        .map_err(|e| DomainError::ThresholdError(format!("frost-tr wire aggregate: {e}")))?;
    pubkey_tweaked
        .verifying_key()
        .verify(&message_buf, &signature)
        .map_err(|e| DomainError::ThresholdError(format!("frost-tr wire verify: {e}")))?;
    message_buf.zeroize();
    participant_node_ids.sort();
    participant_node_ids.dedup();
    Ok(AttributedWireSignature { signature, participant_node_ids })
}

/// Keep only the local identifier's key package (distributed_wire hygiene).
pub fn tr_state_local_only(
    state: FrostTrShareState,
    local_identifier: Identifier,
) -> Result<FrostTrShareState, DomainError> {
    let kp = state
        .key_packages
        .get(&local_identifier)
        .cloned()
        .ok_or_else(|| DomainError::ThresholdError("local TR identifier missing from key packages".into()))?;
    let mut key_packages = BTreeMap::new();
    key_packages.insert(local_identifier, kp);
    Ok(FrostTrShareState { key_packages, pubkey_package: state.pubkey_package, min_signers: state.min_signers })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dealer_lab")]
    use crate::adapters::frost_tr_bitcoin::generate_tr_dealer;

    struct MemoryMesh {
        peers: Vec<(String, Arc<TrCosignPeerState>)>,
    }

    impl TrCosignTransport for MemoryMesh {
        fn collect_commitments(&self, req: &TrCommitRequest) -> Result<Vec<TrCommitResponse>, DomainError> {
            self.peers.iter().map(|(_, p)| p.handle_commit(req)).collect()
        }
        fn collect_signature_shares(&self, req: &TrSignShareRequest) -> Result<Vec<TrSignShareResponse>, DomainError> {
            let mut out = Vec::new();
            for (_, p) in &self.peers {
                if let Some(resp) = p.handle_sign_share(req)? {
                    out.push(resp);
                }
            }
            Ok(out)
        }
    }

    #[cfg(feature = "dealer_lab")]
    #[test]
    fn wire_cosign_three_party_aggregates() {
        let bundle = generate_tr_dealer(3, 2).unwrap();
        let ids: Vec<_> = bundle.key_packages.keys().copied().collect();
        let mut peer_states = Vec::new();
        let mut coord_slot = None;
        let mut coord_id = None;
        for (i, id) in ids.iter().enumerate() {
            let mut map = BTreeMap::new();
            map.insert(*id, bundle.key_packages[id].clone());
            let state =
                FrostTrShareState { key_packages: map, pubkey_package: bundle.pubkey_package.clone(), min_signers: 2 };
            let slot = Arc::new(FrostTrShareSlot::new());
            slot.install(state);
            let node = format!("vault-{}", i + 1);
            let peer = Arc::new(TrCosignPeerState::new(node.clone(), slot.clone()));
            if i == 0 {
                coord_slot = Some(slot);
                coord_id = Some(node);
            } else {
                peer_states.push((format!("vault-{}", i + 1), peer));
            }
        }
        let transport = MemoryMesh { peers: peer_states };
        let msg = [7u8; 32];
        let sig =
            sign_raw_wire(coord_slot.as_ref().unwrap(), &transport, coord_id.as_ref().unwrap(), "sess-wire-tr-1", &msg)
                .unwrap();
        let snap = coord_slot.as_ref().unwrap().snapshot().unwrap();
        let pk = snap.pubkey_package.into_even_y(None).tweak(None::<&[u8]>);
        pk.verifying_key().verify(&msg, &sig).unwrap();
    }
}
