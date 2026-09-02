//! Over-wire multi-party Taproot FROST DKG (no dealer) — `frost-secp256k1-tr`.
//!
//! Mirrors `dkg_wire.rs` (plain FROST) but produces a BIP-340 even-Y Taproot
//! keyset persisted via `persist_tr_shares` (`frost-tr-*` share ids) so that
//! `load_tr_shares` at boot installs `runtime.frost_tr` and the deposit
//! endpoint returns a `tb1p`/`bcrt1p` address.
//!
//! Rounds 1 and 2 are structurally identical to the plain wire DKG (same
//! `frost::keys::dkg::part1/part2/part3`), only the ciphersuite differs.
//! The ONLY divergence is at finalize: apply `.into_even_y(None)` to the
//! `PublicKeyPackage` and the local `KeyPackage`, then persist ONLY the
//! local share (1 key package) — `distributed_wire` refuses multi-share.
//!
//! ToB / Gate integrity (reused from plain wire DKG):
//! - Participant set + `(max_signers, min_signers)` frozen at round1 start
//! - Reject threshold / min_signers drift on wire messages
//! - Reject late join / unknown senders after freeze
//! - Transcript binding: SHA-256 over session constitution (TR-distinct domain)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use frost_secp256k1_tr::keys::{EvenY, KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::Identifier;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::dkg_wire::{
    peer_base_url, DkgStartRequest, Round1WireMessage, Round2WireMessage, Round3WireRequest, WireDkgPeerAuth,
    WireDkgPhase, WireDkgStatus,
};
use super::frost_tr_bitcoin::{persist_tr_shares, FrostTrShareState};
use crate::application::ShareStorePort;
use crate::domain::DomainError;
use crate::{build_mtls_rustls_client_config, post_json_with_retry, PeerHttpSettings};

fn identifier_from_u16(v: u16) -> Result<Identifier, DomainError> {
    Identifier::try_from(v).map_err(|e| DomainError::ThresholdError(format!("tr identifier {v}: {e}")))
}

fn identifier_to_u16(roster: &BTreeMap<String, Identifier>, id: Identifier) -> u16 {
    for (i, (_, rid)) in roster.iter().enumerate() {
        if *rid == id {
            return (i + 1) as u16;
        }
    }
    0
}

fn build_roster(roster: &[String]) -> Result<BTreeMap<String, Identifier>, DomainError> {
    let mut sorted: Vec<String> = roster.iter().map(|s| s.trim().to_string()).collect();
    sorted.sort();
    sorted.dedup();
    if sorted.len() < 2 {
        return Err(DomainError::ThresholdError("TR DKG roster must have >= 2 unique node ids".into()));
    }
    let mut map = BTreeMap::new();
    for (i, node) in sorted.into_iter().enumerate() {
        let id = identifier_from_u16((i + 1) as u16)?;
        map.insert(node, id);
    }
    Ok(map)
}

/// TR-distinct transcript domain (prevents plain<->TR round-message cross-use).
pub fn session_transcript_tr(
    session_id: &str,
    max_signers: u16,
    min_signers: u16,
    roster: &BTreeMap<String, Identifier>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"kerosene-dkg-tr-wire-v1|");
    h.update(session_id.as_bytes());
    h.update(b"|max=");
    h.update(max_signers.to_string().as_bytes());
    h.update(b"|min=");
    h.update(min_signers.to_string().as_bytes());
    h.update(b"|roster=");
    for (i, node) in roster.keys().enumerate() {
        if i > 0 {
            h.update(b",");
        }
        h.update(node.as_bytes());
    }
    hex::encode(h.finalize())
}

fn assert_threshold_tr(kp: &KeyPackage, pk: &PublicKeyPackage, min: u16, max: u16) -> Result<(), DomainError> {
    if *kp.min_signers() != min {
        return Err(DomainError::ThresholdError(format!(
            "TR DKG threshold mismatch (ToB): key_package.min_signers={} expected={min}",
            kp.min_signers()
        )));
    }
    if let Some(pk_min) = pk.min_signers() {
        if pk_min != min {
            return Err(DomainError::ThresholdError(format!(
                "TR DKG threshold mismatch (ToB): pubkey.min_signers={pk_min} expected={min}"
            )));
        }
    }
    if pk.max_signers() != max {
        return Err(DomainError::ThresholdError(format!(
            "TR DKG n mismatch: pubkey.max_signers={} expected={max}",
            pk.max_signers()
        )));
    }
    Ok(())
}

struct TrSessionInner {
    session_id: String,
    local_node_id: String,
    local_identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    roster: BTreeMap<String, Identifier>,
    transcript_hex: String,
    roster_closed: bool,
    phase: WireDkgPhase,
    round1_secret: Option<round1::SecretPackage>,
    round1_packages: BTreeMap<Identifier, round1::Package>,
    round2_secret: Option<round2::SecretPackage>,
    round2_inbox: BTreeMap<Identifier, round2::Package>,
    round2_outbound: BTreeMap<Identifier, round2::Package>,
    key_package: Option<KeyPackage>,
    pubkey_package: Option<PublicKeyPackage>,
}

impl TrSessionInner {
    fn status(&self) -> WireDkgStatus {
        let verifying_key_hex =
            self.pubkey_package.as_ref().map(|pk| hex::encode(pk.verifying_key().serialize().unwrap_or_default()));
        WireDkgStatus {
            session_id: self.session_id.clone(),
            phase: self.phase.as_str().to_string(),
            local_node_id: self.local_node_id.clone(),
            local_identifier: identifier_to_u16(&self.roster, self.local_identifier),
            max_signers: self.max_signers,
            min_signers: self.min_signers,
            transcript_hex: self.transcript_hex.clone(),
            round1_received: self.round1_packages.len(),
            round2_received: self.round2_inbox.len(),
            complete: self.phase == WireDkgPhase::Complete,
            verifying_key_hex,
        }
    }
}

fn build_http_client(auth: &WireDkgPeerAuth, peer_http: &PeerHttpSettings) -> Result<reqwest::Client, DomainError> {
    let builder = peer_http.apply_builder(reqwest::Client::builder())?;
    match auth {
        WireDkgPeerAuth::StaticToken(_) => {
            builder.build().map_err(|e| DomainError::ThresholdError(format!("tr dkg http client: {e}")))
        }
        WireDkgPeerAuth::MutualTls { client_cert_path, client_key_path, ca_path, verify } => {
            let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
            builder
                .use_preconfigured_tls(tls)
                .build()
                .map_err(|e| DomainError::ThresholdError(format!("tr dkg mTLS http client: {e}")))
        }
    }
}

/// In-memory over-wire Taproot DKG hub for one vault process.
pub struct TrWireDkgHub {
    local_node_id: String,
    peer_addrs: BTreeMap<String, String>,
    peer_auth: WireDkgPeerAuth,
    peer_http: PeerHttpSettings,
    sessions: Mutex<BTreeMap<String, TrSessionInner>>,
    completed: Mutex<Option<(KeyPackage, PublicKeyPackage, u16)>>,
    http: reqwest::Client,
}

impl TrWireDkgHub {
    pub fn with_peer_http(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        peer_auth: WireDkgPeerAuth,
        peer_http: PeerHttpSettings,
    ) -> Result<Self, DomainError> {
        let http = build_http_client(&peer_auth, &peer_http)?;
        Ok(Self {
            local_node_id: local_node_id.into(),
            peer_addrs,
            peer_auth,
            peer_http,
            sessions: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(None),
            http,
        })
    }

    pub fn peer_auth_mode(&self) -> &'static str {
        if self.peer_auth.is_mtls() {
            "mtls"
        } else {
            "static_token"
        }
    }

    pub fn completed_local(&self) -> Option<(KeyPackage, PublicKeyPackage, u16)> {
        self.completed.lock().expect("tr dkg completed").clone()
    }

    pub fn status(&self, session_id: &str) -> Result<WireDkgStatus, DomainError> {
        let g = self.sessions.lock().expect("tr dkg sessions");
        let s = g
            .get(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown TR DKG session: {session_id}")))?;
        Ok(s.status())
    }

    /// Start local session: run part1, freeze roster+threshold, return wire message.
    pub fn start(&self, req: DkgStartRequest) -> Result<(WireDkgStatus, Round1WireMessage), DomainError> {
        if req.max_signers < 2 || req.min_signers < 2 || req.min_signers > req.max_signers {
            return Err(DomainError::ThresholdError(format!(
                "bad TR frost DKG params: max={} min={}",
                req.max_signers, req.min_signers
            )));
        }
        let roster = build_roster(&req.roster)?;
        if roster.len() as u16 != req.max_signers {
            return Err(DomainError::ThresholdError(format!(
                "TR roster len {} != max_signers {}",
                roster.len(),
                req.max_signers
            )));
        }
        let transcript_hex = session_transcript_tr(&req.session_id, req.max_signers, req.min_signers, &roster);

        {
            let g = self.sessions.lock().expect("tr dkg sessions");
            if let Some(existing) = g.get(&req.session_id) {
                if existing.transcript_hex != transcript_hex
                    || existing.max_signers != req.max_signers
                    || existing.min_signers != req.min_signers
                    || existing.roster != roster
                {
                    return Err(DomainError::ThresholdError(
                        "TR DKG participants/threshold frozen at round1; constitution drift rejected".into(),
                    ));
                }
                let local_identifier = existing.local_identifier;
                let package = existing
                    .round1_packages
                    .get(&local_identifier)
                    .ok_or_else(|| DomainError::ThresholdError("missing local TR round1 package".into()))?;
                let package_hex = hex::encode(
                    package
                        .serialize()
                        .map_err(|e| DomainError::ThresholdError(format!("tr round1 serialize: {e}")))?,
                );
                let wire = Round1WireMessage {
                    session_id: existing.session_id.clone(),
                    sender_node_id: existing.local_node_id.clone(),
                    sender_identifier: identifier_to_u16(&existing.roster, local_identifier),
                    max_signers: existing.max_signers,
                    min_signers: existing.min_signers,
                    transcript_hex: existing.transcript_hex.clone(),
                    package_hex,
                    envelope: None,
                };
                return Ok((existing.status(), wire));
            }
        }

        let local_identifier = *roster.get(&self.local_node_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("local node {} missing from TR DKG roster", self.local_node_id))
        })?;

        let mut rng = OsRng;
        let (secret, package) = frost::keys::dkg::part1(local_identifier, req.max_signers, req.min_signers, &mut rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr dkg part1: {e}")))?;

        let package_hex = hex::encode(
            package.serialize().map_err(|e| DomainError::ThresholdError(format!("tr round1 serialize: {e}")))?,
        );

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(local_identifier, package.clone());

        let inner = TrSessionInner {
            session_id: req.session_id.clone(),
            local_node_id: self.local_node_id.clone(),
            local_identifier,
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            roster,
            transcript_hex: transcript_hex.clone(),
            roster_closed: false,
            phase: WireDkgPhase::Round1,
            round1_secret: Some(secret),
            round1_packages,
            round2_secret: None,
            round2_inbox: BTreeMap::new(),
            round2_outbound: BTreeMap::new(),
            key_package: None,
            pubkey_package: None,
        };

        let wire = Round1WireMessage {
            session_id: req.session_id.clone(),
            sender_node_id: self.local_node_id.clone(),
            sender_identifier: identifier_to_u16(&inner.roster, local_identifier),
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            transcript_hex,
            package_hex,
            envelope: None,
        };
        let status = inner.status();
        self.sessions.lock().expect("tr dkg sessions").insert(req.session_id, inner);
        Ok((status, wire))
    }

    /// Ingest a peer's round1 package. Auto-advances to part2 when full.
    pub fn ingest_round1(&self, msg: Round1WireMessage) -> Result<WireDkgStatus, DomainError> {
        let mut g = self.sessions.lock().expect("tr dkg sessions");
        let session = g.get_mut(&msg.session_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("unknown TR DKG session {} (start locally first)", msg.session_id))
        })?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }
        if msg.max_signers != session.max_signers || msg.min_signers != session.min_signers {
            return Err(DomainError::ThresholdError(
                "TR round1 threshold/min_signers drift rejected (ToB); constitution frozen at start".into(),
            ));
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("TR round1 transcript binding mismatch; abort DKG".into()));
        }

        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "TR late join / participant set change rejected: unknown sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!("TR sender {} identifier mismatch", msg.sender_node_id)));
        }
        if sender_id == session.local_identifier {
            return Ok(session.status());
        }

        if session.roster_closed || session.phase != WireDkgPhase::Round1 {
            if session.round1_packages.contains_key(&sender_id) {
                return Ok(session.status());
            }
            return Err(DomainError::ThresholdError(
                "TR late join rejected: participant set frozen after round1".into(),
            ));
        }

        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("tr round1 hex: {e}")))?;
        let package = round1::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr round1 deserialize: {e}")))?;
        session.round1_packages.insert(sender_id, package);

        if session.round1_packages.len() as u16 == session.max_signers
            && session.round1_secret.is_some()
            && session.phase == WireDkgPhase::Round1
        {
            Self::advance_to_round2(session)?;
        }
        Ok(session.status())
    }

    fn advance_to_round2(session: &mut TrSessionInner) -> Result<(), DomainError> {
        let secret = session
            .round1_secret
            .take()
            .ok_or_else(|| DomainError::ThresholdError("missing TR round1 secret".into()))?;
        let mut received = session.round1_packages.clone();
        received.remove(&session.local_identifier);
        let (r2_secret, outbound) = frost::keys::dkg::part2(secret, &received)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr dkg part2: {e}")))?;
        session.round2_secret = Some(r2_secret);
        session.round2_outbound = outbound;
        session.roster_closed = true;
        session.phase = WireDkgPhase::Round2;
        Ok(())
    }

    pub fn take_round2_outbound(&self, session_id: &str) -> Result<Vec<Round2WireMessage>, DomainError> {
        let mut g = self.sessions.lock().expect("tr dkg sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown TR DKG session: {session_id}")))?;
        let mut out = Vec::new();
        let outbound = std::mem::take(&mut session.round2_outbound);
        for (recipient_id, package) in outbound {
            let recipient_node_id = session
                .roster
                .iter()
                .find(|(_, id)| **id == recipient_id)
                .map(|(n, _)| n.clone())
                .ok_or_else(|| DomainError::ThresholdError(format!("unknown TR recipient id {recipient_id:?}")))?;
            let package_hex = hex::encode(
                package.serialize().map_err(|e| DomainError::ThresholdError(format!("tr round2 serialize: {e}")))?,
            );
            out.push(Round2WireMessage {
                session_id: session_id.to_string(),
                sender_node_id: session.local_node_id.clone(),
                sender_identifier: identifier_to_u16(&session.roster, session.local_identifier),
                recipient_node_id,
                recipient_identifier: identifier_to_u16(&session.roster, recipient_id),
                transcript_hex: session.transcript_hex.clone(),
                package_hex,
                envelope: None,
            });
        }
        Ok(out)
    }

    pub fn ingest_round2(&self, msg: Round2WireMessage) -> Result<WireDkgStatus, DomainError> {
        let mut g = self.sessions.lock().expect("tr dkg sessions");
        let session = g
            .get_mut(&msg.session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown TR DKG session: {}", msg.session_id)))?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("TR round2 transcript binding mismatch; abort DKG".into()));
        }
        if msg.recipient_node_id != session.local_node_id {
            return Err(DomainError::ThresholdError("TR round2 package not addressed to this vault".into()));
        }
        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "TR late join / participant set change rejected: unknown round2 sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!(
                "TR round2 sender {} identifier mismatch",
                msg.sender_node_id
            )));
        }
        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("tr round2 hex: {e}")))?;
        let package = round2::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr round2 deserialize: {e}")))?;
        session.round2_inbox.insert(sender_id, package);
        Ok(session.status())
    }

    /// Finalize part3 when round2 inbox has n-1 packages. Persists ONLY the
    /// local Taproot share via `persist_tr_shares` (even-Y applied).
    pub fn finalize_round3(
        &self,
        session_id: &str,
        share_store: &dyn ShareStorePort,
    ) -> Result<WireDkgStatus, DomainError> {
        let mut g = self.sessions.lock().expect("tr dkg sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown TR DKG session: {session_id}")))?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }
        let need = (session.max_signers as usize).saturating_sub(1);
        if session.round2_inbox.len() < need {
            return Err(DomainError::ThresholdError(format!(
                "TR round2 incomplete: have {} need {need}",
                session.round2_inbox.len()
            )));
        }
        let r2_secret = session
            .round2_secret
            .as_ref()
            .ok_or_else(|| DomainError::ThresholdError("missing TR round2 secret".into()))?;
        let mut r1_received = session.round1_packages.clone();
        r1_received.remove(&session.local_identifier);
        let (kp, pk) = frost::keys::dkg::part3(r2_secret, &r1_received, &session.round2_inbox)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr dkg part3: {e}")))?;
        assert_threshold_tr(&kp, &pk, session.min_signers, session.max_signers)?;

        // Taproot: force even-Y on group pubkey and local key package.
        let pk = pk.into_even_y(None);
        let kp = kp.into_even_y(None);

        // Persist ONLY the local share (1 key package) — distributed_wire refuses
        // multi-share; load_tr_shares at boot returns exactly this one package.
        let mut key_packages = BTreeMap::new();
        key_packages.insert(session.local_identifier, kp.clone());
        let tr_state =
            FrostTrShareState { key_packages, pubkey_package: pk.clone(), min_signers: session.min_signers as usize };
        persist_tr_shares(&tr_state, share_store)?;

        session.key_package = Some(kp.clone());
        session.pubkey_package = Some(pk.clone());
        session.phase = WireDkgPhase::Complete;
        session.round2_secret = None;

        *self.completed.lock().expect("tr dkg completed") = Some((kp, pk, session.min_signers));
        Ok(session.status())
    }

    fn apply_peer_auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.peer_auth {
            WireDkgPeerAuth::StaticToken(token) => req.header("X-Vault-Token", token),
            WireDkgPeerAuth::MutualTls { .. } => req,
        }
    }

    pub async fn fanout_round1(&self, msg: &Round1WireMessage) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for (peer_id, addr) in &self.peer_addrs {
            if peer_id == &self.local_node_id {
                continue;
            }
            let url = format!("{}/v1/dkg/tr/round1", peer_base_url(addr, mtls));
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| DomainError::ThresholdError(format!("tr round1 fanout to {peer_id}: {e}")))?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!("tr round1 fanout to {peer_id} failed: {body}")));
            }
        }
        Ok(())
    }

    pub async fn fanout_round2(&self, messages: &[Round2WireMessage]) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for msg in messages {
            let addr = self
                .peer_addrs
                .get(&msg.recipient_node_id)
                .ok_or_else(|| DomainError::ThresholdError(format!("no TR peer addr for {}", msg.recipient_node_id)))?;
            let url = format!("{}/v1/dkg/tr/round2", peer_base_url(addr, mtls));
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| {
                        DomainError::ThresholdError(format!("tr round2 fanout to {}: {e}", msg.recipient_node_id))
                    })?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!(
                    "tr round2 fanout to {} failed: {body}",
                    msg.recipient_node_id
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::AeadDiskShareStore;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-tr-wire-dkg-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn three_hubs() -> (Vec<TrWireDkgHub>, DkgStartRequest) {
        let roster = vec!["vault-1".into(), "vault-2".into(), "vault-3".into()];
        let hubs: Vec<TrWireDkgHub> = (1..=3)
            .map(|i| {
                TrWireDkgHub::with_peer_http(
                    format!("vault-{i}"),
                    BTreeMap::new(),
                    WireDkgPeerAuth::StaticToken("lab-token".into()),
                    PeerHttpSettings::clearnet_defaults(),
                )
                .unwrap()
            })
            .collect();
        let start = DkgStartRequest {
            session_id: "sess-tr-wire-1".into(),
            max_signers: 3,
            min_signers: 2,
            roster: roster.clone(),
        };
        (hubs, start)
    }

    #[test]
    fn tr_wire_dkg_three_party_persists_single_local_share() {
        let (hubs, start) = three_hubs();
        let session = start.session_id.clone();
        let tmp = TempDir::new("tr");

        let mut r1_msgs = Vec::new();
        for h in &hubs {
            let (_st, msg) = h.start(start.clone()).unwrap();
            assert!(!msg.transcript_hex.is_empty());
            r1_msgs.push(msg);
        }
        for (i, h) in hubs.iter().enumerate() {
            for (j, msg) in r1_msgs.iter().enumerate() {
                if i != j {
                    h.ingest_round1(msg.clone()).unwrap();
                }
            }
        }

        let mut r2_all = Vec::new();
        for h in &hubs {
            r2_all.extend(h.take_round2_outbound(&session).unwrap());
        }
        for msg in &r2_all {
            let idx = msg.recipient_node_id.trim_start_matches("vault-");
            let i: usize = idx.parse().unwrap();
            hubs[i - 1].ingest_round2(msg.clone()).unwrap();
        }

        let mut vks = Vec::new();
        for (i, h) in hubs.iter().enumerate() {
            let store = AeadDiskShareStore::new(tmp.0.join(format!("shares-{i}")), "lab-pass");
            let st = h.finalize_round3(&session, &store).unwrap();
            assert!(st.complete);
            let (kp, pk, min) = h.completed_local().unwrap();
            assert_eq!(min, 2);
            assert_eq!(*kp.min_signers(), 2);
            vks.push(*pk.verifying_key());
            // load_tr_shares must yield exactly 1 key package (local only).
            let loaded = crate::adapters::load_tr_shares(&store).unwrap();
            assert_eq!(loaded.key_packages.len(), 1);
            assert_eq!(*loaded.pubkey_package.verifying_key(), *pk.verifying_key());
        }
        // All 3 vaults share the same group verifying key.
        assert_eq!(vks[0], vks[1]);
        assert_eq!(vks[1], vks[2]);
    }
}
