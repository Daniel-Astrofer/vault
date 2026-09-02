//! Taproot-compatible FROST (`frost-secp256k1-tr`) for on-chain Bitcoin sighashes.
//!
//! Intent / off-chain proofs keep using `frost-secp256k1`. This module holds a
//! separate BIP-340 keyset used only for PSBT / Taproot key-path spends.
//!
//! On-chain signatures cover the raw 32-byte sighash. Policy is enforced *before*
//! sign via Intent gate **and** PSBT output binding (destination + amount).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{schnorr, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, ScriptBuf, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{EvenY, KeyPackage, PublicKeyPackage, Tweak};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::adapters::{destination_script_pubkey, to_bitcoin_network, validate_psbt};
use crate::application::{AntiNoncePort, DailyRotationPort, ShareStorePort};
use crate::domain::{BitcoinNetwork, DomainError, PsbtPolicy};

const TR_PUBKEY_SHARE_ID: &str = "frost-tr-dkg-pubkey";
const TR_ROSTER_SHARE_ID: &str = "frost-tr-roster";
const TR_MIN_SHARE_ID: &str = "frost-tr-min-signers";

/// CHANNELS Taproot keyset — distinct from USERS omnibus (`frost-tr-*`).
const TR_CHANNELS_PUBKEY_SHARE_ID: &str = "frost-tr-channels-dkg-pubkey";
const TR_CHANNELS_ROSTER_SHARE_ID: &str = "frost-tr-channels-roster";
const TR_CHANNELS_MIN_SHARE_ID: &str = "frost-tr-channels-min-signers";

#[derive(Clone)]
pub struct FrostTrShareState {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub pubkey_package: PublicKeyPackage,
    pub min_signers: usize,
}

#[derive(Default)]
pub struct FrostTrShareSlot {
    inner: RwLock<Option<FrostTrShareState>>,
}

impl FrostTrShareSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, state: FrostTrShareState) {
        *self.inner.write().expect("tr share lock") = Some(state);
    }

    pub fn snapshot(&self) -> Result<FrostTrShareState, DomainError> {
        self.inner
            .read()
            .expect("tr share lock")
            .clone()
            .ok_or_else(|| DomainError::ThresholdError("taproot FROST shares not installed".into()))
    }

    pub fn replace(&self, state: FrostTrShareState) {
        *self.inner.write().expect("tr share lock") = Some(state);
    }

    pub fn is_installed(&self) -> bool {
        self.inner.read().expect("tr share lock").is_some()
    }
}

/// Persist Taproot FROST key packages via ShareStorePort (AEAD lab / TEE seal).
pub fn persist_tr_shares(state: &FrostTrShareState, store: &dyn ShareStorePort) -> Result<(), DomainError> {
    let mut roster = Vec::new();
    for (id, kp) in &state.key_packages {
        let id_hex = hex::encode(id.serialize());
        let bytes =
            kp.serialize().map_err(|e| DomainError::ThresholdError(format!("tr key package serialize: {e}")))?;
        store.put_share(&format!("frost-tr-dkg-id-{id_hex}"), &bytes)?;
        roster.push(id_hex);
    }
    let pk_bytes = state
        .pubkey_package
        .serialize()
        .map_err(|e| DomainError::ThresholdError(format!("tr pubkey package serialize: {e}")))?;
    store.put_share(TR_PUBKEY_SHARE_ID, &pk_bytes)?;
    store.put_share(TR_ROSTER_SHARE_ID, roster.join(",").as_bytes())?;
    store.put_share(TR_MIN_SHARE_ID, state.min_signers.to_string().as_bytes())?;
    Ok(())
}

/// Load Taproot FROST material previously sealed by [`persist_tr_shares`].
pub fn load_tr_shares(store: &dyn ShareStorePort) -> Result<FrostTrShareState, DomainError> {
    let roster_raw = store.get_share(TR_ROSTER_SHARE_ID)?;
    let roster = String::from_utf8(roster_raw)
        .map_err(|_| DomainError::ShareStoreForbidden("frost-tr roster is not utf8".into()))?;
    let min_raw = store.get_share(TR_MIN_SHARE_ID)?;
    let min_signers: usize = String::from_utf8(min_raw)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| DomainError::ShareStoreForbidden("frost-tr min_signers corrupt".into()))?;
    let pk_bytes = store.get_share(TR_PUBKEY_SHARE_ID)?;
    let pubkey_package = PublicKeyPackage::deserialize(&pk_bytes)
        .map_err(|e| DomainError::ThresholdError(format!("tr pubkey package deserialize: {e}")))?;

    let mut key_packages = BTreeMap::new();
    for id_hex in roster.split(',').filter(|s| !s.is_empty()) {
        let id_bytes = hex::decode(id_hex)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("frost-tr roster id hex: {e}")))?;
        let id = Identifier::deserialize(&id_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr identifier deserialize: {e}")))?;
        let kp_bytes = store.get_share(&format!("frost-tr-dkg-id-{id_hex}"))?;
        let kp = KeyPackage::deserialize(&kp_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr key package deserialize: {e}")))?;
        key_packages.insert(id, kp);
    }
    if key_packages.is_empty() {
        return Err(DomainError::ShareStoreForbidden("frost-tr roster empty".into()));
    }
    Ok(FrostTrShareState { key_packages, pubkey_package, min_signers })
}

/// Persist CHANNELS Taproot FROST key packages (≠ USERS omnibus share ids).
pub fn persist_tr_channels_shares(state: &FrostTrShareState, store: &dyn ShareStorePort) -> Result<(), DomainError> {
    let mut roster = Vec::new();
    for (id, kp) in &state.key_packages {
        let id_hex = hex::encode(id.serialize());
        let bytes =
            kp.serialize().map_err(|e| DomainError::ThresholdError(format!("tr-ch key package serialize: {e}")))?;
        store.put_share(&format!("frost-tr-channels-dkg-id-{id_hex}"), &bytes)?;
        roster.push(id_hex);
    }
    let pk_bytes = state
        .pubkey_package
        .serialize()
        .map_err(|e| DomainError::ThresholdError(format!("tr-ch pubkey package serialize: {e}")))?;
    store.put_share(TR_CHANNELS_PUBKEY_SHARE_ID, &pk_bytes)?;
    store.put_share(TR_CHANNELS_ROSTER_SHARE_ID, roster.join(",").as_bytes())?;
    store.put_share(TR_CHANNELS_MIN_SHARE_ID, state.min_signers.to_string().as_bytes())?;
    Ok(())
}

/// Load CHANNELS Taproot FROST material previously sealed by [`persist_tr_channels_shares`].
pub fn load_tr_channels_shares(store: &dyn ShareStorePort) -> Result<FrostTrShareState, DomainError> {
    let roster_raw = store.get_share(TR_CHANNELS_ROSTER_SHARE_ID)?;
    let roster = String::from_utf8(roster_raw)
        .map_err(|_| DomainError::ShareStoreForbidden("frost-tr-channels roster is not utf8".into()))?;
    let min_raw = store.get_share(TR_CHANNELS_MIN_SHARE_ID)?;
    let min_signers: usize = String::from_utf8(min_raw)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| DomainError::ShareStoreForbidden("frost-tr-channels min_signers corrupt".into()))?;
    let pk_bytes = store.get_share(TR_CHANNELS_PUBKEY_SHARE_ID)?;
    let pubkey_package = PublicKeyPackage::deserialize(&pk_bytes)
        .map_err(|e| DomainError::ThresholdError(format!("tr-ch pubkey package deserialize: {e}")))?;

    let mut key_packages = BTreeMap::new();
    for id_hex in roster.split(',').filter(|s| !s.is_empty()) {
        let id_bytes = hex::decode(id_hex)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("frost-tr-channels roster id hex: {e}")))?;
        let id = Identifier::deserialize(&id_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr-ch identifier deserialize: {e}")))?;
        let kp_bytes = store.get_share(&format!("frost-tr-channels-dkg-id-{id_hex}"))?;
        let kp = KeyPackage::deserialize(&kp_bytes)
            .map_err(|e| DomainError::ThresholdError(format!("tr-ch key package deserialize: {e}")))?;
        key_packages.insert(id, kp);
    }
    if key_packages.is_empty() {
        return Err(DomainError::ShareStoreForbidden("frost-tr-channels roster empty".into()));
    }
    Ok(FrostTrShareState { key_packages, pubkey_package, min_signers })
}

/// Multi-round Taproot FROST refresh DKG (preserves group verifying key → same `tb1p`).
pub fn refresh_tr_shares_in_process(
    old_key_packages: &BTreeMap<Identifier, KeyPackage>,
    old_pubkey: &PublicKeyPackage,
) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), DomainError> {
    use frost_secp256k1_tr::keys::refresh::{refresh_dkg_part1, refresh_dkg_part2, refresh_dkg_shares};

    if old_key_packages.is_empty() {
        return Err(DomainError::ThresholdError("tr reshare requires at least one key package".into()));
    }
    let identifiers: Vec<Identifier> = old_key_packages.keys().copied().collect();
    let max_signers = identifiers.len() as u16;
    let min_signers = *old_key_packages
        .values()
        .next()
        .map(|kp| kp.min_signers())
        .ok_or_else(|| DomainError::ThresholdError("empty tr key packages".into()))?;
    if max_signers < 2 || min_signers < 2 || min_signers > max_signers {
        return Err(DomainError::ThresholdError(format!("bad tr reshare params: max={max_signers} min={min_signers}")));
    }

    let mut rng = OsRng;

    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for id in &identifiers {
        let (secret, package) = refresh_dkg_part1(*id, max_signers, min_signers, &mut rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr refresh part1: {e}")))?;
        round1_secrets.insert(*id, secret);
        round1_packages.insert(*id, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut round2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for id in &identifiers {
        let mut received = round1_packages.clone();
        received.remove(id);
        let secret = round1_secrets
            .remove(id)
            .ok_or_else(|| DomainError::ThresholdError("missing tr refresh round1 secret".into()))?;
        let (r2_secret, outbound) = refresh_dkg_part2(secret, &received)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr refresh part2: {e}")))?;
        round2_secrets.insert(*id, r2_secret);
        for (receiver, package) in outbound {
            round2_inbox.entry(receiver).or_default().insert(*id, package);
        }
    }

    let old_vk = *old_pubkey.verifying_key();
    let mut new_key_packages = BTreeMap::new();
    let mut new_pubkey: Option<PublicKeyPackage> = None;
    for id in &identifiers {
        let mut r1_received = round1_packages.clone();
        r1_received.remove(id);
        let r2_received = round2_inbox
            .get(id)
            .ok_or_else(|| DomainError::ThresholdError(format!("missing tr refresh round2 inbox for {id:?}")))?;
        let r2_secret = round2_secrets
            .get(id)
            .ok_or_else(|| DomainError::ThresholdError("missing tr refresh round2 secret".into()))?;
        let old_kp = old_key_packages
            .get(id)
            .ok_or_else(|| DomainError::ThresholdError(format!("missing old tr key package for {id:?}")))?;
        let (kp, pk) = refresh_dkg_shares(r2_secret, &r1_received, r2_received, old_pubkey.clone(), old_kp.clone())
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr refresh part3: {e}")))?;

        if *kp.min_signers() != min_signers {
            return Err(DomainError::ThresholdError(format!(
                "tr reshare threshold drift: got {} want {min_signers}",
                kp.min_signers()
            )));
        }
        // Invariant: Taproot group verifying key MUST stay identical (deposit tb1p unchanged).
        if *pk.verifying_key() != old_vk {
            return Err(DomainError::ThresholdError("tr reshare changed group verifying key (forbidden)".into()));
        }
        new_key_packages.insert(*id, kp);
        new_pubkey = Some(pk);
    }

    let pubkey =
        new_pubkey.ok_or_else(|| DomainError::ThresholdError("tr reshare produced no pubkey package".into()))?;
    Ok((new_key_packages, pubkey))
}

#[derive(Debug)]
pub struct BitcoinSighashSignature {
    pub session_id: String,
    pub day_epoch: String,
    pub signature_hex: String,
    pub participants: usize,
    pub scheme: &'static str,
}

#[derive(Debug)]
pub struct SignedPsbtResult {
    pub session_id: String,
    pub day_epoch: String,
    pub signed_psbt: String,
    pub signatures: Vec<InputSignature>,
    pub participants: usize,
    pub participant_node_ids: Vec<String>,
    pub threshold: usize,
    pub scheme: &'static str,
}

pub struct FinancialQuorumProof {
    pub signature_hex: String,
    pub verifying_key_hex: String,
    pub participant_node_ids: Vec<String>,
    pub required_threshold: usize,
}

#[derive(Debug, Clone)]
pub struct InputSignature {
    pub input_index: usize,
    pub sighash_hex: String,
    pub signature_hex: String,
}

pub struct DepositInfo {
    pub network: String,
    pub xonly_pubkey_hex: String,
    pub output_pubkey_hex: String,
    pub address: String,
    pub descriptor: String,
    pub scheme: &'static str,
}

pub struct FrostTrBitcoinOrchestrator {
    shares: Arc<FrostTrShareSlot>,
    anti_nonce: Box<dyn AntiNoncePort>,
    rotation: Arc<dyn DailyRotationPort>,
    network: BitcoinNetwork,
    /// Lab `dealer_lab` may sign with N local shares in-process. Staging/prod /
    /// `distributed_wire` must use single local share + peer co-sign (Critical #1/#2).
    allow_local_multisign: bool,
    local_node_id: String,
    cosign: Option<Arc<dyn crate::adapters::TrCosignTransport>>,
    psbt_policy: PsbtPolicy,
}

impl FrostTrBitcoinOrchestrator {
    /// Produce an attributable FROST 2/3 proof for a canonical 32-byte
    /// financial proposal hash. Production always uses one local share plus
    /// authenticated peers; dealer-lab multi-share proofs are refused.
    pub fn sign_financial_quorum_proof(&self, proposal_hash: &[u8; 32]) -> Result<FinancialQuorumProof, DomainError> {
        if self.allow_local_multisign {
            return Err(DomainError::ThresholdError(
                "financial quorum proof requires distributed_wire; dealer_lab is forbidden".into(),
            ));
        }
        let snap = self.shares.snapshot()?;
        let transport = self.cosign.as_ref().ok_or_else(|| {
            DomainError::ThresholdError("financial quorum proof requires TR wire co-sign transport".into())
        })?;
        let session_id = format!("financial-quorum-{}", hex::encode(proposal_hash));
        let attributed = crate::adapters::sign_raw_wire_attributed(
            &self.shares,
            transport.as_ref(),
            &self.local_node_id,
            &session_id,
            proposal_hash,
        )?;
        let pubkey_tweaked = snap.pubkey_package.clone().into_even_y(None).tweak(None::<&[u8]>);
        let signature = attributed
            .signature
            .serialize()
            .map_err(|e| DomainError::ThresholdError(format!("signature serialize: {e}")))?;
        let verifying_key = pubkey_tweaked
            .verifying_key()
            .serialize()
            .map_err(|e| DomainError::ThresholdError(format!("verifying key serialize: {e}")))?;
        Ok(FinancialQuorumProof {
            signature_hex: hex::encode(signature),
            verifying_key_hex: hex::encode(verifying_key),
            participant_node_ids: attributed.participant_node_ids,
            required_threshold: snap.min_signers,
        })
    }

    pub fn new(
        shares: Arc<FrostTrShareSlot>,
        anti_nonce: Box<dyn AntiNoncePort>,
        rotation: Arc<dyn DailyRotationPort>,
        network: BitcoinNetwork,
    ) -> Self {
        Self {
            shares,
            anti_nonce,
            rotation,
            network,
            allow_local_multisign: cfg!(feature = "dealer_lab"),
            local_node_id: "local".into(),
            cosign: None,
            psbt_policy: PsbtPolicy::lab_defaults(),
        }
    }

    pub fn with_psbt_policy(mut self, policy: PsbtPolicy) -> Self {
        self.psbt_policy = policy;
        self
    }

    pub fn with_wire_cosign(
        mut self,
        local_node_id: impl Into<String>,
        allow_local_multisign: bool,
        cosign: Arc<dyn crate::adapters::TrCosignTransport>,
    ) -> Self {
        self.local_node_id = local_node_id.into();
        self.allow_local_multisign = allow_local_multisign;
        self.cosign = Some(cosign);
        self
    }

    /// Omnibus deposit address (shared mesh key). Same `tb1p` for all USERS.
    /// TODO(4.4): Add `deposit_address_for(user_id)` for per-user rotating addresses.
    /// See docs/ops/DEPOSIT_ADDRESS_STRATEGY.md for trade-off analysis.
    pub fn deposit_info(&self) -> Result<DepositInfo, DomainError> {
        let snap = self.shares.snapshot()?;
        let internal = xonly_from_verifying_key(snap.pubkey_package.verifying_key())?;
        let secp = Secp256k1::verification_only();
        let (output, _parity) = UntweakedPublicKey::from(internal).tap_tweak(&secp, None);
        let address = Address::p2tr_tweaked(output, to_bitcoin_network(self.network));
        let out_hex = hex::encode(output.to_x_only_public_key().serialize());
        let desc = format!("tr({out_hex})");
        Ok(DepositInfo {
            network: self.network.as_str().to_string(),
            xonly_pubkey_hex: hex::encode(internal.serialize()),
            output_pubkey_hex: out_hex,
            address: address.to_string(),
            descriptor: desc,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    /// Sign a raw 32-byte Bitcoin Taproot sighash (BIP-340). No message binding.
    pub fn sign_sighash(&self, session_id: &str, sighash32: &[u8]) -> Result<BitcoinSighashSignature, DomainError> {
        if sighash32.len() != 32 {
            return Err(DomainError::ThresholdError("bitcoin sighash must be exactly 32 bytes".into()));
        }
        self.anti_nonce.claim_session(session_id)?;
        let day_epoch = self.rotation.current_day_epoch()?;
        self.rotation.require_epoch(&day_epoch)?;

        let attributed = self.sign_raw_quorum(sighash32)?;
        let sig_bytes =
            attributed.signature.serialize().map_err(|e| DomainError::ThresholdError(format!("sig serialize: {e}")))?;
        Ok(BitcoinSighashSignature {
            session_id: session_id.to_string(),
            day_epoch: day_epoch.as_str().to_string(),
            signature_hex: hex::encode(sig_bytes),
            participants: self.shares.snapshot()?.min_signers,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    /// Intent-gated callers pass a funded PSBT; we bind outputs to Intent then sign
    /// Taproot key-path inputs that match the mesh deposit key.
    pub fn sign_psbt(
        &self,
        session_id: &str,
        psbt_b64: &str,
        destination: &str,
        amount_sats: u64,
    ) -> Result<SignedPsbtResult, DomainError> {
        self.anti_nonce.claim_session(session_id)?;
        let day_epoch = self.rotation.current_day_epoch()?;
        self.rotation.require_epoch(&day_epoch)?;

        let mut psbt =
            Psbt::from_str(psbt_b64.trim()).map_err(|e| DomainError::ThresholdError(format!("invalid psbt: {e}")))?;
        if psbt.inputs.is_empty() {
            return Err(DomainError::ThresholdError("psbt has no inputs".into()));
        }

        // High #13: fee / locktime / RBF policy before Intent bind / sign.
        validate_psbt(&self.psbt_policy, &psbt)?;

        let snap = self.shares.snapshot()?;
        let internal = xonly_from_verifying_key(snap.pubkey_package.verifying_key())?;
        let secp = Secp256k1::verification_only();
        let (tweaked, _) = UntweakedPublicKey::from(internal).tap_tweak(&secp, None);
        let our_output = tweaked.to_x_only_public_key();
        let mesh_change_spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(our_output));

        // Critical: bind Intent destination+amount to PSBT outputs before signing.
        let payment_spk = destination_script_pubkey(self.network, destination)?;
        let outs: Vec<(Vec<u8>, u64)> =
            psbt.unsigned_tx.output.iter().map(|o| (o.script_pubkey.to_bytes(), o.value.to_sat())).collect();
        crate::domain::assert_outputs_match_intent(
            &outs,
            payment_spk.as_bytes(),
            amount_sats,
            Some(mesh_change_spk.as_bytes()),
        )?;

        let prevouts = collect_prevouts(&psbt)?;
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        let mut signatures = Vec::new();
        let mut participant_node_ids = BTreeSet::new();

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let Some(utxo) = input.witness_utxo.as_ref() else {
                continue;
            };
            if !is_p2tr(&utxo.script_pubkey) {
                continue;
            }
            // Only sign outputs that match our Taproot key-path deposit key.
            if !script_matches_output_key(&utxo.script_pubkey, our_output) {
                continue;
            }
            if input.tap_key_sig.is_some() {
                continue;
            }

            let sighash = cache
                .taproot_key_spend_signature_hash(idx, &Prevouts::All(&prevouts), TapSighashType::Default)
                .map_err(|e| DomainError::ThresholdError(format!("taproot sighash: {e}")))?;
            let sighash_bytes = sighash.to_byte_array();
            let attributed = self.sign_raw_quorum(&sighash_bytes)?;
            participant_node_ids.extend(attributed.participant_node_ids);
            let sig_bytes = attributed
                .signature
                .serialize()
                .map_err(|e| DomainError::ThresholdError(format!("sig serialize: {e}")))?;
            let schnorr = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| DomainError::ThresholdError(format!("schnorr decode: {e}")))?;
            input.tap_key_sig = Some(TaprootSignature { signature: schnorr, sighash_type: TapSighashType::Default });
            signatures.push(InputSignature {
                input_index: idx,
                sighash_hex: hex::encode(sighash_bytes),
                signature_hex: hex::encode(sig_bytes),
            });
        }

        if signatures.is_empty() {
            return Err(DomainError::ThresholdError("no Taproot key-path inputs matched mesh deposit key".into()));
        }

        Ok(SignedPsbtResult {
            session_id: session_id.to_string(),
            day_epoch: day_epoch.as_str().to_string(),
            signed_psbt: psbt.to_string(),
            signatures,
            participants: participant_node_ids.len(),
            participant_node_ids: participant_node_ids.into_iter().collect(),
            threshold: snap.min_signers,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    fn sign_raw_quorum(&self, message: &[u8]) -> Result<crate::adapters::AttributedWireSignature, DomainError> {
        let snap = self.shares.snapshot()?;
        if self.allow_local_multisign {
            return Err(DomainError::ThresholdError("local multi-share signing was removed".into()));
        }
        if snap.key_packages.len() != 1 {
            return Err(DomainError::ThresholdError(
                "distributed signing requires exactly one local Taproot share".into(),
            ));
        }
        let transport = self.cosign.as_ref().ok_or_else(|| {
            DomainError::ThresholdError("distributed signing requires peer mTLS co-sign transport".into())
        })?;
        let session_id = format!("tr-wire-{}", hex::encode(sha2_first_16(message)));
        crate::adapters::sign_raw_wire_attributed(
            &self.shares,
            transport.as_ref(),
            &self.local_node_id,
            &session_id,
            message,
        )
    }
}

fn sha2_first_16(msg: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let dig = Sha256::digest(msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&dig[..16]);
    out
}

/// Lab dealer keygen for Taproot FROST (even-Y internal key; tweak applied at sign/deposit).
#[cfg(feature = "dealer_lab")]
pub fn generate_tr_dealer(max_signers: u16, min_signers: u16) -> Result<FrostTrShareState, DomainError> {
    let mut rng = OsRng;
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(max_signers, min_signers, frost::keys::IdentifierList::Default, &mut rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr dealer: {e}")))?;

    let pubkey_package = pubkey_package.into_even_y(None);
    let mut key_packages = BTreeMap::new();
    for (identifier, secret_share) in &shares {
        let kp = KeyPackage::try_from(secret_share.clone())
            .map_err(|e| DomainError::ThresholdError(format!("tr key package: {e}")))?
            .into_even_y(None);
        key_packages.insert(*identifier, kp);
    }

    Ok(FrostTrShareState { key_packages, pubkey_package, min_signers: min_signers as usize })
}

fn xonly_from_verifying_key(vk: &frost::VerifyingKey) -> Result<XOnlyPublicKey, DomainError> {
    let bytes = vk.serialize().map_err(|e| DomainError::ThresholdError(format!("verifying key serialize: {e}")))?;
    // frost-tr verifying key serialize is x-only (32) or compressed (33).
    let xonly_bytes: [u8; 32] = match bytes.len() {
        32 => bytes.as_slice().try_into().unwrap(),
        33 => bytes[1..].try_into().unwrap(),
        n => return Err(DomainError::ThresholdError(format!("unexpected verifying key length {n}"))),
    };
    XOnlyPublicKey::from_slice(&xonly_bytes).map_err(|e| DomainError::ThresholdError(format!("xonly: {e}")))
}

fn collect_prevouts(psbt: &Psbt) -> Result<Vec<TxOut>, DomainError> {
    let mut out = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(utxo) = &input.witness_utxo {
            out.push(utxo.clone());
            continue;
        }
        if let Some(tx) = &input.non_witness_utxo {
            let vout = psbt.unsigned_tx.input[i].previous_output.vout as usize;
            let txout = tx
                .output
                .get(vout)
                .cloned()
                .ok_or_else(|| DomainError::ThresholdError(format!("missing prevout {i}")))?;
            out.push(txout);
            continue;
        }
        return Err(DomainError::ThresholdError(format!("psbt input {i} missing witness_utxo")));
    }
    Ok(out)
}

fn is_p2tr(script: &ScriptBuf) -> bool {
    script.is_p2tr()
}

fn script_matches_output_key(script: &ScriptBuf, output_key: XOnlyPublicKey) -> bool {
    let expected = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key));
    *script == expected
}

impl DepositInfo {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"network":"{}","xonly_pubkey":"{}","output_pubkey":"{}","address":"{}","descriptor":"{}","scheme":"{}"}}"#,
            self.network, self.xonly_pubkey_hex, self.output_pubkey_hex, self.address, self.descriptor, self.scheme
        )
    }
}

impl BitcoinSighashSignature {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"session_id":"{}","day_epoch":"{}","signature":"{}","participants":{},"scheme":"{}"}}"#,
            self.session_id, self.day_epoch, self.signature_hex, self.participants, self.scheme
        )
    }
}

impl SignedPsbtResult {
    pub fn to_json(&self) -> String {
        let sigs: Vec<String> = self
            .signatures
            .iter()
            .map(|s| {
                format!(
                    r#"{{"input_index":{},"sighash":"{}","signature":"{}"}}"#,
                    s.input_index, s.sighash_hex, s.signature_hex
                )
            })
            .collect();
        let participant_ids = self
            .participant_node_ids
            .iter()
            .map(|id| serde_json::to_string(id).expect("node id JSON"))
            .collect::<Vec<_>>()
            .join(",");
        let signature = self.signatures.first().map(|value| value.signature_hex.as_str()).unwrap_or("");
        format!(
            r#"{{"session_id":"{}","day_epoch":"{}","signed_psbt":"{}","signatures":[{}],"signature":"{}","participants":{},"participant_ids":[{}],"threshold":{},"scheme":"{}"}}"#,
            self.session_id,
            self.day_epoch,
            self.signed_psbt,
            sigs.join(","),
            signature,
            self.participants,
            participant_ids,
            self.threshold,
            self.scheme
        )
    }
}

/// Lab helper: build a tiny unsigned key-path PSBT spending a synthetic P2TR UTXO
/// to `payment_spk` (Intent destination), with optional change back to mesh key.
#[cfg(all(test, feature = "dealer_lab"))]
pub fn lab_synthetic_funded_psbt(
    mesh_output_key: XOnlyPublicKey,
    network: bitcoin::Network,
    amount_sats: u64,
    payment_spk: ScriptBuf,
) -> Result<String, DomainError> {
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, Sequence, Transaction, TxIn, Witness};

    let mesh_spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(mesh_output_key));
    let fee = 500u64;
    let change = 200u64;
    let prev_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(amount_sats + fee + change), script_pubkey: mesh_spk.clone() }],
    };
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint { txid: prev_tx.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(amount_sats), script_pubkey: payment_spk },
            TxOut {
                value: Amount::from_sat(change),
                script_pubkey: Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(mesh_output_key),
                    network,
                )
                .script_pubkey(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).map_err(|e| DomainError::ThresholdError(format!("psbt: {e}")))?;
    psbt.inputs[0].witness_utxo =
        Some(TxOut { value: Amount::from_sat(amount_sats + fee + change), script_pubkey: mesh_spk });
    Ok(psbt.to_string())
}

#[cfg(all(test, feature = "dealer_lab"))]
mod tests {
    use super::*;
    use crate::adapters::{LedgerDayEpochStub, PersistedAntiNonce, SystemClock};
    use crate::application::ClockPort;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempProbe(std::path::PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-tr-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tr_sign_sighash_and_psbt_roundtrip() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("psbt");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> = Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(slot, Box::new(anti), rotation, BitcoinNetwork::Testnet3);
        let deposit = orch.deposit_info().unwrap();
        assert!(deposit.address.starts_with("tb1p"));
        assert!(deposit.descriptor.starts_with("tr("));

        let sighash = [7u8; 32];
        let sig = orch.sign_sighash("btc-sess-1", &sighash).unwrap();
        assert_eq!(sig.signature_hex.len(), 128);

        let output = XOnlyPublicKey::from_slice(&hex::decode(&deposit.output_pubkey_hex).unwrap()).unwrap();
        let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let payment_spk = destination_script_pubkey(BitcoinNetwork::Testnet3, dest).unwrap();
        let psbt = lab_synthetic_funded_psbt(output, bitcoin::Network::Testnet, 1_000, payment_spk).unwrap();
        let signed = orch.sign_psbt("btc-psbt-1", &psbt, dest, 1_000).unwrap();
        assert!(!signed.signed_psbt.is_empty());
        assert_eq!(signed.signatures.len(), 1);
        assert!(Psbt::from_str(&signed.signed_psbt).unwrap().inputs[0].tap_key_sig.is_some());
    }

    #[test]
    fn tr_rejects_unbound_psbt_destination() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("unbound");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> = Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(slot, Box::new(anti), rotation, BitcoinNetwork::Testnet3);
        let deposit = orch.deposit_info().unwrap();
        let output = XOnlyPublicKey::from_slice(&hex::decode(&deposit.output_pubkey_hex).unwrap()).unwrap();
        let claimed = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let attacker = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        let attacker_spk = destination_script_pubkey(BitcoinNetwork::Testnet3, attacker).unwrap();
        let psbt = lab_synthetic_funded_psbt(output, bitcoin::Network::Testnet, 1_000, attacker_spk).unwrap();
        let err = orch.sign_psbt("btc-psbt-atk", &psbt, claimed, 1_000).unwrap_err();
        assert!(matches!(err, DomainError::InvalidIntent(_)));
    }

    #[test]
    fn tr_rejects_non_mesh_change_output() {
        use bitcoin::absolute::LockTime;
        use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};

        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("change-escape");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> = Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(slot, Box::new(anti), rotation, BitcoinNetwork::Testnet3);
        let deposit = orch.deposit_info().unwrap();
        let output = XOnlyPublicKey::from_slice(&hex::decode(&deposit.output_pubkey_hex).unwrap()).unwrap();
        let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let payment_spk = destination_script_pubkey(BitcoinNetwork::Testnet3, dest).unwrap();
        // Core-style change to a different testnet address (not mesh tr()).
        let core_change = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        let change_spk = destination_script_pubkey(BitcoinNetwork::Testnet3, core_change).unwrap();
        let mesh_spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output));
        let amount_sats = 1_000u64;
        let fee = 500u64;
        let change = 200u64;
        let prev_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount_sats + fee + change),
                script_pubkey: mesh_spk.clone(),
            }],
        };
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint { txid: prev_tx.compute_txid(), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(amount_sats), script_pubkey: payment_spk },
                TxOut { value: Amount::from_sat(change), script_pubkey: change_spk },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        psbt.inputs[0].witness_utxo =
            Some(TxOut { value: Amount::from_sat(amount_sats + fee + change), script_pubkey: mesh_spk });
        let err = orch.sign_psbt("btc-psbt-chg", &psbt.to_string(), dest, amount_sats).unwrap_err();
        assert!(matches!(err, DomainError::InvalidIntent(_)));
        assert!(err.to_string().contains("change") || err.to_string().contains("non-tr"), "got {err}");
    }

    #[test]
    fn tr_rejects_session_reuse() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("reuse");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> = Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(slot, Box::new(anti), rotation, BitcoinNetwork::Testnet3);
        orch.sign_sighash("reuse-a", &[1u8; 32]).unwrap();
        let err = orch.sign_sighash("reuse-a", &[2u8; 32]).unwrap_err();
        assert!(matches!(err, DomainError::NonceReuse(_)));
    }

    #[test]
    fn tr_reshare_preserves_deposit_and_sign_works() {
        use crate::adapters::{
            AeadDiskShareStore, DealerLabAdapter, FrostShareSlot, FrostShareState, InMemoryLedger, PolicyReshareHook,
            QuorumDailyRotation,
        };
        use crate::domain::{Constitution, NodeId, ResharePolicy};

        let intent = DealerLabAdapter::generate(3, 2).unwrap();
        let tr = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("tr-reshare");
        let store = Arc::new(AeadDiskShareStore::new(tmp.0.join("shares"), "lab-tr-reshare-pass"));
        persist_tr_shares(&tr, store.as_ref()).unwrap();
        let loaded = load_tr_shares(store.as_ref()).unwrap();
        assert_eq!(loaded.pubkey_package.verifying_key(), tr.pubkey_package.verifying_key());

        let writer = NodeId::new("vault-1").unwrap();
        let ledger = Arc::new(
            InMemoryLedger::genesis(
                Constitution::v1_lab(3).unwrap(),
                vec![writer.clone(), NodeId::new("vault-2").unwrap(), NodeId::new("vault-3").unwrap()],
                writer.clone(),
            )
            .unwrap(),
        );
        let intent_slot = Arc::new(FrostShareSlot::new());
        intent_slot.install(FrostShareState {
            key_packages: intent.key_packages,
            pubkey_package: intent.pubkey_package,
            min_signers: 2,
        });
        let tr_slot = Arc::new(FrostTrShareSlot::new());
        tr_slot.install(tr);
        let hook = Arc::new(
            PolicyReshareHook::new(ResharePolicy::Daily, ledger, writer, intent_slot, tr_slot.clone())
                .with_share_store(store.clone()),
        );

        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200)));
        let rotation: Arc<dyn DailyRotationPort> =
            Arc::new(QuorumDailyRotation::with_persist(clock.clone(), 1, "v1", hook, tmp.0.join("day_epoch")));
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let orch = FrostTrBitcoinOrchestrator::new(
            tr_slot.clone(),
            Box::new(anti),
            rotation.clone(),
            BitcoinNetwork::Testnet3,
        );
        let before = orch.deposit_info().unwrap();
        assert!(before.address.starts_with("tb1p"));

        // Advance day → Intent + Taproot reshare; deposit must stay identical.
        clock.0.store(1_704_067_200 + 86_400, Ordering::SeqCst);
        assert_eq!(rotation.advance().unwrap().as_str(), "2024-01-02");
        let after = orch.deposit_info().unwrap();
        assert_eq!(before.address, after.address);
        assert_eq!(before.output_pubkey_hex, after.output_pubkey_hex);
        assert_eq!(before.descriptor, after.descriptor);

        let sig = orch.sign_sighash("post-reshare-1", &[9u8; 32]).unwrap();
        assert_eq!(sig.signature_hex.len(), 128);
        assert_eq!(sig.day_epoch, "2024-01-02");

        // ShareStorePort after reshare still yields same group key.
        let reloaded = load_tr_shares(store.as_ref()).unwrap();
        assert_eq!(
            *reloaded.pubkey_package.verifying_key(),
            *tr_slot.snapshot().unwrap().pubkey_package.verifying_key()
        );
    }

    #[test]
    fn refresh_tr_n3_preserves_group_key() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let old_vk = *state.pubkey_package.verifying_key();
        let (new_packages, new_pk) = refresh_tr_shares_in_process(&state.key_packages, &state.pubkey_package).unwrap();
        assert_eq!(new_packages.len(), 3);
        assert_eq!(*new_pk.verifying_key(), old_vk);
        let mut changed = false;
        for (id, old_kp) in &state.key_packages {
            if old_kp.signing_share() != new_packages[id].signing_share() {
                changed = true;
                break;
            }
        }
        assert!(changed, "expected refreshed TR signing shares to differ");
    }

    struct FakeClock(AtomicU64);
    impl ClockPort for FakeClock {
        fn unix_now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
}
