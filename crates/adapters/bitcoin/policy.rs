//! Translation between pure PSBT policy and `bitcoin` crate values.

use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Network, ScriptBuf};

use crate::domain::{assert_outputs_match_intent, BitcoinNetwork, DomainError, PsbtPolicy, RbfPolicy};

/// Converts the domain Bitcoin network identifier to the `bitcoin` crate enum.
pub fn to_bitcoin_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Testnet3 => Network::Testnet,
    }
}

/// Validates a destination for the configured network and derives its script.
///
/// Both domain-level address checks and the Bitcoin library's network check are
/// applied. Invalid address syntax returns `InvalidIntent`; network mismatches
/// return `BitcoinNetworkMismatch`.
pub fn destination_script_pubkey(network: BitcoinNetwork, destination: &str) -> Result<ScriptBuf, DomainError> {
    crate::domain::validate_destination(network, destination)?;
    let unchecked = destination.trim().parse::<Address<NetworkUnchecked>>().map_err(|_| {
        DomainError::InvalidIntent("PSBT Intent bind requires a Bitcoin testnet3 address destination".into())
    })?;
    let checked = unchecked
        .require_network(to_bitcoin_network(network))
        .map_err(|_| DomainError::BitcoinNetworkMismatch(format!("address not valid for {}", network.as_str())))?;
    Ok(checked.script_pubkey())
}

/// Validates PSBT input/output values, absolute fee, fee rate, locktime, and RBF policy.
///
/// Every input must provide a witness UTXO or a previous transaction containing
/// the referenced output. This checks the fee and transaction policy only; it
/// does not bind outputs to a particular Intent or verify ownership of inputs.
pub fn validate_psbt(policy: &PsbtPolicy, psbt: &Psbt) -> Result<(), DomainError> {
    let tx = &psbt.unsigned_tx;
    let mut input_sats = 0u64;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let value = if let Some(utxo) = &input.witness_utxo {
            utxo.value.to_sat()
        } else if let Some(previous_tx) = &input.non_witness_utxo {
            previous_tx
                .output
                .get(tx.input[index].previous_output.vout as usize)
                .map(|output| output.value.to_sat())
                .ok_or_else(|| DomainError::InvalidIntent(format!("psbt input {index} missing prevout value")))?
        } else {
            return Err(DomainError::InvalidIntent(format!("psbt input {index} missing witness_utxo for fee policy")));
        };
        input_sats = input_sats.saturating_add(value);
    }
    let output_sats: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
    if output_sats > input_sats {
        return Err(DomainError::InvalidIntent("psbt outputs exceed inputs".into()));
    }
    let fee = input_sats - output_sats;
    if fee > policy.max_fee_sats {
        return Err(DomainError::InvalidIntent(format!(
            "psbt fee {fee} sats exceeds max_fee_sats {}",
            policy.max_fee_sats
        )));
    }
    let vbytes = tx.weight().to_wu().div_ceil(4).max(1);
    if fee / vbytes > policy.max_fee_rate_sat_vb {
        return Err(DomainError::InvalidIntent(format!("psbt fee rate exceeds max {}", policy.max_fee_rate_sat_vb)));
    }
    if tx.lock_time != LockTime::ZERO {
        let raw = tx.lock_time.to_consensus_u32();
        if policy.max_locktime == 0 || raw > policy.max_locktime {
            return Err(DomainError::InvalidIntent(format!("psbt locktime {raw} exceeds policy")));
        }
    }
    for (index, input) in tx.input.iter().enumerate() {
        let signals_rbf = input.sequence.to_consensus_u32() < 0xffff_fffe;
        match policy.rbf {
            RbfPolicy::Require if !signals_rbf => {
                return Err(DomainError::InvalidIntent(format!("psbt input {index} must signal RBF")))
            }
            RbfPolicy::Forbid if signals_rbf => {
                return Err(DomainError::InvalidIntent(format!("psbt input {index} RBF signalling forbidden")))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Applies transaction policy and binds unsigned outputs to an Intent payment.
///
/// The payment script and amount must match the requested destination; any
/// additional permitted change is checked against `change_script` by the domain
/// binding rule. This function does not sign the PSBT.
pub fn validate_psbt_independent(
    policy: &PsbtPolicy,
    psbt: &Psbt,
    payment_script: &[u8],
    amount_sats: u64,
    change_script: Option<&[u8]>,
) -> Result<(), DomainError> {
    validate_psbt(policy, psbt)?;
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|output| (output.script_pubkey.as_bytes().to_vec(), output.value.to_sat()))
        .collect::<Vec<_>>();
    assert_outputs_match_intent(&outputs, payment_script, amount_sats, change_script)
}
