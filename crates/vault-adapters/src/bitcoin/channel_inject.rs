//! CHANNELS -> LND channel inject stub (Item 4.7).
//!
//! Defines the `ChannelInjectPort` trait and a stub implementation that returns
//! `NotImplemented` until real LND REST integration is built.
//!
//! ## Real Implementation (FUTURE)
//!
//! When implemented, `RealChannelInject` will:
//! 1. **Soft-reserve** the Intents CHANNELS fund step (non-mutating decision gate).
//! 2. **Caps check**: ensure channel amount within configured CHANNELS limits.
//! 3. **Allowlist**: validate LND peer pubkey against mesh-configured allowed peers.
//! 4. **PSBT construction**: create a Taproot PSBT from the mesh CHANNELS key to the
//!    LND funding address (BOLT 2 `funding_created` with `open_channel` RPC).
//! 5. **LND REST call**: POST to LND REST API (`/v1/channels`) with `funding_txid`
//!    and commitment from PSBT.
//! 6. **Commit**: durable Intent id + phase resume; pending-channels refuse until
//!    confirmed.
//! 7. **Retry reconciler**: commit-retry on LND REST failures; fail-closed without
//!    mesh fund txid.
//!
//! Fail-closed invariant: if the mesh cannot produce a valid funding txid, the
//! Intent is rejected and funds stay in CHANNELS pool.

use crate::application::ports::ChannelInjectPort;
use crate::domain::DomainError;

/// Stub that returns `NotImplemented` for all channel injection operations.
/// Replaced with `RealChannelInject` after LND REST integration.
pub struct StubChannelInject;

impl ChannelInjectPort for StubChannelInject {
    fn open_channel(
        &self,
        _lnd_peer_pubkey: &str,
        _funding_amount_sats: u64,
        _push_sats: u64,
    ) -> Result<String, DomainError> {
        Err(DomainError::RequestRejected("channel_inject: not implemented (LND REST stub)".into()))
    }

    fn close_channel(&self, _channel_point: &str, _force: bool) -> Result<String, DomainError> {
        Err(DomainError::RequestRejected("channel_inject: close not implemented (LND REST stub)".into()))
    }
}
