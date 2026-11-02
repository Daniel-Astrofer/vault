//! Key lifecycle state machine: Genesis, Rotation, Expiration, Revocation.
//!
//! Manages lifecycle for identity, transport, and audit keys across both
//! classical (Ed25519/X25519) and PQ (ML-DSA-65/ML-KEM-768) domains.
//!
//! # Atomic rotation
//! Classical and PQ identity keys rotate together. No window where only one
//! key type has been rotated.

use vault_domain::{DayEpoch, DomainError};

/// Key lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLifecycleEvent {
    /// A key was created for the specified domain.
    Created {
        /// Identifier of the newly created key.
        key_id: String,
        /// Namespace describing the key's purpose.
        key_domain: KeyDomain,
        /// Day epoch when creation was recorded.
        at_epoch: DayEpoch,
    },
    /// A key was replaced while retaining a link to its predecessor.
    Rotated {
        /// Identifier of the key that was replaced.
        old_key_id: String,
        /// Identifier of the replacement key.
        new_key_id: String,
        /// Namespace of both keys in the rotation.
        key_domain: KeyDomain,
        /// Day epoch when the rotation was recorded.
        at_epoch: DayEpoch,
    },
    /// A key passed its configured expiration epoch.
    Expired {
        /// Identifier of the expired key.
        key_id: String,
        /// Day epoch at which expiration was observed.
        at_epoch: DayEpoch,
    },
    /// A key was administratively or operationally revoked.
    Revoked {
        /// Identifier of the revoked key.
        key_id: String,
        /// Recorded explanation for the revocation.
        reason: String,
        /// Day epoch when revocation was recorded.
        at_epoch: DayEpoch,
    },
}

/// Key domain namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDomain {
    /// Keys used to authenticate the node's signing identity.
    Identity,
    /// Keys used to establish protected peer transport.
    Transport,
    /// Keys used to sign or verify audit records.
    Audit,
}

impl KeyDomain {
    /// Return the stable lowercase namespace label used in key metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyDomain::Identity => "identity",
            KeyDomain::Transport => "transport",
            KeyDomain::Audit => "audit",
        }
    }
}

/// Individual key metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Stable identifier for this key version.
    pub key_id: String,
    /// Purpose namespace that constrains where the key may be used.
    pub key_domain: KeyDomain,
    /// Day epoch when this key became part of the lifecycle state.
    pub created_at: DayEpoch,
    /// Last epoch on which the key remains valid; absent means no scheduled expiry.
    pub expires_at: Option<DayEpoch>,
    /// Epoch when the key was revoked, if it was revoked.
    pub revoked_at: Option<DayEpoch>,
    /// Previous key version replaced by this key, if any.
    pub parent_key_id: Option<String>,
}

impl KeyMetadata {
    /// Return whether the key is neither revoked nor past its expiration epoch.
    ///
    /// A key is still active on the exact epoch stored in `expires_at`.
    pub fn is_active(&self, current_epoch: &DayEpoch) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(ref exp) = self.expires_at {
            if current_epoch > exp {
                return false;
            }
        }
        true
    }

    /// Return whether a revocation epoch has been recorded.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Return whether the current epoch is strictly later than the expiration epoch.
    pub fn is_expired(&self, current_epoch: &DayEpoch) -> bool {
        self.expires_at.as_ref().is_some_and(|exp| current_epoch > exp)
    }
}

/// Complete key lifecycle state for a vault node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLifecycle {
    /// Current classical identity signing key metadata.
    pub identity_classical: Option<KeyMetadata>,
    /// Current post-quantum identity signing key metadata.
    pub identity_pq: Option<KeyMetadata>,
    /// Current classical transport key metadata.
    pub transport_classical: Option<KeyMetadata>,
    /// Current post-quantum transport key metadata.
    pub transport_pq: Option<KeyMetadata>,
    /// Current classical audit signing key metadata.
    pub audit_classical: Option<KeyMetadata>,
    /// Current post-quantum audit signing key metadata.
    pub audit_pq: Option<KeyMetadata>,
}

impl KeyLifecycle {
    /// Create an empty lifecycle state before genesis key provisioning.
    pub fn new() -> Self {
        Self {
            identity_classical: None,
            identity_pq: None,
            transport_classical: None,
            transport_pq: None,
            audit_classical: None,
            audit_pq: None,
        }
    }

    /// Validate that identity keys are present (both classical and PQ) and active.
    /// Require both classical and post-quantum identity keys to be active at `epoch`.
    pub fn validate_identity_active(&self, epoch: &DayEpoch) -> Result<(), DomainError> {
        match (&self.identity_classical, &self.identity_pq) {
            (Some(c), Some(p)) => {
                if !c.is_active(epoch) {
                    return Err(DomainError::InvalidIntent("classical identity key expired or revoked".into()));
                }
                if !p.is_active(epoch) {
                    return Err(DomainError::InvalidIntent("PQ identity key expired or revoked".into()));
                }
                Ok(())
            }
            _ => Err(DomainError::InvalidIntent("identity keys not yet generated (genesis required)".into())),
        }
    }

    /// Validate that transport keys are present and active.
    /// Require both classical and post-quantum transport keys to be active at `epoch`.
    pub fn validate_transport_active(&self, epoch: &DayEpoch) -> Result<(), DomainError> {
        match (&self.transport_classical, &self.transport_pq) {
            (Some(c), Some(p)) => {
                if !c.is_active(epoch) || !p.is_active(epoch) {
                    return Err(DomainError::InvalidIntent("transport keys expired or revoked".into()));
                }
                Ok(())
            }
            _ => Err(DomainError::InvalidIntent("transport keys not yet generated (genesis required)".into())),
        }
    }
}

impl Default for KeyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}
