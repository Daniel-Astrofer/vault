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
    Created { key_id: String, key_domain: KeyDomain, at_epoch: DayEpoch },
    Rotated { old_key_id: String, new_key_id: String, key_domain: KeyDomain, at_epoch: DayEpoch },
    Expired { key_id: String, at_epoch: DayEpoch },
    Revoked { key_id: String, reason: String, at_epoch: DayEpoch },
}

/// Key domain namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDomain {
    Identity,
    Transport,
    Audit,
}

impl KeyDomain {
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
    pub key_id: String,
    pub key_domain: KeyDomain,
    pub created_at: DayEpoch,
    pub expires_at: Option<DayEpoch>,
    pub revoked_at: Option<DayEpoch>,
    pub parent_key_id: Option<String>,
}

impl KeyMetadata {
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

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired(&self, current_epoch: &DayEpoch) -> bool {
        self.expires_at.as_ref().is_some_and(|exp| current_epoch > exp)
    }
}

/// Complete key lifecycle state for a vault node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLifecycle {
    pub identity_classical: Option<KeyMetadata>,
    pub identity_pq: Option<KeyMetadata>,
    pub transport_classical: Option<KeyMetadata>,
    pub transport_pq: Option<KeyMetadata>,
    pub audit_classical: Option<KeyMetadata>,
    pub audit_pq: Option<KeyMetadata>,
}

impl KeyLifecycle {
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
