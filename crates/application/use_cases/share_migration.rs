//! Share migration between crypto suites.
//!
//! When the vault mesh upgrades to a new crypto suite (e.g., classical → hybrid),
//! on-disk shares sealed under the old suite must be detected, unsealed, and
//! re-sealed under the new suite. Migration is atomic: the old share is deleted
//! only after the new share is persisted and verified.

use vault_domain::DomainError;

/// Trait for migrating share persistence between crypto suites.
pub trait ShareMigrationPort: Send + Sync {
    /// Detect shares with stale `suite_id`. Returns the list of share IDs
    /// that need migration.
    fn detect_stale_shares(&self, old_suite_id: &str) -> Result<Vec<String>, DomainError>;

    /// Unseal a share encrypted under the old suite, returning plaintext.
    fn unseal_old(&self, share_id: &str, old_suite_id: &str) -> Result<Vec<u8>, DomainError>;

    /// Re-seal plaintext under the new suite.
    fn reseal_new(&self, share_id: &str, plaintext: &[u8], new_suite_id: &str) -> Result<(), DomainError>;

    /// Delete a share from the old suite (only after new copy verified).
    fn delete_old(&self, share_id: &str, old_suite_id: &str) -> Result<(), DomainError>;

    /// Atomic migration of a single share:
    /// 1. Unseal with old suite
    /// 2. Re-seal with new suite (persist)
    /// 3. Verify new share can be read back
    /// 4. Delete old share
    fn migrate_one(&self, share_id: &str, old_suite_id: &str, new_suite_id: &str) -> Result<(), DomainError> {
        let plaintext = self.unseal_old(share_id, old_suite_id)?;
        self.reseal_new(share_id, &plaintext, new_suite_id)?;

        // Verify: read back under new suite and confirm plaintext matches.
        let verified = self.unseal_old(share_id, new_suite_id)?;
        if verified != plaintext {
            return Err(DomainError::ShareStoreForbidden(format!(
                "migration verify failed for {share_id}: plaintext mismatch"
            )));
        }

        self.delete_old(share_id, old_suite_id)?;
        Ok(())
    }

    /// Migrate all stale shares in one batch.
    fn migrate_all_stale(&self, old_suite_id: &str, new_suite_id: &str) -> Result<usize, DomainError> {
        let stale = self.detect_stale_shares(old_suite_id)?;
        if stale.is_empty() {
            return Ok(0);
        }
        for share_id in &stale {
            self.migrate_one(share_id, old_suite_id, new_suite_id)?;
        }
        Ok(stale.len())
    }
}

/// No-op migration: no shares to migrate, no stale suite detected.
pub struct NoopShareMigration;

impl ShareMigrationPort for NoopShareMigration {
    fn detect_stale_shares(&self, _old_suite_id: &str) -> Result<Vec<String>, DomainError> {
        Ok(Vec::new())
    }

    fn unseal_old(&self, share_id: &str, _old_suite_id: &str) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::ShareStoreForbidden(format!("noop migration cannot unseal {share_id}")))
    }

    fn reseal_new(&self, share_id: &str, _plaintext: &[u8], _new_suite_id: &str) -> Result<(), DomainError> {
        Err(DomainError::ShareStoreForbidden(format!("noop migration cannot reseal {share_id}")))
    }

    fn delete_old(&self, share_id: &str, _old_suite_id: &str) -> Result<(), DomainError> {
        Err(DomainError::ShareStoreForbidden(format!("noop migration cannot delete {share_id}")))
    }
}
