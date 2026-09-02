//! Mutual TLS auth (Production Gate path). Lab may opt in via `VAULT_AUTH_MODE=mtls`.
//! Peer authentication happens at the rustls handshake; this adapter refuses static tokens.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::application::VaultAuthPort;
use crate::domain::DomainError;

/// Auth port for mTLS mode: transport already verified the client certificate.
pub struct MutualTlsAuthAdapter {
    reshare_trigger_allowed: bool,
    /// Expected Ed25519 public key from the vault's hybrid identity.
    /// Used to verify cert fingerprint binding at the application layer.
    identity_ed25519_pub: Option<[u8; 32]>,
}

impl MutualTlsAuthAdapter {
    pub fn new() -> Self {
        Self { reshare_trigger_allowed: false, identity_ed25519_pub: None }
    }

    pub fn with_reshare_trigger(allowed: bool) -> Self {
        Self { reshare_trigger_allowed: allowed, identity_ed25519_pub: None }
    }

    /// Bind this mTLS adapter to a vault's hybrid identity.
    /// The Ed25519 public key is used to verify the cert fingerprint
    /// matches the identity registered in the roster.
    pub fn with_identity(mut self, ed25519_pub: [u8; 32]) -> Self {
        self.identity_ed25519_pub = Some(ed25519_pub);
        self
    }

    /// Return the bound Ed25519 public key, if set.
    pub fn identity_ed25519_pub(&self) -> Option<[u8; 32]> {
        self.identity_ed25519_pub
    }
}

impl Default for MutualTlsAuthAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultAuthPort for MutualTlsAuthAdapter {
    fn mode_name(&self) -> &'static str {
        "mtls"
    }

    fn is_static_token(&self) -> bool {
        false
    }

    fn authorize(&self, token_header: Option<&str>) -> Result<(), DomainError> {
        // Identity is the verified client cert from rustls — not X-Vault-Token.
        if token_header.filter(|t| !t.is_empty()).is_some() {
            return Err(DomainError::AuthRejected(
                "static X-Vault-Token refused in mTLS mode; use client certificate".into(),
            ));
        }
        Ok(())
    }

    fn authorize_reshare_trigger(&self) -> Result<(), DomainError> {
        if !self.reshare_trigger_allowed {
            return Err(DomainError::AuthRejected(
                "manual reshare trigger refused under mTLS without VAULT_ALLOW_MANUAL_RESHARE=1 (or lab)".into(),
            ));
        }
        Ok(())
    }
}

/// Build a rustls `ServerConfig` that requires and verifies client certificates against `client_ca_path`.
pub fn build_mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<Arc<ServerConfig>, DomainError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| DomainError::AuthRejected(format!("read VAULT_TLS_CERT_PATH {}: {e}", cert_path.display())))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| DomainError::AuthRejected(format!("read VAULT_TLS_KEY_PATH {}: {e}", key_path.display())))?;
    let ca_pem = std::fs::read(client_ca_path).map_err(|e| {
        DomainError::AuthRejected(format!("read VAULT_TLS_CLIENT_CA_PATH {}: {e}", client_ca_path.display()))
    })?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DomainError::AuthRejected(format!("parse server cert PEM: {e}")))?;
    if certs.is_empty() {
        return Err(DomainError::AuthRejected("VAULT_TLS_CERT_PATH contains no certificates".into()));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| DomainError::AuthRejected(format!("parse server key PEM: {e}")))?
        .ok_or_else(|| DomainError::AuthRejected("VAULT_TLS_KEY_PATH contains no private key".into()))?;

    let mut roots = RootCertStore::empty();
    let mut ca_count = 0usize;
    for ca in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        let ca = ca.map_err(|e| DomainError::AuthRejected(format!("parse client CA PEM: {e}")))?;
        roots.add(ca).map_err(|e| DomainError::AuthRejected(format!("add client CA: {e}")))?;
        ca_count += 1;
    }
    if ca_count == 0 {
        return Err(DomainError::AuthRejected("VAULT_TLS_CLIENT_CA_PATH contains no certificates".into()));
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| DomainError::AuthRejected(format!("client cert verifier: {e}")))?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| DomainError::AuthRejected(format!("mTLS server cert/key: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtls_authorize_ok_without_token() {
        assert!(MutualTlsAuthAdapter::new().authorize(None).is_ok());
        assert!(MutualTlsAuthAdapter::new().authorize(Some("")).is_ok());
    }

    #[test]
    fn mtls_authorize_refuses_static_token_header() {
        let err = MutualTlsAuthAdapter::new().authorize(Some("kerosene-vault-lab-only")).unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
    }

    #[test]
    fn mtls_allows_treasury_sign() {
        assert!(MutualTlsAuthAdapter::new().authorize_treasury_sign().is_ok());
    }

    #[test]
    fn mtls_reshare_trigger_refused_by_default() {
        let err = MutualTlsAuthAdapter::new().authorize_reshare_trigger().unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
        assert!(MutualTlsAuthAdapter::with_reshare_trigger(true).authorize_reshare_trigger().is_ok());
    }

    #[test]
    fn mtls_is_not_static_token_mode() {
        let a = MutualTlsAuthAdapter::new();
        assert_eq!(a.mode_name(), "mtls");
        assert!(!a.is_static_token());
    }
}
