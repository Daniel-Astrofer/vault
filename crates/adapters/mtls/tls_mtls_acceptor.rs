//! Inject verified mTLS client leaf into Axum request extensions.
//!
//! `axum-server` does not expose peer certs by default; this acceptor wraps
//! `RustlsAcceptor` and layers `PeerClientCert` after the handshake.

use std::io;
use std::sync::Arc;

use axum::middleware::AddExtension;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use futures_util::future::BoxFuture;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

use super::tls_peer_verify::extract_sans;
use crate::domain::DomainError;
use crate::{principal_from_cert_sans, MeshPrincipal};
use std::collections::HashSet;

/// Leaf client certificate DER from the completed mTLS handshake.
#[derive(Clone, Debug)]
pub struct PeerClientCert {
    /// DER-encoded leaf certificate bytes, shared across request extensions.
    pub leaf_der: Arc<[u8]>,
}

impl PeerClientCert {
    /// Copies a rustls certificate into the request-extension representation.
    pub fn from_der(der: CertificateDer<'static>) -> Self {
        Self { leaf_der: Arc::from(der.as_ref().to_vec().into_boxed_slice()) }
    }

    /// Extracts URI and DNS subject alternative names from the leaf certificate.
    pub fn uri_and_dns_sans(&self) -> Result<(Vec<String>, Vec<String>), DomainError> {
        extract_sans(self.leaf_der.as_ref())
    }

    /// Resolves this certificate's SANs to a mesh principal and validates its node ID.
    pub fn to_principal(
        &self,
        local_node_id: &str,
        allowed_vault_ids: &HashSet<String>,
    ) -> Result<MeshPrincipal, DomainError> {
        let (uris, dns) = self.uri_and_dns_sans()?;
        principal_from_cert_sans(&uris, &dns, local_node_id, allowed_vault_ids)
    }
}

/// Rustls acceptor that attaches [`PeerClientCert`] to every request on the connection.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    /// Wraps an existing rustls acceptor while preserving its TLS configuration.
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }

    /// Builds a peer-certificate acceptor from a rustls server configuration.
    ///
    /// Client certificate trust and verification remain controlled by that
    /// server configuration; this wrapper only exposes the verified leaf.
    pub fn from_config(config: Arc<rustls::ServerConfig>) -> Self {
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(config);
        Self::new(RustlsAcceptor::new(rustls_config))
    }
}

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, Option<PeerClientCert>>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let server_conn = stream.get_ref().1;
            let peer = server_conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| PeerClientCert::from_der(c.clone()));
            let service = Extension(peer).layer(service);
            Ok((stream, service))
        })
    }
}
