use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::{build_mtls_rustls_client_config, PeerHttpSettings, TlsPeerVerifyPolicy};
use crate::application::ports::PeerDirectoryPort;
use crate::application::OnlineStatusPort;
use crate::domain::DomainError;

/// Honest online count for fail-stop: self + peers that answer the configured liveness endpoint.
///
/// Unreachable / unknown peers are **not** counted (fail-closed). Does not
/// invent liveness from `VAULT_ONLINE_COUNT` alone when peers are configured.
pub struct ProbedOnlineCount {
    peers: Arc<dyn PeerDirectoryPort>,
    peer_health_urls: Vec<String>,
    peer_http: PeerHttpSettings,
    auth_token: Option<String>,
    tls: Option<rustls::ClientConfig>,
    /// Optional ceiling (from `VAULT_ONLINE_COUNT`); never raises above probed.
    max_online: Option<usize>,
    /// When true (lab only), skip probing and report `lab_static` — tests only.
    lab_static: Option<usize>,
}

impl ProbedOnlineCount {
    /// Creates a health-probed counter using optional static-token auth.
    ///
    /// `max_online` is only a ceiling; it never increases the number proven by
    /// successful probes. When no health URLs are supplied, clearnet peer TCP
    /// endpoints are used as a weaker fallback.
    pub fn new(
        peers: Arc<dyn PeerDirectoryPort>,
        peer_health_urls: Vec<String>,
        peer_http: PeerHttpSettings,
        auth_token: Option<String>,
        max_online: Option<usize>,
    ) -> Self {
        Self { peers, peer_health_urls, peer_http, auth_token, tls: None, max_online, lab_static: None }
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates a health-probed counter using the supplied mTLS client identity.
    ///
    /// The static-token path is disabled. TLS setup errors are returned before
    /// any peer probes are attempted.
    pub fn with_mtls(
        peers: Arc<dyn PeerDirectoryPort>,
        peer_health_urls: Vec<String>,
        peer_http: PeerHttpSettings,
        client_cert_path: &Path,
        client_key_path: &Path,
        ca_path: &Path,
        verify: &TlsPeerVerifyPolicy,
        max_online: Option<usize>,
    ) -> Result<Self, DomainError> {
        let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
        Ok(Self { peers, peer_health_urls, peer_http, auth_token: None, tls: Some(tls), max_online, lab_static: None })
    }

    /// Lab / unit harness: fixed count without probing (never used in hardened boot).
    pub fn lab_static(count: usize) -> Self {
        Self {
            peers: Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            peer_health_urls: vec![],
            peer_http: PeerHttpSettings::clearnet_defaults(),
            auth_token: None,
            tls: None,
            max_online: None,
            lab_static: Some(count),
        }
    }

    fn probe_timeout(&self) -> Duration {
        // Onion circuits often need more than five seconds. Honor the configured
        // connection budget, bounded by the total request budget and a health cap.
        let cap = if self.peer_http.transport.is_tor() { Duration::from_secs(15) } else { Duration::from_millis(500) };
        self.peer_http.connect_timeout.min(self.peer_http.timeout).min(cap)
    }

    fn probe_url(&self, url: &str) -> bool {
        let mut builder = match self.peer_http.apply_blocking_builder(reqwest::blocking::Client::builder()) {
            Ok(b) => b,
            Err(_) => return false,
        };
        builder = builder.timeout(self.probe_timeout());
        if let Some(tls) = self.tls.clone() {
            builder = builder.use_preconfigured_tls(tls);
        }
        let Ok(client) = builder.build() else {
            return false;
        };
        let mut req = client.get(url);
        if let Some(token) = self.auth_token.as_deref() {
            req = req.header("X-Vault-Token", token);
        }
        match req.send() {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Cheap clearnet TCP when HTTP bases are empty but peers have host:port.
    fn cheap_tcp(addr: &str) -> bool {
        let trimmed = addr.trim();
        if trimmed.is_empty() || trimmed.contains(".onion") {
            return false;
        }
        let candidate = if trimmed.contains(':') { trimmed.to_string() } else { format!("{trimmed}:7701") };
        let Ok(mut iter) = candidate.to_socket_addrs() else {
            return false;
        };
        let Some(sa) = iter.next() else {
            return false;
        };
        std::net::TcpStream::connect_timeout(&sa, Duration::from_millis(80)).is_ok()
    }
}

impl OnlineStatusPort for ProbedOnlineCount {
    /// Counts this process and peers that pass the configured liveness probe.
    ///
    /// Lab static mode returns its fixed value. Otherwise unresponsive and
    /// unknown peers are excluded, and the optional configured ceiling is applied.
    fn online_count(&self) -> usize {
        if let Some(n) = self.lab_static {
            return n;
        }
        // Self is always online in this process.
        let mut online = 1usize;
        if !self.peer_health_urls.is_empty() {
            for url in &self.peer_health_urls {
                if self.probe_url(url) {
                    online = online.saturating_add(1);
                }
            }
        } else if let Ok(peers) = self.peers.list_peers() {
            // Fail-closed when unknown: directory presence ≠ online.
            // Attempt cheap TCP only for clearnet; onion without health URL → not counted.
            for p in peers {
                if Self::cheap_tcp(&p.endpoint.address) {
                    online = online.saturating_add(1);
                }
            }
        }
        if let Some(max) = self.max_online {
            online = online.min(max);
        }
        online
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_probe_honors_connection_budget_up_to_fifteen_seconds() {
        let mut settings = PeerHttpSettings::tor_defaults();
        settings.connect_timeout = Duration::from_secs(12);
        let mut probe = ProbedOnlineCount::new(
            Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            vec![],
            settings,
            None,
            None,
        );
        assert_eq!(probe.probe_timeout(), Duration::from_secs(12));
        probe.peer_http.connect_timeout = Duration::from_secs(60);
        assert_eq!(probe.probe_timeout(), Duration::from_secs(15));
        probe.peer_http.timeout = Duration::from_secs(3);
        assert_eq!(probe.probe_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn clearnet_probe_retains_short_health_budget() {
        let probe = ProbedOnlineCount::new(
            Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            vec![],
            PeerHttpSettings::clearnet_defaults(),
            None,
            None,
        );
        assert_eq!(probe.probe_timeout(), Duration::from_millis(500));
    }

    #[test]
    fn tor_probe_accepts_response_after_old_five_second_limit() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut request = [0u8; 2048];
            assert!(stream.read(&mut request).unwrap() > 0);
            std::thread::sleep(Duration::from_millis(5_200));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let mut settings = PeerHttpSettings::tor_defaults();
        // A local HTTP harness isolates timeout behavior from external Tor/TLS.
        settings.socks_proxy = None;
        settings.connect_timeout = Duration::from_secs(8);
        settings.timeout = Duration::from_secs(8);
        let probe = ProbedOnlineCount::new(
            Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            vec![format!("http://{address}/v1/live")],
            settings,
            None,
            None,
        );
        assert_eq!(probe.online_count(), 2);
        server.join().unwrap();
    }

    #[test]
    fn unreachable_configured_peer_does_not_count_online() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let probe = ProbedOnlineCount::new(
            Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            vec![format!("http://{address}/v1/live")],
            PeerHttpSettings::clearnet_defaults(),
            None,
            None,
        );
        assert_eq!(probe.online_count(), 1);
    }

    #[test]
    fn lab_static_reports_fixed() {
        let p = ProbedOnlineCount::lab_static(3);
        assert_eq!(p.online_count(), 3);
    }

    #[test]
    fn no_peers_is_self_only() {
        let p = ProbedOnlineCount::new(
            Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            vec![],
            PeerHttpSettings::clearnet_defaults(),
            None,
            None,
        );
        assert_eq!(p.online_count(), 1);
    }
}
