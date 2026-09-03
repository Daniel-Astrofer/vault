use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::PeerHttpSettings;
use crate::application::ports::PeerDirectoryPort;
use crate::application::OnlineStatusPort;

/// Honest online count for fail-stop: self + peers that answer `/v1/health`.
///
/// Unreachable / unknown peers are **not** counted (fail-closed). Does not
/// invent liveness from `VAULT_ONLINE_COUNT` alone when peers are configured.
pub struct ProbedOnlineCount {
    peers: Arc<dyn PeerDirectoryPort>,
    peer_health_urls: Vec<String>,
    peer_http: PeerHttpSettings,
    auth_token: Option<String>,
    /// Optional ceiling (from `VAULT_ONLINE_COUNT`); never raises above probed.
    max_online: Option<usize>,
    /// When true (lab only), skip probing and report `lab_static` — tests only.
    lab_static: Option<usize>,
}

impl ProbedOnlineCount {
    pub fn new(
        peers: Arc<dyn PeerDirectoryPort>,
        peer_health_urls: Vec<String>,
        peer_http: PeerHttpSettings,
        auth_token: Option<String>,
        max_online: Option<usize>,
    ) -> Self {
        Self { peers, peer_health_urls, peer_http, auth_token, max_online, lab_static: None }
    }

    /// Lab / unit harness: fixed count without probing (never used in hardened boot).
    pub fn lab_static(count: usize) -> Self {
        Self {
            peers: Arc::new(crate::adapters::InMemoryPeerDirectory::new()),
            peer_health_urls: vec![],
            peer_http: PeerHttpSettings::clearnet_defaults(),
            auth_token: None,
            max_online: None,
            lab_static: Some(count),
        }
    }

    fn probe_url(&self, url: &str) -> bool {
        let mut builder = match self.peer_http.apply_blocking_builder(reqwest::blocking::Client::builder()) {
            Ok(b) => b,
            Err(_) => return false,
        };
        builder = builder.timeout(Duration::from_millis(self.peer_http.connect_timeout.as_millis().min(500) as u64));
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
        std::net::TcpStream::connect_timeout(&SocketAddr::from(sa), Duration::from_millis(80)).is_ok()
    }
}

impl OnlineStatusPort for ProbedOnlineCount {
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
