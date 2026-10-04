//! Credential-file-only local probe; never constructs VaultRuntime or a signer.
use std::{io::Read, net::SocketAddr, time::Duration};

fn pem(name: &str) -> Result<Vec<u8>, ()> {
    let path = std::env::var(name).map_err(|_| ())?;
    if !std::path::Path::new(&path).is_absolute() {
        return Err(());
    }
    // Mounted Kubernetes Secret symlinks resolve to regular files. A FIFO or
    // device can block before the HTTP request timeout has started.
    if !std::fs::metadata(&path).map_err(|_| ())?.is_file() {
        return Err(());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| ())?.take(65537).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(());
    }
    Ok(bytes)
}

fn local_target(raw: &str) -> Result<(reqwest::Url, String, SocketAddr), ()> {
    let url = reqwest::Url::parse(raw).map_err(|_| ())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/v1/local-health"
    {
        return Err(());
    }
    let host = url.host_str().ok_or(())?.to_owned();
    // IP literals bypass DNS overrides. Reject them rather than permit a remote
    // target or silently change the certificate identity to a different IP.
    if host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
        return Err(());
    }
    let port = url.port_or_known_default().ok_or(())?;
    Ok((url, host, SocketAddr::from(([127, 0, 0, 1], port))))
}

fn locally_ready(body: &[u8]) -> Result<(), ()> {
    #[derive(serde::Deserialize)]
    struct LocalHealth {
        local_ready: bool,
    }
    let value: LocalHealth = serde_json::from_slice(body).map_err(|_| ())?;
    if !value.local_ready {
        return Err(());
    }
    Ok(())
}

pub async fn run() -> Result<(), ()> {
    let (url, host, address) = local_target(&std::env::var("VAULT_HEALTH_PROBE_URL").map_err(|_| ())?)?;
    let mut identity = pem("VAULT_TLS_CLIENT_CERT_PATH")?;
    identity.push(b'\n');
    identity.extend(pem("VAULT_TLS_CLIENT_KEY_PATH")?);
    let ca = reqwest::Certificate::from_pem_bundle(&pem("VAULT_TLS_CLIENT_CA_PATH")?).map_err(|_| ())?;
    if ca.is_empty() {
        return Err(());
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .identity(reqwest::Identity::from_pem(&identity).map_err(|_| ())?)
        .resolve(&host, address)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4));
    for certificate in ca {
        builder = builder.add_root_certificate(certificate);
    }
    let mut response = builder.build().map_err(|_| ())?.get(url).send().await.map_err(|_| ())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > 4096 {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    locally_ready(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_is_https_fixed_path_no_credentials_or_redirect_inputs() {
        for raw in [
            "http://localhost/v1/local-health",
            "https://user@localhost/v1/local-health",
            "https://localhost/",
            "https://localhost/v1/local-health?x=1",
            "https://localhost/v1/local-health#x",
            "https://192.0.2.1/v1/local-health",
            "https://127.0.0.1/v1/local-health",
            "https://[::1]/v1/local-health",
            "https://[2001:db8::1]/v1/local-health",
            "https://2130706433/v1/local-health",
        ] {
            assert!(local_target(raw).is_err());
        }
        let (_, host, address) = local_target("https://vault.example:7701/v1/local-health").unwrap();
        assert_eq!(host, "vault.example");
        assert_eq!(address, "127.0.0.1:7701".parse().unwrap());
    }
    #[test]
    fn local_readiness_is_not_financial_authority() {
        assert!(locally_ready(br#"{"local_ready":true,"financial_ready":false}"#).is_ok());
        for body in [br#"{"local_ready":false}"#.as_slice(), br#"{"local_ready":"true"}"#, br#"{}"#, b"invalid"] {
            assert!(locally_ready(body).is_err());
        }
    }
    #[test]
    fn contradictory_duplicate_readiness_is_rejected() {
        for body in [
            br#"{"local_ready":false,"local_ready":true}"#.as_slice(),
            br#"{"local_ready":true,"local_ready":false}"#,
            br#"{"local_ready":true,"local_ready":true}"#,
            br#"{"local_ready":true} {"local_ready":true}"#,
        ] {
            assert!(locally_ready(body).is_err());
        }
    }
}
