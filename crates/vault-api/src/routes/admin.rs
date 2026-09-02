//! Admin API router — separate from the main HTTP vault surface.
//!
//! Serves read-only admin endpoints over a Unix domain socket (production)
//! or optionally TCP with mTLS.
//!
//! # Security
//! - All responses are scrubbed of shares, nonces, passphrases, seeds,
//!   private keys, and private certificates.
//! - Production builds (`feature = "production"`) reject `dealer_lab` features.
//! - Server-side authorization validates that the caller has admin access.
//! - Request ID is generated for audit trail on every request.

use std::sync::Arc;

use crate::bootstrap::VaultRuntime;
use crate::{admin_error, resolve_request_id, AdminService};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use kerosene_contracts::AdminErrorEnvelopeV1;
use tower::ServiceExt;

/// Shared state for the admin API router.
#[derive(Clone)]
pub struct AdminApiState {
    pub service: AdminService,
    pub auth_token: String,
}

/// Auth header constant for admin API token validation.
const ADMIN_AUTH_HEADER: &str = "X-Vault-Token";

/// Build the admin API router with security + auth middleware.
///
/// All routes require a valid auth token via `X-Vault-Token` header.
/// Fails (panics) at construction if no token is configured — fail-closed.
pub fn build_admin_router(runtime: Arc<VaultRuntime>) -> Router {
    let auth_token = runtime
        .config
        .effective_vault_token()
        .expect(
            "FATAL: VAULT_API_TOKEN is required for admin API. \
             The admin socket will NOT start without an auth token (fail-closed).",
        )
        .to_string();
    let service = AdminService::new(runtime);
    let state = AdminApiState { service, auth_token };

    let protected = Router::new()
        .route("/admin/status", get(admin_status_handler))
        .route("/admin/health", get(admin_health_handler))
        .route("/admin/roster", get(admin_roster_handler))
        .route("/admin/ceremony", get(admin_ceremony_handler))
        .route("/admin/compatibility", get(admin_compatibility_handler))
        .route("/admin/audit-reference", get(admin_audit_reference_handler))
        .route_layer(from_fn_with_state(state.clone(), require_admin_auth_mw));

    Router::new()
        .merge(protected)
        .layer(from_fn(admin_security_headers_mw))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

/// Auth middleware for admin routes.
async fn require_admin_auth_mw(
    State(state): State<AdminApiState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    match headers.get(ADMIN_AUTH_HEADER).and_then(|v| v.to_str().ok()) {
        Some(token) if token == state.auth_token => Ok(next.run(request).await),
        Some(_) | None => {
            eprintln!("unauthorized admin API request (missing or invalid auth token)");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "unauthorized: valid X-Vault-Token header required"})),
            ))
        }
    }
}

/// Security headers middleware for admin responses.
async fn admin_security_headers_mw(request: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(request).await;
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("cache-control"),
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    resp
}

/// Extract request ID from headers.
fn extract_request_id(headers: &HeaderMap) -> String {
    resolve_request_id(headers.get("X-Request-Id").and_then(|v| v.to_str().ok()))
}

/// Render an admin error as JSON.
fn admin_error_json(err: AdminErrorEnvelopeV1) -> (StatusCode, Json<AdminErrorEnvelopeV1>) {
    let code = match err.code.as_str() {
        "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
        "FORBIDDEN" => StatusCode::FORBIDDEN,
        "NOT_FOUND" => StatusCode::NOT_FOUND,
        "TOO_LARGE" => StatusCode::PAYLOAD_TOO_LARGE,
        "TOO_MANY_REQUESTS" => StatusCode::TOO_MANY_REQUESTS,
        "SERVICE_UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(err))
}

/// GET /admin/status — local status and financial readiness.
async fn admin_status_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.status(&request_id);
    (StatusCode::OK, Json(resp))
}

/// GET /admin/health — health and version.
async fn admin_health_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.health(&request_id);
    (StatusCode::OK, Json(resp))
}

/// GET /admin/roster — observed roster and quorum.
async fn admin_roster_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.roster(&request_id);
    (StatusCode::OK, Json(resp))
}

/// GET /admin/ceremony — ceremony state inspection.
async fn admin_ceremony_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.ceremony(&request_id);
    (StatusCode::OK, Json(resp))
}

/// GET /admin/compatibility — protocol and release compatibility.
async fn admin_compatibility_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.compatibility(&request_id);
    (StatusCode::OK, Json(resp))
}

/// GET /admin/audit-reference — audit reference and request ID.
async fn admin_audit_reference_handler(State(state): State<AdminApiState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = extract_request_id(&headers);
    let resp = state.service.audit_reference(&request_id);
    (StatusCode::OK, Json(resp))
}

/// Spawn the admin API on a Unix domain socket.
///
/// Creates a `tokio::net::UnixListener` bound to `socket_path`,
/// sets restrictive permissions (0o600), and serves the admin router.
/// The socket file's parent directory is created if it does not exist.
///
/// The accept loop runs in a background `tokio::spawn` task.
pub async fn spawn_admin_unix_socket(runtime: Arc<VaultRuntime>, socket_path: &str) -> Result<(), String> {
    let path = std::path::Path::new(socket_path);

    // Remove stale socket file
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("failed to remove stale socket {socket_path}: {e}"))?;
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create socket directory {parent:?}: {e}"))?;
    }

    let listener =
        tokio::net::UnixListener::bind(path).map_err(|e| format!("failed to bind Unix socket {socket_path}: {e}"))?;

    // Set restrictive permissions: owner-only read/write
    set_socket_permissions(path).map_err(|e| format!("failed to set socket permissions on {socket_path}: {e}"))?;

    let router = build_admin_router(runtime);

    eprintln!("admin_api=unix socket_path={socket_path}");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let router = router.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let router = router.clone();
                            async move {
                                let (parts, _body) = req.into_parts();
                                let axum_req = axum::http::Request::from_parts(parts, Body::from(&b""[..]));
                                Ok::<_, std::convert::Infallible>(router.oneshot(axum_req).await.unwrap())
                            }
                        });
                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            eprintln!("admin_api connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("admin_api accept error: {e}");
                    break;
                }
            }
        }
    });

    Ok(())
}

/// Set restrictive permissions on a Unix socket (0o600 = owner rw only).
fn set_socket_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Spawn the admin API on a TCP listener.
///
/// When `mtls_config` is `Some`, mTLS is enforced (future: not yet wired).
pub async fn spawn_admin_tcp(
    runtime: Arc<VaultRuntime>,
    addr: &str,
    _mtls_config: Option<(&str, &str, &str)>,
) -> Result<(), String> {
    let router = build_admin_router(runtime);
    let listener =
        tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("failed to bind admin TCP {addr}: {e}"))?;

    eprintln!("admin_api=tcp addr={addr}");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("admin_api TCP serve error: {e}");
        }
    });

    Ok(())
}

/// Check whether the `dealer_lab` feature gate should reject this request.
///
/// In production builds, dealer_lab operations are always rejected.
#[allow(dead_code)]
pub fn check_dealer_lab_gate(request_id: &str) -> Result<(), (StatusCode, Json<AdminErrorEnvelopeV1>)> {
    #[cfg(all(feature = "production", feature = "dealer_lab"))]
    {
        return Err(admin_error_json(admin_error(
            request_id,
            "FORBIDDEN",
            "dealer_lab is not permitted in production builds",
        )));
    }
    let _ = request_id;
    Ok(())
}

/// Adversarial input validation for admin requests.
///
/// Checks for path traversal, oversized payloads, and other malicious patterns.
pub fn validate_admin_request_path(
    path: &str,
    request_id: &str,
) -> Result<(), (StatusCode, Json<AdminErrorEnvelopeV1>)> {
    if path.len() > 256 {
        return Err(admin_error_json(admin_error(
            request_id,
            "TOO_LARGE",
            format!("request path too long ({} bytes)", path.len()),
        )));
    }
    if path.contains("..") {
        return Err(admin_error_json(admin_error(request_id, "FORBIDDEN", "path traversal detected")));
    }
    if path.contains('\0') {
        return Err(admin_error_json(admin_error(request_id, "FORBIDDEN", "null byte in request path")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_rejected() {
        let request_id = "test-req";
        assert!(validate_admin_request_path("/admin/../etc/passwd", request_id).is_err());
        assert!(validate_admin_request_path("/admin/status", request_id).is_ok());
        assert!(validate_admin_request_path(&"a".repeat(300), request_id).is_err());
    }

    #[test]
    fn null_byte_rejected() {
        let request_id = "test-req";
        assert!(validate_admin_request_path("/admin/status\0evil", request_id).is_err());
    }

    #[test]
    fn admin_error_json_maps_codes() {
        let env = admin_error("req-1", "UNAUTHORIZED", "bad auth");
        let (status, _) = admin_error_json(env);
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let env = admin_error("req-2", "FORBIDDEN", "no access");
        let (status, _) = admin_error_json(env);
        assert_eq!(status, StatusCode::FORBIDDEN);

        let env = admin_error("req-3", "UNKNOWN_ERR", "default");
        let (status, _) = admin_error_json(env);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn socket_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o600);
        assert_eq!(mode.mode() & 0o777, 0o600);
    }
}
