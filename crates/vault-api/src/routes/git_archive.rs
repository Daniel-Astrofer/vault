//! Raw, pinned Git history archives; no release or signer acceptance.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use bytes::Bytes;
use std::sync::Arc;

use crate::application::{ClockPort, GitArchiveStorePort, GitBundleVerifierPort, IngestGitArchive};
use crate::domain::{validate_release_id, GitArchiveApprovalV2, GitArchiveError, GIT_BUNDLE_MAX_BYTES};

#[derive(Clone)]
pub(super) struct GitArchiveState {
    pub store: Option<Arc<dyn GitArchiveStorePort>>,
    pub verifier: Arc<dyn GitBundleVerifierPort>,
    pub clock: Arc<dyn ClockPort>,
}

pub(super) fn git_archive_router<S: Clone + Send + Sync + 'static>(state: GitArchiveState) -> Router<S> {
    Router::new()
        .route("/admin/v2/git-archives/capability", get(capability))
        .route("/admin/v2/releases/{release_id}/repositories/{repository_id}/git-archive/approval", put(approve))
        .route("/admin/v2/releases/{release_id}/repositories/{repository_id}/git-archive/receipt", get(receipt))
        .route(
            "/admin/v2/releases/{release_id}/repositories/{repository_id}/git-archive",
            get(download)
                .put(upload)
                .layer(axum::extract::DefaultBodyLimit::max(GIT_BUNDLE_MAX_BYTES))
                .layer(from_fn_with_state(Arc::new(tokio::sync::Semaphore::new(1)), bound_transfer)),
        )
        .with_state(state)
}

async fn bound_transfer(State(slots): State<Arc<tokio::sync::Semaphore>>, request: Request, next: Next) -> Response {
    let Ok(_permit) = slots.try_acquire_owned() else {
        return error(GitArchiveError::Busy);
    };
    match tokio::time::timeout(std::time::Duration::from_secs(45), next.run(request)).await {
        Ok(response) => response,
        Err(_) => error(GitArchiveError::Unavailable),
    }
}

fn error(error: GitArchiveError) -> Response {
    let (status, code) = match error {
        GitArchiveError::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_GIT_ARCHIVE"),
        GitArchiveError::NotFound => (StatusCode::NOT_FOUND, "GIT_ARCHIVE_NOT_FOUND"),
        GitArchiveError::ApprovalRequired => (StatusCode::FORBIDDEN, "GIT_ARCHIVE_APPROVAL_REQUIRED"),
        GitArchiveError::Conflict => (StatusCode::CONFLICT, "GIT_ARCHIVE_BINDING_CONFLICT"),
        GitArchiveError::Corrupt => (StatusCode::SERVICE_UNAVAILABLE, "GIT_ARCHIVE_CORRUPT"),
        GitArchiveError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "GIT_ARCHIVE_UNAVAILABLE"),
        GitArchiveError::Busy => (StatusCode::TOO_MANY_REQUESTS, "GIT_ARCHIVE_BUSY"),
    };
    let mut response = (
        status,
        Json(serde_json::json!({ "archiveVersion": 2, "error": code,
        "archiveAvailable": false, "acceptedRelease": false, "signerActivation": false })),
    )
        .into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert("retry-after", "30".parse().unwrap());
    }
    response
}

async fn capability(State(state): State<GitArchiveState>) -> Response {
    let available =
        tokio::task::spawn_blocking(move || state.store.is_some() && state.verifier.available()).await.unwrap_or(false);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "archiveVersion": 2, "archiveAvailable": available,
        "verification": if available { "pinned-git-cli" } else { "unavailable" },
        "acceptedRelease": false, "signerActivation": false })),
    )
        .into_response()
}

async fn approve(
    State(state): State<GitArchiveState>,
    Path((release_id, repository_id)): Path<(String, String)>,
    Json(approval): Json<GitArchiveApprovalV2>,
) -> Response {
    if approval.release_id != release_id || approval.repository_id != repository_id {
        return error(GitArchiveError::Conflict);
    }
    let Some(store) = state.store else {
        return error(GitArchiveError::Unavailable);
    };
    let response_approval = approval.clone();
    match tokio::task::spawn_blocking(move || store.approve_git_archive(approval)).await {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(serde_json::json!({ "archiveVersion": 2, "approval": response_approval,
            "acceptedRelease": false, "signerActivation": false })),
        )
            .into_response(),
        Ok(Err(err)) => error(err),
        Err(_) => error(GitArchiveError::Unavailable),
    }
}

async fn upload(
    State(state): State<GitArchiveState>,
    Path((release_id, repository_id)): Path<(String, String)>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if !matches!(
        headers.get("content-type").and_then(|h| h.to_str().ok()),
        Some("application/octet-stream" | "application/x-git-bundle")
    ) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "raw Git bundle Content-Type required").into_response();
    }
    let Some(store) = state.store else {
        return error(GitArchiveError::Unavailable);
    };
    let result = tokio::task::spawn_blocking(move || {
        IngestGitArchive::new(store, state.verifier, state.clock).execute(&release_id, &repository_id, &bytes)
    })
    .await;
    match result {
        Ok(Ok(receipt)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "archiveVersion": 2, "archive": receipt,
            "selfContained": true, "acceptedRelease": false, "signerActivation": false })),
        )
            .into_response(),
        Ok(Err(err)) => error(err),
        Err(_) => error(GitArchiveError::Unavailable),
    }
}

async fn receipt(
    State(state): State<GitArchiveState>,
    Path((release_id, repository_id)): Path<(String, String)>,
) -> Response {
    let Some(store) = state.store else {
        return error(GitArchiveError::Unavailable);
    };
    match tokio::task::spawn_blocking(move || store.get_git_archive(&release_id, &repository_id)).await {
        Ok(Ok((receipt, _))) => (
            StatusCode::OK,
            Json(serde_json::json!({ "archiveVersion": 2, "archive": receipt,
            "selfContained": true, "acceptedRelease": false, "signerActivation": false })),
        )
            .into_response(),
        Ok(Err(err)) => error(err),
        Err(_) => error(GitArchiveError::Unavailable),
    }
}

async fn download(
    State(state): State<GitArchiveState>,
    Path((release_id, repository_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if validate_release_id(&release_id).is_err() || validate_release_id(&repository_id).is_err() {
        return error(GitArchiveError::Invalid);
    }
    let Some(store) = state.store else {
        return error(GitArchiveError::Unavailable);
    };
    let result = tokio::task::spawn_blocking(move || store.get_git_archive(&release_id, &repository_id)).await;
    let (receipt, bytes) = match result {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return error(err),
        Err(_) => return error(GitArchiveError::Unavailable),
    };
    let etag = format!("\"{}\"", receipt.approval.bundle_sha256);
    // Rehash before conditional handling: a corrupt archive must never give 304.
    let unchanged = headers.get("if-none-match").and_then(|h| h.to_str().ok()) == Some(etag.as_str());
    let mut response =
        if unchanged { StatusCode::NOT_MODIFIED.into_response() } else { Response::new(Body::from(bytes)) };
    let headers = response.headers_mut();
    headers.insert("etag", etag.parse().unwrap());
    headers.insert("content-type", "application/x-git-bundle".parse().unwrap());
    headers.insert("x-archive-commit", receipt.approval.commit.parse().unwrap());
    headers.insert("x-archive-repository", receipt.approval.repository_id.parse().unwrap());
    headers.insert("x-archive-retention", "pinned".parse().unwrap());
    headers.insert("accept-ranges", "none".parse().unwrap());
    if !unchanged {
        headers.insert("content-length", receipt.byte_length.to_string().parse().unwrap());
    }
    response
}

#[cfg(test)]
mod git_archive_tests {
    use super::*;
    use crate::adapters::PersistedGitArchives;
    use crate::domain::{ContentHash, GitArchiveReceiptV2, GitBundleVerificationV2};
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct Clock;
    impl ClockPort for Clock {
        fn unix_now_secs(&self) -> u64 {
            100
        }
    }
    // API isolation only; actual Git plumbing is exercised by adapters tests.
    struct RejectVerifier;
    impl GitBundleVerifierPort for RejectVerifier {
        fn available(&self) -> bool {
            false
        }
        fn verify(&self, _: &GitArchiveApprovalV2, _: &[u8]) -> Result<GitBundleVerificationV2, GitArchiveError> {
            Err(GitArchiveError::Unavailable)
        }
    }
    fn router(store: Arc<PersistedGitArchives>) -> Router {
        super::super::admin::protect_admin_routes(
            git_archive_router(GitArchiveState {
                store: Some(store),
                verifier: Arc::new(RejectVerifier),
                clock: Arc::new(Clock),
            }),
            "test-only-token".into(),
        )
    }
    fn path(suffix: &str) -> String {
        format!("/admin/v2/releases/release-001/repositories/core/git-archive{suffix}")
    }
    fn approval(raw: &[u8]) -> GitArchiveApprovalV2 {
        GitArchiveApprovalV2 {
            archive_version: 2,
            release_id: "release-001".into(),
            repository_id: "core".into(),
            commit: "a".repeat(40),
            object_format: "sha1".into(),
            bundle_sha256: ContentHash::from_bytes(raw).as_str().into(),
            retention_pinned: true,
        }
    }

    #[tokio::test]
    async fn git_archive_auth_applies_to_all_new_routes_before_storage() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PersistedGitArchives::open(dir.path()).unwrap());
        let app = router(store.clone());
        for (method, uri) in [
            ("GET", "/admin/v2/git-archives/capability".into()),
            ("GET", path("")),
            ("PUT", path("")),
            ("GET", path("/receipt")),
            ("PUT", path("/approval")),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        assert_eq!(store.git_archive_approval("release-001", "core"), Err(GitArchiveError::ApprovalRequired));
    }

    #[tokio::test]
    async fn git_archive_repository_binding_and_unavailable_verifier_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PersistedGitArchives::open(dir.path()).unwrap());
        let app = router(store.clone());
        let mut wrong = approval(b"raw");
        wrong.repository_id = "vault".into();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(path("/approval"))
                    .header("X-Vault-Token", "test-only-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&wrong).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        store.approve_git_archive(approval(b"raw")).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(path(""))
                    .header("X-Vault-Token", "test-only-token")
                    .header("Content-Type", "application/x-git-bundle")
                    .body(Body::from("raw"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(json["acceptedRelease"], false);
        assert_eq!(json["signerActivation"], false);
        assert_eq!(store.get_git_archive("release-001", "core"), Err(GitArchiveError::NotFound));
    }

    #[tokio::test]
    async fn git_archive_conditional_download_cannot_hide_corrupted_blob() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PersistedGitArchives::open(dir.path()).unwrap());
        let approved = approval(b"inert API fixture");
        store.approve_git_archive(approved.clone()).unwrap();
        store
            .put_git_archive(
                GitArchiveReceiptV2 {
                    approval: approved.clone(),
                    verified_at_secs: 100,
                    byte_length: 17,
                    verification: GitBundleVerificationV2 {
                        commit_count: 2,
                        bundle_version: 2,
                        git_executable_sha256: ContentHash::from_bytes(b"test-pin").as_str().into(),
                    },
                },
                b"inert API fixture",
            )
            .unwrap();
        let app = router(store);
        let request = || {
            Request::builder()
                .uri(path(""))
                .header("X-Vault-Token", "test-only-token")
                .header("If-None-Match", format!("\"{}\"", approved.bundle_sha256))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(app.clone().oneshot(request()).await.unwrap().status(), StatusCode::NOT_MODIFIED);
        let blob = dir.path().join("bundles").join(&approved.bundle_sha256);
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(blob, b"corrupt").unwrap();
        assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
