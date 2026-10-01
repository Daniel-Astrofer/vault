//! Versioned operator evidence routes. No connection to signer activation.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde::Deserialize;

use crate::application::{
    ClockPort, GetReleaseCompatibility, IngestSourceArchive, ReleaseCompatibilityContext, SourceArchiveStorePort,
};
use crate::domain::{validate_release_id, ContentHash, DomainError, SOURCE_BUNDLE_MAX_BYTES};

#[derive(Clone)]
pub(super) struct SourceEvidenceState {
    pub archives: Arc<dyn SourceArchiveStorePort>,
    pub clock: Arc<dyn ClockPort>,
    pub context: Arc<dyn Fn() -> ReleaseCompatibilityContext + Send + Sync>,
}

pub(super) fn source_evidence_router<S: Clone + Send + Sync + 'static>(state: SourceEvidenceState) -> Router<S> {
    Router::new()
        .route(
            "/admin/v1/releases/source-archives",
            post(ingest).layer(axum::extract::DefaultBodyLimit::max(SOURCE_BUNDLE_MAX_BYTES)),
        )
        .route("/admin/v1/releases/{release_id}/compatibility", get(compatibility))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingQuery {
    canonical_digest: String,
    target_sequence: u64,
}

fn error(err: DomainError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match err {
        DomainError::UnknownRelease(_) => (StatusCode::NOT_FOUND, "SOURCE_ARCHIVE_NOT_FOUND"),
        DomainError::ReleasePredicate(_) => (StatusCode::CONFLICT, "RELEASE_BINDING_MISMATCH"),
        DomainError::MeasurementMismatch => (StatusCode::SERVICE_UNAVAILABLE, "ARCHIVE_INTEGRITY_FAILURE"),
        // Do not reflect local filesystem paths or source content in error bodies.
        _ => (StatusCode::BAD_REQUEST, "INVALID_OR_CONFLICTING_SOURCE_EVIDENCE"),
    };
    (
        status,
        Json(
            serde_json::json!({ "evidenceVersion": 1, "error": code, "compatible": false, "signerActivation": false }),
        ),
    )
}

async fn ingest(State(state): State<SourceEvidenceState>, body: Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    match IngestSourceArchive::new(state.archives, state.clock).execute(&body) {
        Ok(receipt) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "evidenceVersion": 1, "archive": receipt, "acceptedRelease": false, "signerActivation": false,
            })),
        )
            .into_response(),
        Err(err) => error(err).into_response(),
    }
}

async fn compatibility(
    State(state): State<SourceEvidenceState>,
    Path(release_id): Path<String>,
    Query(query): Query<BindingQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let result = (|| {
        validate_release_id(&release_id)?;
        if query.target_sequence == 0 {
            return Err(DomainError::InvalidRelease("zero sequence".into()));
        }
        let digest = ContentHash::parse(query.canonical_digest)?;
        GetReleaseCompatibility::new(state.archives).execute(
            &release_id,
            &digest,
            query.target_sequence,
            &(state.context)(),
        )
    })();
    match result {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(err) => error(err).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::PersistedReleaseMesh;
    use crate::domain::{ReleasePolicy, SourceBundleV1, SourceFileV1};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    struct Clock;
    impl ClockPort for Clock {
        fn unix_now_secs(&self) -> u64 {
            100
        }
    }

    #[tokio::test]
    async fn authenticated_versioned_ingestion_and_read_are_bound_and_never_activate() {
        let dir = tempfile::tempdir().unwrap();
        let mesh = Arc::new(PersistedReleaseMesh::open(dir.path(), ReleasePolicy::lab_default(3)).unwrap());
        let state = SourceEvidenceState {
            archives: mesh.clone(),
            clock: Arc::new(Clock),
            context: Arc::new(|| ReleaseCompatibilityContext {
                protocol_version: 1,
                storage_version: 1,
                share_storage_version: 1,
                production_safe: true,
                features: vec!["production".into()],
                observed_at_secs: 101,
            }),
        };
        let router =
            super::super::admin::protect_admin_routes(source_evidence_router::<()>(state), "operator-token".into())
                .layer(axum::extract::DefaultBodyLimit::max(64 * 1024));
        let bundle = SourceBundleV1 {
            format_version: 1,
            release_id: "r1".into(),
            target_sequence: 7,
            protocol_version: 1,
            storage_version: 1,
            production: true,
            features: ["production".into()].into(),
            files: vec![SourceFileV1 { path: "source.rs".into(), content_hex: "6162".into() }],
        };
        let body = serde_json::to_vec(&bundle).unwrap();
        let digest = bundle.canonical_digest().unwrap();
        let read_uri =
            format!("/admin/v1/releases/r1/compatibility?canonicalDigest={}&targetSequence=7", digest.as_str());
        for token in [None, Some("wrong")] {
            for (method, uri, body) in
                [("GET", read_uri.as_str(), Vec::new()), ("POST", "/admin/v1/releases/source-archives", body.clone())]
            {
                let mut req = Request::builder().method(method).uri(uri);
                if let Some(token) = token {
                    req = req.header("X-Vault-Token", token);
                }
                let resp = router.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            }
        }
        let send = |method: &str, uri: &str, body: Vec<u8>| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-Vault-Token", "operator-token")
                .body(Body::from(body))
                .unwrap()
        };
        let resp = router.clone().oneshot(send("GET", &read_uri, vec![])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = router.clone().oneshot(send("POST", "/admin/v1/releases/source-archives", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(json["acceptedRelease"], false);
        let resp = router.clone().oneshot(send("GET", &read_uri, vec![])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let json: serde_json::Value = serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(json["releaseId"], "r1");
        assert_eq!(json["canonicalDigest"], digest.as_str());
        assert_eq!(json["targetSequence"], 7);
        assert_eq!(json["compatible"], false);
        assert_eq!(json["signerActivation"], false);
        let mismatch = read_uri.replace("targetSequence=7", "targetSequence=8");
        let resp = router.clone().oneshot(send("GET", &mismatch, vec![])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let mismatch = read_uri.replace(digest.as_str(), ContentHash::from_bytes(b"other source").as_str());
        let resp = router.clone().oneshot(send("GET", &mismatch, vec![])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let mut conflict = bundle.clone();
        conflict.target_sequence = 8;
        let resp = router
            .clone()
            .oneshot(send("POST", "/admin/v1/releases/source-archives", serde_json::to_vec(&conflict).unwrap()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        // The versioned upload limit must override the legacy 64 KiB admin limit.
        let mut large = bundle.clone();
        large.release_id = "r2".into();
        large.files[0].content_hex = "00".repeat(40 * 1024);
        let resp = router
            .clone()
            .oneshot(send("POST", "/admin/v1/releases/source-archives", serde_json::to_vec(&large).unwrap()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = router.clone().oneshot(send("GET", "/admin/v1/releases/r1/compatibility", vec![])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = router
            .clone()
            .oneshot(send("POST", "/admin/v1/releases/source-archives", vec![b' '; SOURCE_BUNDLE_MAX_BYTES + 1]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let resp =
            router.oneshot(send("POST", "/admin/v1/releases/source-archives", b"hash text".to_vec())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        use crate::application::ReleaseStorePort;
        assert!(mesh.allowlist().unwrap().is_empty());
        assert!(mesh.get_candidate("r1").is_err());
    }
}
