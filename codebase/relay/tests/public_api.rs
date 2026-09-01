use axum::{body::to_bytes, http::Request};
use safechat_relay::build_router;
use tower::ServiceExt;

fn temporary_database() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "safechat-relay-public-api-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock must be after unix epoch")
            .as_nanos()
    ))
}

#[tokio::test]
async fn public_router_exposes_health_and_capabilities_contracts() {
    let database = temporary_database();
    let app = build_router(&database, None).expect("build relay router");

    let health = app
        .clone()
        .oneshot(
            Request::get("/v1/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("health response");
    assert_eq!(health.status(), axum::http::StatusCode::OK);
    let health_body = to_bytes(health.into_body(), 1024)
        .await
        .expect("read health response");
    let health: serde_json::Value =
        serde_json::from_slice(&health_body).expect("valid health JSON");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["api_version"], "safechat-relay-v1");

    let capabilities = app
        .oneshot(
            Request::get("/v1/capabilities")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("capabilities response");
    assert_eq!(capabilities.status(), axum::http::StatusCode::OK);
    let capabilities_body = to_bytes(capabilities.into_body(), 4096)
        .await
        .expect("read capabilities response");
    let capabilities: serde_json::Value =
        serde_json::from_slice(&capabilities_body).expect("valid capabilities JSON");
    assert_eq!(capabilities["api_version"], "safechat-relay-v1");
    assert_eq!(
        capabilities["message_representation"]["protocol_version"],
        1
    );

    std::fs::remove_file(database).expect("remove temporary database");
}

#[tokio::test]
async fn public_router_rejects_unknown_routes_without_private_state_access() {
    let database = temporary_database();
    let app = build_router(&database, None).expect("build relay router");
    let response = app
        .oneshot(
            Request::get("/v1/not-a-route")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("unknown route response");
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    std::fs::remove_file(database).expect("remove temporary database");
}
