//! HTTP route composition for the relay service.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};

use crate::{MAX_BODY, admin, bundles, contacts, enrollment, events, messages};

/// Builds the relay API without owning process startup or CLI concerns.
pub(super) fn build(state: crate::AppState) -> Router {
    Router::new()
        .route("/v1/health", get(crate::health))
        .route("/v1/capabilities", get(crate::capabilities))
        .route("/v1/admin/allowlist", post(admin::allowlist))
        .route("/v1/devices/challenge", post(enrollment::challenge))
        .route(
            "/v1/devices/enrollment-requests",
            post(enrollment::enrollment_request),
        )
        .route("/v1/devices/register", post(enrollment::register))
        .route(
            "/v1/devices/{device}/bundle",
            put(bundles::publish).get(bundles::fetch),
        )
        .route(
            "/v1/devices/by-address/{address}/bundle",
            get(bundles::fetch_by_address),
        )
        .route("/v1/messages", post(messages::send).get(messages::receive))
        .route(
            "/v1/contacts/requests",
            post(contacts::create).get(contacts::list),
        )
        .route(
            "/v1/contacts/requests/{request_id}/accept",
            post(contacts::accept),
        )
        .route(
            "/v1/contacts/requests/{request_id}/reject",
            post(contacts::reject),
        )
        .route("/v1/messages/status", get(messages::status))
        .route("/v1/messages/{server_id}/ack", post(messages::acknowledge))
        .route("/v1/events", get(events::route))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}
