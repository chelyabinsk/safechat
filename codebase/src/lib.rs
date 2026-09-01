//! Compatibility facade for the CLI package.
//!
//! Reusable protocol and application code lives in workspace crates.
//!
//! Only named compatibility modules are exposed here. This prevents adding a
//! new internal crate item from silently becoming part of the root package's
//! public API while keeping the existing CLI imports working.

pub mod chat_service {
    pub use safechat_application::chat_service::{ChatEvent, ChatService};
}
pub mod profile_store {
    pub use safechat_core::profile_store::{
        EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryPage, HistoryStore,
        PROFILE_VERSION, RelayConfig, load_history, load_relay_config, load_relay_peer_ids,
        load_relay_token, save_history, save_relay_config, save_relay_peer_ids, save_relay_token,
    };
}
pub mod signal_adapter {
    pub use safechat_core::diagnostics::run_signal_demo;
    pub use safechat_core::signal::{
        IdentityPublicKey, IdentityRecoveryRecord, MessageId, PeerAddress, SafeChatMessage,
        SignalEnvelope, SignalPreKeyBundle, SqliteSignalState, identity_fingerprint,
        upstream_revision,
    };
}
pub mod transport {
    pub use safechat_core::transport::{
        BundleTransport, ContactRequest, ContactTransport, DeliveryStatus, MessageTransport,
        RecoveryTransport, TextTransport, TransportMessage,
    };
}
pub mod relay_client {
    pub use safechat_transports::relay_client::{
        EnrollmentResponse, RelayBundle, RelayClient, RelayClientConfig, RelayMessage,
        RelayMessageStatus, RelayRegistration,
    };
}
pub mod relay_transport {
    pub use safechat_transports::relay_transport::RelayTransport;
}
