//! Reusable SafeChat protocol boundaries shared by the command-line tools.
//!
//! The modules remain grouped by responsibility. Consumers should prefer the
//! types re-exported here for stable application contracts over depending on
//! implementation-specific helpers inside a module.

mod diagnostics_impl;
pub mod profile_store;
mod signal_adapter;
mod signal_types;
pub mod transport;

/// Stable Signal-facing contract for application and transport crates.
pub mod signal {
    pub use super::signal_adapter::{
        IdentityRecoveryRecord, MessageId, SafeChatMessage, SignalEnvelope, SignalPreKeyBundle,
        SqliteSignalState, identity_fingerprint, upstream_revision,
    };
    pub use super::signal_types::{IdentityPublicKey, PeerAddress};
}

/// Non-production diagnostics kept separate from the messaging contract.
pub mod diagnostics {
    pub use super::diagnostics_impl::run_signal_demo;
}

pub use profile_store::{HistoryEntry, HistoryFile, HistoryPage, HistoryStore, PROFILE_VERSION};
pub use signal::{
    IdentityPublicKey, IdentityRecoveryRecord, MessageId, PeerAddress, SafeChatMessage,
    SignalEnvelope, SignalPreKeyBundle, SqliteSignalState, identity_fingerprint,
};
pub use transport::{
    BundleTransport, ContactRequest, ContactTransport, DeliveryStatus, MessageTransport,
    RecoveryTransport, TextTransport, TransportMessage,
};
