//! Reusable SafeChat protocol boundaries shared by the command-line tools.
//!
//! The modules remain grouped by responsibility. Consumers should prefer the
//! types re-exported here for stable application contracts over depending on
//! implementation-specific helpers inside a module.

pub mod profile_store;
pub mod signal_adapter;
pub mod transport;

pub use profile_store::{HistoryEntry, HistoryFile, HistoryPage, HistoryStore, PROFILE_VERSION};
pub use signal_adapter::{
    IdentityRecoveryRecord, MessageId, SafeChatMessage, SignalEnvelope, SignalPreKeyBundle,
    SqliteSignalState, identity_fingerprint,
};
pub use transport::{
    BundleTransport, ContactRequest, ContactTransport, DeliveryStatus, MessageTransport,
    RecoveryTransport, TextTransport, TransportMessage,
};
