//! Compatibility facade for the CLI package.
//!
//! Reusable protocol and application code lives in workspace crates.
//!
//! Only named compatibility modules are exposed here. This prevents adding a
//! new internal crate item from silently becoming part of the root package's
//! public API while keeping the existing CLI imports working.

pub mod chat_service {
    pub use safechat_application::chat_service::*;
}
pub mod profile_store {
    pub use safechat_core::profile_store::*;
}
pub mod signal_adapter {
    pub use safechat_core::signal_adapter::*;
}
pub mod transport {
    pub use safechat_core::transport::*;
}
pub mod relay_client {
    pub use safechat_transports::relay_client::*;
}
pub mod relay_transport {
    pub use safechat_transports::relay_transport::*;
}
