//! Compatibility facade for the CLI package.
//!
//! Reusable protocol and application code lives in `safechat-core`; this
//! facade keeps existing `safechat::...` imports working for the binaries.

pub use safechat_application::*;
pub use safechat_core::*;
pub use safechat_transports::*;
