//! Diagnostics that exercise the production Signal boundary.

use anyhow::Result;

/// Runs the opt-in Signal demonstration without adding demo helpers to the
/// production-facing `safechat::signal` module.
pub fn run_signal_demo() -> Result<Vec<u8>> {
    super::signal_adapter::run_signal_demo_impl()
}
