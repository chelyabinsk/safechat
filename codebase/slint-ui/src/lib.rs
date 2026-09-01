//! Reusable UI application service and state contracts.
//!
//! The graphical executable is a thin adapter over this library. Keeping the
//! worker, ports, commands, events, and state in a library lets front ends and
//! integration tests exercise behavior without constructing a native window.

pub mod ui_service;
