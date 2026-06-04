//! sysexits(3) exit codes used by the CLI.
//!
//! Centralized so the numeric codes carry names everywhere — `main`'s
//! dispatch refers to these constants instead of bare literals.

/// Success.
pub(crate) const OK: u8 = 0;
/// `EX_USAGE` (64): argument-parsing or operator-input failure.
pub(crate) const USAGE: u8 = 64;
/// `EX_UNAVAILABLE` (69): upstream service (machine-uid) refused.
pub(crate) const UNAVAILABLE: u8 = 69;
