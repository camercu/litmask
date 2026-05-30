//! sysexits(3) exit codes shared across the CLI subcommands.
//!
//! Centralized so the numeric codes carry names everywhere — the
//! subcommand `Outcome::exit_code` mappings and `main`'s top-level
//! dispatch both refer to these constants instead of bare literals.

/// Success.
pub(crate) const OK: u8 = 0;
/// `EX_USAGE` (64): argument-parsing or operator-input failure.
pub(crate) const USAGE: u8 = 64;
/// `EX_DATAERR` (65): input data was malformed or could not be
/// processed (ambiguous locator, AEAD failure, unsupported wrapper).
pub(crate) const DATAERR: u8 = 65;
/// `EX_NOINPUT` (66): expected input was absent (locator not found).
pub(crate) const NOINPUT: u8 = 66;
/// `EX_UNAVAILABLE` (69): upstream service (machine-uid) refused.
pub(crate) const UNAVAILABLE: u8 = 69;
/// `EX_SOFTWARE` (70): unexpected internal failure (atomic commit
/// I/O, etc.).
pub(crate) const SOFTWARE: u8 = 70;
