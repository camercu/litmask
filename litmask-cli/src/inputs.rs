//! Shared input-file reading for the `inspect` and `bind` shells.
//!
//! Both subcommands read the same pair before planning — the
//! `litmask.config` text and the target binary's bytes — and both
//! surface the same operator-facing diagnostic when a path is wrong.
//! Centralizing the read here keeps the two shells' error text and
//! ordering from drifting.

use std::fs;
use std::path::Path;

/// Failure reading one of the two CLI input files. Both map to
/// `EX_USAGE` at the top level: a bad path is an operator-input error.
#[derive(Debug)]
pub(crate) enum InputError {
    ConfigUnreadable,
    BinaryUnreadable,
}

impl InputError {
    /// Human-readable diagnostic naming the offending path and a
    /// next step. The CLI is never shipped, so messages may be as
    /// descriptive as needed (the no-identifying-strings rule is a
    /// release-binary concern, not a CLI one).
    pub(crate) fn describe(&self, binary: &Path, config: &Path) -> String {
        match self {
            Self::ConfigUnreadable => format!(
                "could not read the config file '{}'\n  \
                 check the path exists and is readable",
                config.display()
            ),
            Self::BinaryUnreadable => format!(
                "could not read the binary '{}'\n  \
                 check the path exists and is readable",
                binary.display()
            ),
        }
    }
}

/// Read the config text and binary bytes. Config is read first so a
/// missing config is reported before a missing binary.
pub(crate) fn read(
    binary_path: &Path,
    config_path: &Path,
) -> Result<(String, Vec<u8>), InputError> {
    let config_text = fs::read_to_string(config_path).map_err(|_| InputError::ConfigUnreadable)?;
    let binary_bytes = fs::read(binary_path).map_err(|_| InputError::BinaryUnreadable)?;
    Ok((config_text, binary_bytes))
}
