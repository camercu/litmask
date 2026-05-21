//! `litmask-cli inspect` subcommand (§2.9.2.1–§2.9.2.3).
//!
//! Scans a binary file for occurrences of the 12-byte locator
//! recorded in `litmask.config`. Returns the sysexits.h-aligned
//! exit code per the §2.9.2.3 table:
//!
//! | Outcome | Exit | Stdout |
//! |---|---|---|
//! | Exactly one match | 0 | `verified` |
//! | Multiple matches | 65 (`EX_DATAERR`) | `ambiguous:<count>` |
//! | No match | 66 (`EX_NOINPUT`) | `not_found` |
//!
//! Argument-parse and config-read failures map to `EX_USAGE` (64)
//! at the caller; unexpected internal errors map to `EX_SOFTWARE`
//! (70).

use std::fs;
use std::path::Path;

use litmask_internal::base64url;

const EXIT_VERIFIED: u8 = 0;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
/// Wrapper-locator length (§1.7.3): the first 12 bytes of the
/// AEAD-encrypted `mask_key` wrapper, which double as the locator
/// recorded in `litmask.config`.
const LOCATOR_LEN: usize = 12;

/// Internal failure shapes — the caller maps each to the
/// appropriate sysexits.h code so this module stays focused on the
/// inspect logic itself.
pub(crate) enum Error {
    /// `litmask.config` missing or unreadable.
    ConfigUnreadable,
    /// `litmask.config` does not parse, or lacks a valid `locator`.
    ConfigMalformed,
    /// Target binary is missing or unreadable.
    BinaryUnreadable,
    /// Anything we did not anticipate. Maps to `EX_SOFTWARE` so the
    /// operator can distinguish "your input is wrong" from "the
    /// tool itself broke".
    #[allow(dead_code)]
    Internal,
}

impl Error {
    /// Operator-facing message. Stays terse and avoids leaking
    /// litmask-identifying vocabulary into the CLI's own surface;
    /// the binary's strings are the operator's responsibility.
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::ConfigUnreadable => "config file is missing or unreadable",
            Self::ConfigMalformed => "config file is malformed or missing required `locator`",
            Self::BinaryUnreadable => "target binary is missing or unreadable",
            Self::Internal => "unexpected internal failure",
        }
    }
}

/// Inspect `binary` against the locator recorded in `config`.
/// Returns the exit code to surface to the OS. Side effects: writes
/// the outcome tag (`verified`, `ambiguous:<n>`, `not_found`) to
/// stdout. Never modifies `binary`.
pub(crate) fn run(binary: &Path, config: &Path) -> Result<u8, Error> {
    let locator = read_locator(config)?;
    let bytes = fs::read(binary).map_err(|_| Error::BinaryUnreadable)?;
    let count = count_occurrences(&bytes, &locator);
    let code = report(count);
    Ok(code)
}

fn report(count: usize) -> u8 {
    match count {
        1 => {
            println!("verified");
            EXIT_VERIFIED
        }
        0 => {
            println!("not_found");
            EX_NOINPUT
        }
        n => {
            println!("ambiguous:{n}");
            EX_DATAERR
        }
    }
}

/// Parse `litmask.config` and return the 12-byte locator. The TOML
/// surface is minimal: a top-level `locator = "<base64url>"` line.
/// Stricter parsing (rejecting unknown keys, requiring `unlock_key`)
/// is deferred to Task 25 where `bind` actually consumes the
/// `unlock_key` field.
fn read_locator(config: &Path) -> Result<[u8; LOCATOR_LEN], Error> {
    let body = fs::read_to_string(config).map_err(|_| Error::ConfigUnreadable)?;
    // `toml::Value::from_str` parses a single value, not a TOML
    // document — so the leading `#` comment in `litmask.config`
    // would cause it to bail with "expected nothing". Use the
    // document-level Table parser instead.
    let table: toml::Table = body.parse().map_err(|_| Error::ConfigMalformed)?;
    let locator_text = table
        .get("locator")
        .and_then(|v| v.as_str())
        .ok_or(Error::ConfigMalformed)?;
    let bytes = base64url::decode(locator_text).map_err(|_| Error::ConfigMalformed)?;
    bytes.try_into().map_err(|_| Error::ConfigMalformed)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
/// `windows(N)` slides one byte at a time so adjacent occurrences
/// (impossible for a 12-byte random locator in practice, but a
/// possibility the §2.9.2 ambiguous-match branch must still count)
/// are still each counted once.
fn count_occurrences(haystack: &[u8], needle: &[u8; LOCATOR_LEN]) -> usize {
    if haystack.len() < LOCATOR_LEN {
        return 0;
    }
    haystack
        .windows(LOCATOR_LEN)
        .filter(|w| *w == needle)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_zero_when_needle_absent() {
        assert_eq!(
            count_occurrences(b"aaaaaaaaaaaaaaaaaa", &[0xCDu8; LOCATOR_LEN]),
            0
        );
    }

    #[test]
    fn count_one_when_needle_planted_once() {
        let needle = [0xABu8; LOCATOR_LEN];
        let mut haystack: Vec<u8> = b"prefix".to_vec();
        haystack.extend_from_slice(&needle);
        haystack.extend_from_slice(b"suffix");
        assert_eq!(count_occurrences(&haystack, &needle), 1);
    }

    #[test]
    fn count_n_when_needle_planted_n_times() {
        let needle = [0xEFu8; LOCATOR_LEN];
        let mut haystack: Vec<u8> = Vec::new();
        for _ in 0..5 {
            haystack.extend_from_slice(&needle);
            haystack.extend_from_slice(b"gap");
        }
        assert_eq!(count_occurrences(&haystack, &needle), 5);
    }

    #[test]
    fn count_zero_when_haystack_shorter_than_locator() {
        let needle = [0u8; LOCATOR_LEN];
        assert_eq!(count_occurrences(b"short", &needle), 0);
    }
}
