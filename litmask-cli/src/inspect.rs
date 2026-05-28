//! `litmask-cli inspect` subcommand.
//!
//! Functional core / imperative shell split: [`plan`] is a pure
//! function over (config text, binary bytes) that returns an
//! [`Outcome`]; [`run`] is the thin shell that reads the files and
//! emits the documented stdout tag / exit code.
//!
//! Outcome table:
//!
//! | Outcome | Exit | Stdout |
//! |---|---|---|
//! | `Verified` | 0 | `verified` |
//! | `Ambiguous(n)` | 65 (`EX_DATAERR`) | `ambiguous:<n>` |
//! | `NotFound` | 66 (`EX_NOINPUT`) | `not_found` |
//! | `ConfigMalformed` | 64 (`EX_USAGE`) | (stderr message at shell) |

use std::fs;
use std::path::Path;

use litmask_internal::scan::{LocateOutcome, count_occurrences, locate_wrapper};

use crate::config;

/// Outcome of the pure planner. `plan` returns one of these
/// variants; the shell renders each to its `(exit_code, stdout_tag)`
/// pair. Constructing the outcome separately from emitting it lets
/// unit tests cover every classification branch without doing I/O.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Verified,
    NotFound,
    Ambiguous(usize),
    ConfigMalformed,
}

impl Outcome {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Ambiguous(_) => 65,
            Self::NotFound => 66,
            Self::ConfigMalformed => 64,
        }
    }

    /// Stdout tag for the outcome, or `None` when the shell should
    /// stay silent on stdout (and emit a stderr message instead).
    pub(crate) fn stdout_tag(&self) -> Option<String> {
        match self {
            Self::Verified => Some("verified".to_string()),
            Self::Ambiguous(n) => Some(format!("ambiguous:{n}")),
            Self::NotFound => Some("not_found".to_string()),
            Self::ConfigMalformed => None,
        }
    }
}

/// Pure functional core: classify a binary against the locator
/// recorded in a config. No I/O, no globals, deterministic.
pub(crate) fn plan(config_text: &str, binary_bytes: &[u8]) -> Outcome {
    let Ok(locator) = config::parse_locator_only(config_text) else {
        return Outcome::ConfigMalformed;
    };
    match locate_wrapper(binary_bytes, &locator) {
        LocateOutcome::Found(_) => Outcome::Verified,
        LocateOutcome::None => Outcome::NotFound,
        LocateOutcome::Ambiguous => Outcome::Ambiguous(count_occurrences(binary_bytes, &locator)),
    }
}

/// Imperative shell. Reads the two inputs from disk, calls the
/// pure planner, and emits stdout + exit code per the outcome.
/// `Err` covers shell-only failures (file I/O); everything that
/// the planner can decide flows through `Ok(Outcome)` so the
/// caller can map it uniformly.
pub(crate) fn run(binary_path: &Path, config_path: &Path) -> Result<Outcome, ShellError> {
    let config_text = fs::read_to_string(config_path).map_err(|_| ShellError::ConfigUnreadable)?;
    let binary_bytes = fs::read(binary_path).map_err(|_| ShellError::BinaryUnreadable)?;
    let outcome = plan(&config_text, &binary_bytes);
    if let Some(tag) = outcome.stdout_tag() {
        println!("{tag}");
    }
    Ok(outcome)
}

/// Shell-layer failures — the I/O steps that happen before the
/// planner ever runs. All map to `EX_USAGE` at the caller because
/// they indicate the operator's inputs (paths) are wrong.
#[derive(Debug)]
pub(crate) enum ShellError {
    ConfigUnreadable,
    BinaryUnreadable,
}

impl ShellError {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::ConfigUnreadable => "config file is missing or unreadable",
            Self::BinaryUnreadable => "target binary is missing or unreadable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litmask_internal::base64url;
    use litmask_internal::{NONCE_LEN, WRAPPER_LEN};

    const LOCATOR: [u8; NONCE_LEN] = [0xCDu8; NONCE_LEN];

    fn config_with_locator(loc: &[u8; NONCE_LEN]) -> String {
        format!(
            "# fixture\nunlock_key = \"placeholder\"\nlocator = \"{}\"\nlength = 62\n",
            base64url::encode(loc),
        )
    }

    // ── plan: locator-search outcomes ─────────────────────────

    #[test]
    fn plan_no_match_yields_not_found() {
        let cfg = config_with_locator(&LOCATOR);
        let binary = vec![0u8; 1024]; // no locator bytes inside
        assert_eq!(plan(&cfg, &binary), Outcome::NotFound);
    }

    #[test]
    fn plan_single_match_yields_verified() {
        let cfg = config_with_locator(&LOCATOR);
        let mut binary = vec![0u8; 1024];
        binary[200..200 + NONCE_LEN].copy_from_slice(&LOCATOR);
        assert_eq!(plan(&cfg, &binary), Outcome::Verified);
    }

    #[test]
    fn plan_identical_duplicates_yields_verified() {
        let cfg = config_with_locator(&LOCATOR);
        let mut binary = vec![0u8; 1024];
        let mut wrapper = [0x42u8; WRAPPER_LEN];
        wrapper[..NONCE_LEN].copy_from_slice(&LOCATOR);
        for offset in [100, 400] {
            binary[offset..offset + WRAPPER_LEN].copy_from_slice(&wrapper);
        }
        assert_eq!(plan(&cfg, &binary), Outcome::Verified);
    }

    #[test]
    fn plan_differing_wrappers_yields_ambiguous() {
        let cfg = config_with_locator(&LOCATOR);
        let mut binary = vec![0u8; 1024];
        for (i, offset) in [100, 400, 700].iter().enumerate() {
            binary[*offset..*offset + NONCE_LEN].copy_from_slice(&LOCATOR);
            #[allow(clippy::cast_possible_truncation)]
            {
                binary[*offset + NONCE_LEN] = (i + 1) as u8;
            }
        }
        assert_eq!(plan(&cfg, &binary), Outcome::Ambiguous(3));
    }

    #[test]
    fn plan_empty_binary_yields_not_found() {
        let cfg = config_with_locator(&LOCATOR);
        assert_eq!(plan(&cfg, &[]), Outcome::NotFound);
    }

    #[test]
    fn plan_binary_shorter_than_locator_yields_not_found() {
        let cfg = config_with_locator(&LOCATOR);
        assert_eq!(plan(&cfg, &[0u8; NONCE_LEN - 1]), Outcome::NotFound);
    }

    // ── plan: config-malformation paths ───────────────────────

    /// Single round-trip from `plan` to confirm `ConfigMalformed`
    /// flows from the shared parser into the outcome. Exhaustive
    /// branch coverage of the parser's reject cases lives in
    /// `crate::config::tests`; duplicating them here would
    /// re-assert the same `config::parse_locator_only` contract
    /// through a thin wrapper.
    #[test]
    fn plan_propagates_config_malformed_from_shared_parser() {
        let cfg = "unlock_key = \"placeholder\"\nlength = 62\n"; // no locator
        assert_eq!(plan(cfg, &[0u8; 1024]), Outcome::ConfigMalformed);
    }

    // ── Outcome.exit_code / stdout_tag pairings ────────────────

    #[test]
    fn outcome_verified_exits_zero_with_verified_tag() {
        let o = Outcome::Verified;
        assert_eq!(o.exit_code(), 0);
        assert_eq!(o.stdout_tag().as_deref(), Some("verified"));
    }

    #[test]
    fn outcome_not_found_exits_66_with_not_found_tag() {
        let o = Outcome::NotFound;
        assert_eq!(o.exit_code(), 66);
        assert_eq!(o.stdout_tag().as_deref(), Some("not_found"));
    }

    #[test]
    fn outcome_ambiguous_exits_65_with_ambiguous_count() {
        let o = Outcome::Ambiguous(7);
        assert_eq!(o.exit_code(), 65);
        assert_eq!(o.stdout_tag().as_deref(), Some("ambiguous:7"));
    }

    #[test]
    fn outcome_config_malformed_exits_64_with_no_stdout() {
        let o = Outcome::ConfigMalformed;
        assert_eq!(o.exit_code(), 64);
        assert_eq!(o.stdout_tag(), None);
    }

    // ── count_occurrences edge cases ─────────────────────────

    #[test]
    fn count_occurrences_adjacent_matches_are_each_counted() {
        // Two back-to-back locators (24 bytes) — both should be
        // counted; the windows iterator slides one byte at a time
        // so it visits both starting offsets. The locator pattern
        // here is deliberately heterogeneous so internal sliding
        // windows (e.g., starting at offset 1) DON'T match — only
        // the two true occurrences at offsets 0 and 12 do.
        let needle: [u8; NONCE_LEN] = *b"LITMASK-LOCT";
        let mut haystack = needle.to_vec();
        haystack.extend_from_slice(&needle);
        assert_eq!(count_occurrences(&haystack, &needle), 2);
    }
}
