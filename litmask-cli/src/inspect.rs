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

use std::borrow::Cow;
use std::path::Path;

use litmask_internal::{LocateOutcome, count_occurrences, locate_wrapper};

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
        use crate::exit;
        match self {
            Self::Verified => exit::OK,
            Self::Ambiguous(_) => exit::DATAERR,
            Self::NotFound => exit::NOINPUT,
            Self::ConfigMalformed => exit::USAGE,
        }
    }

    /// Stdout tag for the outcome, or `None` when the shell should
    /// stay silent on stdout (and emit a stderr message instead).
    pub(crate) fn stdout_tag(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::Verified => Some(Cow::Borrowed("verified")),
            Self::Ambiguous(n) => Some(Cow::Owned(format!("ambiguous:{n}"))),
            Self::NotFound => Some(Cow::Borrowed("not_found")),
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
pub(crate) fn run(
    binary_path: &Path,
    config_path: &Path,
) -> Result<Outcome, crate::inputs::InputError> {
    let (config_text, binary_bytes) = crate::inputs::read(binary_path, config_path)?;
    let outcome = plan(&config_text, &binary_bytes);
    if let Some(tag) = outcome.stdout_tag() {
        println!("{tag}");
    }
    Ok(outcome)
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

    #[rstest::rstest]
    #[case::verified(Outcome::Verified, 0, Some("verified"))]
    #[case::not_found(Outcome::NotFound, 66, Some("not_found"))]
    #[case::ambiguous(Outcome::Ambiguous(7), 65, Some("ambiguous:7"))]
    #[case::config_malformed(Outcome::ConfigMalformed, 64, None)]
    fn outcome_exit_code_and_stdout_tag(
        #[case] outcome: Outcome,
        #[case] exit_code: u8,
        #[case] tag: Option<&str>,
    ) {
        assert_eq!(outcome.exit_code(), exit_code);
        assert_eq!(outcome.stdout_tag().as_deref(), tag);
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
