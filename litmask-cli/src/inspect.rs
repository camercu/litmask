//! `litmask inspect` subcommand.
//!
//! Functional core / imperative shell split: [`plan`] is a pure
//! function over (config text, binary bytes) that returns an
//! [`Outcome`]; [`run`] is the thin shell that reads the files and
//! returns the [`Outcome`] for the caller to render + map to an
//! exit code.
//!
//! Outcome table:
//!
//! | Outcome | Exit | Stream |
//! |---|---|---|
//! | `Verified` | 0 | stdout confirmation |
//! | `Ambiguous(n)` | 65 (`EX_DATAERR`) | stderr diagnostic |
//! | `NotFound` | 66 (`EX_NOINPUT`) | stderr diagnostic |
//! | `ConfigMalformed` | 64 (`EX_USAGE`) | stderr diagnostic |

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

    /// `true` for the one outcome that is a confirmation rather than
    /// a problem. The shell routes this to stdout and every other
    /// outcome's [`describe`](Self::describe) text to stderr.
    pub(crate) fn is_success(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Human-readable description with the binary and config paths
    /// interpolated. `Verified` confirms the match; the others
    /// explain what was wrong and the likely cause. The CLI is never
    /// shipped, so messages are as descriptive as useful.
    pub(crate) fn describe(&self, binary: &Path, config: &Path) -> String {
        let bin = binary.display();
        let cfg = config.display();
        match self {
            Self::Verified => {
                format!("verified: '{bin}' contains the locator recorded in '{cfg}'")
            }
            Self::NotFound => format!(
                "no litmask wrapper found in '{bin}'\n  \
                 the locator from '{cfg}' is not present — is '{bin}' a \
                 litmask-built release binary, and does '{cfg}' belong to it?"
            ),
            Self::Ambiguous(n) => format!(
                "found {n} differing litmask wrappers in '{bin}'\n  \
                 the locator from '{cfg}' matches more than one distinct \
                 wrapper, so the binary cannot be verified unambiguously"
            ),
            Self::ConfigMalformed => format!(
                "could not parse '{cfg}' as a litmask.config\n  \
                 expected a base64url 'locator' field"
            ),
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

/// Imperative shell. Reads the two inputs from disk and calls the
/// pure planner. Rendering the outcome (stdout/stderr) and mapping
/// it to an exit code is the caller's job. `Err` covers shell-only
/// failures (file I/O); everything the planner can decide flows
/// through `Ok(Outcome)` so the caller can map it uniformly.
pub(crate) fn run(
    binary_path: &Path,
    config_path: &Path,
) -> Result<Outcome, crate::inputs::InputError> {
    let (config_text, binary_bytes) = crate::inputs::read(binary_path, config_path)?;
    Ok(plan(&config_text, &binary_bytes))
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

    // ── Outcome.exit_code / is_success pairings ────────────────

    #[rstest::rstest]
    #[case::verified(Outcome::Verified, 0, true)]
    #[case::not_found(Outcome::NotFound, 66, false)]
    #[case::ambiguous(Outcome::Ambiguous(7), 65, false)]
    #[case::config_malformed(Outcome::ConfigMalformed, 64, false)]
    fn outcome_exit_code_and_success(
        #[case] outcome: Outcome,
        #[case] exit_code: u8,
        #[case] is_success: bool,
    ) {
        assert_eq!(outcome.exit_code(), exit_code);
        assert_eq!(outcome.is_success(), is_success);
    }

    #[test]
    fn outcome_describe_names_paths_and_outcome() {
        let bin = Path::new("/opt/app/my_app");
        let cfg = Path::new("/opt/app/litmask.config");

        let verified = Outcome::Verified.describe(bin, cfg);
        assert!(verified.contains("verified"));
        assert!(verified.contains("/opt/app/my_app"));

        let not_found = Outcome::NotFound.describe(bin, cfg);
        assert!(not_found.contains("/opt/app/my_app"));

        let ambiguous = Outcome::Ambiguous(3).describe(bin, cfg);
        assert!(ambiguous.contains('3'));

        let malformed = Outcome::ConfigMalformed.describe(bin, cfg);
        assert!(malformed.contains("/opt/app/litmask.config"));
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
