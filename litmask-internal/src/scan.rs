//! Binary-scanning helpers for locating the litmask wrapper inside a
//! compiled artifact. Shared by `litmask-cli` (inspect + bind) and
//! fuzzing harnesses.

use crate::{NONCE_LEN, WRAPPER_LEN};

/// Outcome of searching a binary for the wrapper locator.
#[derive(Debug, PartialEq, Eq)]
pub enum LocateOutcome {
    /// No match found (or all matches lack room for a full wrapper).
    None,
    /// Exactly one match at the given byte offset.
    Single(usize),
    /// Two or more valid matches — ambiguous.
    Multiple,
}

/// Count occurrences of `needle` in `haystack`.
///
/// Slides one byte at a time so adjacent occurrences (impossible for
/// a 12-byte random locator in practice, but a possibility the
/// ambiguous-match branch must still count) are each counted once.
#[must_use]
pub fn count_occurrences(haystack: &[u8], needle: &[u8; NONCE_LEN]) -> usize {
    if haystack.len() < NONCE_LEN {
        return 0;
    }
    haystack.windows(NONCE_LEN).filter(|w| *w == needle).count()
}

/// Locate the wrapper in `haystack` by searching for `locator`.
///
/// Returns [`LocateOutcome::Single`] only when exactly one match has
/// room for a full [`WRAPPER_LEN`]-byte wrapper following it.
#[must_use]
pub fn locate_wrapper(haystack: &[u8], locator: &[u8; NONCE_LEN]) -> LocateOutcome {
    if haystack.len() < WRAPPER_LEN {
        return LocateOutcome::None;
    }
    let mut hits = haystack
        .windows(NONCE_LEN)
        .enumerate()
        .filter(|(_, w)| *w == locator)
        .filter(|(i, _)| i + WRAPPER_LEN <= haystack.len())
        .map(|(i, _)| i);
    let Some(first) = hits.next() else {
        return LocateOutcome::None;
    };
    if hits.next().is_some() {
        return LocateOutcome::Multiple;
    }
    LocateOutcome::Single(first)
}
