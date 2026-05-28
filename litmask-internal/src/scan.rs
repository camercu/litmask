//! Binary-scanning helpers for locating the litmask wrapper inside a
//! compiled artifact. Shared by `litmask-cli` (inspect + bind) and
//! fuzzing harnesses.

extern crate alloc;

use alloc::vec::Vec;

use crate::{NONCE_LEN, WRAPPER_LEN};

/// Outcome of searching a binary for the wrapper locator.
#[derive(Debug, PartialEq, Eq)]
pub enum LocateOutcome {
    /// No match found (or all matches lack room for a full wrapper).
    None,
    /// One or more matches whose full `WRAPPER_LEN`-byte content is
    /// identical. Compilers/linkers may duplicate `include_bytes!`
    /// data; callers that modify the wrapper must patch every offset.
    Found(Vec<usize>),
    /// Two or more matches with differing wrapper content.
    Ambiguous,
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
/// Returns [`LocateOutcome::Found`] when all matches carry identical
/// `WRAPPER_LEN`-byte content (the common case is one match; the
/// multi-match case covers compiler-duplicated `include_bytes!` data).
/// Returns [`LocateOutcome::Ambiguous`] only when matches differ.
#[must_use]
pub fn locate_wrapper(haystack: &[u8], locator: &[u8; NONCE_LEN]) -> LocateOutcome {
    if haystack.len() < WRAPPER_LEN {
        return LocateOutcome::None;
    }
    let offsets: Vec<usize> = haystack
        .windows(NONCE_LEN)
        .enumerate()
        .filter(|(_, w)| *w == locator)
        .filter(|(i, _)| i + WRAPPER_LEN <= haystack.len())
        .map(|(i, _)| i)
        .collect();
    match offsets.len() {
        0 => LocateOutcome::None,
        1 => LocateOutcome::Found(offsets),
        _ => {
            let first = &haystack[offsets[0]..offsets[0] + WRAPPER_LEN];
            if offsets[1..]
                .iter()
                .all(|&o| haystack[o..o + WRAPPER_LEN] == *first)
            {
                LocateOutcome::Found(offsets)
            } else {
                LocateOutcome::Ambiguous
            }
        }
    }
}
