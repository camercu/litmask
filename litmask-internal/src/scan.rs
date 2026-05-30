//! Binary-scanning helpers for locating the litmask wrapper inside a
//! compiled artifact. Shared by `litmask-cli` (inspect + bind) and
//! fuzzing harnesses.

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const LOCATOR: [u8; NONCE_LEN] = [0xAA; NONCE_LEN];

    fn make_wrapper(locator: &[u8; NONCE_LEN], fill: u8) -> [u8; WRAPPER_LEN] {
        let mut w = [fill; WRAPPER_LEN];
        w[..NONCE_LEN].copy_from_slice(locator);
        w
    }

    // ── count_occurrences ──────────────────────────────────────────

    #[test]
    fn count_empty_haystack() {
        assert_eq!(count_occurrences(&[], &LOCATOR), 0);
    }

    #[test]
    fn count_haystack_shorter_than_needle() {
        assert_eq!(count_occurrences(&[0xAA; NONCE_LEN - 1], &LOCATOR), 0);
    }

    #[test]
    fn count_no_match() {
        assert_eq!(count_occurrences(&[0x00; 128], &LOCATOR), 0);
    }

    #[test]
    fn count_single_match() {
        let mut hay = vec![0x00u8; 64];
        hay[10..10 + NONCE_LEN].copy_from_slice(&LOCATOR);
        assert_eq!(count_occurrences(&hay, &LOCATOR), 1);
    }

    #[test]
    fn count_multiple_non_overlapping() {
        let mut hay = vec![0x00u8; 128];
        hay[0..NONCE_LEN].copy_from_slice(&LOCATOR);
        hay[64..64 + NONCE_LEN].copy_from_slice(&LOCATOR);
        assert_eq!(count_occurrences(&hay, &LOCATOR), 2);
    }

    #[test]
    fn count_needle_at_exact_end() {
        let mut hay = vec![0x00u8; NONCE_LEN];
        hay.copy_from_slice(&LOCATOR);
        assert_eq!(count_occurrences(&hay, &LOCATOR), 1);
    }

    // ── locate_wrapper ─────────────────────────────────────────────

    #[test]
    fn locate_empty_haystack() {
        assert_eq!(locate_wrapper(&[], &LOCATOR), LocateOutcome::None);
    }

    #[test]
    fn locate_haystack_shorter_than_wrapper() {
        assert_eq!(
            locate_wrapper(&[0xAA; WRAPPER_LEN - 1], &LOCATOR),
            LocateOutcome::None,
        );
    }

    #[test]
    fn locate_no_match() {
        assert_eq!(
            locate_wrapper(&[0x00; WRAPPER_LEN * 2], &LOCATOR),
            LocateOutcome::None,
        );
    }

    #[test]
    fn locate_single_match_at_start() {
        let wrapper = make_wrapper(&LOCATOR, 0x11);
        let mut hay = vec![0x00u8; WRAPPER_LEN + 32];
        hay[..WRAPPER_LEN].copy_from_slice(&wrapper);
        match locate_wrapper(&hay, &LOCATOR) {
            LocateOutcome::Found(offsets) => assert_eq!(offsets, vec![0]),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn locate_single_match_at_exact_end() {
        let wrapper = make_wrapper(&LOCATOR, 0x22);
        let pad = 50;
        let mut hay = vec![0x00u8; pad + WRAPPER_LEN];
        hay[pad..].copy_from_slice(&wrapper);
        match locate_wrapper(&hay, &LOCATOR) {
            LocateOutcome::Found(offsets) => assert_eq!(offsets, vec![pad]),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn locate_match_without_room_for_full_wrapper_is_none() {
        let mut hay = vec![0x00u8; WRAPPER_LEN + 5];
        hay[6..6 + NONCE_LEN].copy_from_slice(&LOCATOR);
        assert_eq!(locate_wrapper(&hay, &LOCATOR), LocateOutcome::None);
    }

    #[test]
    fn locate_multiple_identical_wrappers() {
        let wrapper = make_wrapper(&LOCATOR, 0x33);
        let gap = WRAPPER_LEN + 16;
        let mut hay = vec![0x00u8; gap + WRAPPER_LEN];
        hay[..WRAPPER_LEN].copy_from_slice(&wrapper);
        hay[gap..gap + WRAPPER_LEN].copy_from_slice(&wrapper);
        match locate_wrapper(&hay, &LOCATOR) {
            LocateOutcome::Found(offsets) => assert_eq!(offsets, vec![0, gap]),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn locate_multiple_differing_wrappers_is_ambiguous() {
        let w1 = make_wrapper(&LOCATOR, 0x44);
        let mut w2 = make_wrapper(&LOCATOR, 0x44);
        w2[WRAPPER_LEN - 1] = 0xFF;
        let gap = WRAPPER_LEN + 16;
        let mut hay = vec![0x00u8; gap + WRAPPER_LEN];
        hay[..WRAPPER_LEN].copy_from_slice(&w1);
        hay[gap..gap + WRAPPER_LEN].copy_from_slice(&w2);
        assert_eq!(locate_wrapper(&hay, &LOCATOR), LocateOutcome::Ambiguous);
    }
}
