#![no_main]

use libfuzzer_sys::fuzz_target;
use litmask_internal::NONCE_LEN;
use litmask_internal::scan::{LocateOutcome, count_occurrences, locate_wrapper};

fuzz_target!(|data: &[u8]| {
    if data.len() < NONCE_LEN {
        return;
    }
    let needle: [u8; NONCE_LEN] = data[..NONCE_LEN].try_into().unwrap();
    let haystack = &data[NONCE_LEN..];

    let count = count_occurrences(haystack, &needle);
    let outcome = locate_wrapper(haystack, &needle);

    match outcome {
        LocateOutcome::None => {}
        LocateOutcome::Found(offsets) => assert!(count >= offsets.len()),
        LocateOutcome::Ambiguous => assert!(count >= 2),
    }
});
