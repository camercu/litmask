#![no_main]

use libfuzzer_sys::fuzz_target;
use litmask_internal::parse_mask_format_template;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = parse_mask_format_template(s);
    }
});
