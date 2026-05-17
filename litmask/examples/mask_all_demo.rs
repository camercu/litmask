//! Demonstrates `#[mask_all]`. Every bare string-shaped literal in
//! the attributed module is rewritten to `mask!(literal)` at proc-
//! macro time. The fixture phrases are unique enough that the
//! integration test scrub can assert their plaintext absence from
//! the compiled release binary.

use litmask::mask_all;

#[mask_all]
mod demo {
    pub fn run() {
        let banner = "uranium-walrus-5f8d23-task12";
        let bytes = b"thorium-loris-2a9b41-task12";
        let cstr = c"polonium-dingo-7c4e68-task12";
        println!(
            "banner={banner} bytes_len={} cstr_len={}",
            bytes.len(),
            cstr.to_bytes().len(),
        );
    }
}

fn main() {
    demo::run();
}
