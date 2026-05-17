//! Demonstrates `#[mask_all]`. Every bare string-shaped literal in
//! the attributed module is rewritten to `mask!(literal)` at proc-
//! macro time. The fixture phrases are unique enough that the
//! integration test scrub can assert their plaintext absence from
//! the compiled release binary.

use litmask::mask_all;

#[mask_all]
mod demo {
    pub fn run() {
        // Each binding here is the rewritten value of a `mask!()`
        // call at runtime — the literal text never landed in
        // `.rodata`. The println below prints the decrypted forms
        // so a human can verify the round-trip, and the scrub
        // test confirms the originals are absent from the binary.
        let banner = "uranium-walrus-5f8d23-task12";
        let bytes = b"thorium-loris-2a9b41-task12";
        let cstr = c"polonium-dingo-7c4e68-task12";
        // `.expect("...")` would have a string-literal argument that
        // `#[mask_all]` rewrites to `mask!(...)`, producing a `String`
        // where `.expect` wants `&str` — a real Task 12 footgun. Use
        // `.unwrap()` here to avoid distracting from the demo, or
        // wrap panic messages in `unmasked!(...)` to opt out
        // explicitly.
        let bytes_decoded = std::str::from_utf8(&bytes).unwrap();
        let cstr_decoded = cstr.to_str().unwrap();
        println!("banner={banner}");
        println!("bytes ={bytes_decoded}");
        println!("cstr  ={cstr_decoded}");

        // Task 13 §2.3.2.5 fixtures — `include_str!` and `concat!`
        // invocations must be wrapped in `mask!()` by the walker so
        // the resulting strings are absent from the binary plaintext.
        let included = include_str!("examples/fixtures/task13_include_str.txt");
        let assembled = concat!("rhodium-", "lemur-", "5c2a93-task13");
        println!("included ={}", included.trim());
        println!("assembled={assembled}");
    }
}

fn main() {
    demo::run();
}
