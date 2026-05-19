//! Demonstrates `mask_include_str!(...)`.
//!
//! Paths are resolved relative to `CARGO_MANIFEST_DIR`. The fixture
//! uses a lexically unusual phrase so the integration test that
//! asserts it is absent from the compiled binary cannot
//! false-positive against std / dependency text.

use litmask::mask_include_str;

fn main() {
    let quote: String = mask_include_str!("examples/fixtures/quote.txt");
    println!("quote={quote:?}");
}
