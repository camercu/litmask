//! Direct-call companion to `mask_all_demo`: exercises each
//! `mask_*!` macro at its canonical invocation form so the
//! `example_scrub` tests prove the masked plaintext is absent from
//! the release binary on the direct-call path (separate from the
//! `#[mask_all]` rewrite path which `mask_all_demo` covers).

use litmask::{
    mask_concat, mask_env, mask_file, mask_include_bytes, mask_include_str, mask_option_env,
};

fn main() {
    let from_file: String = mask_include_str!("examples/fixtures/quote.txt");
    println!("include_str_len={}", from_file.len());

    let raw_bytes: Vec<u8> = mask_include_bytes!("examples/fixtures/binary_blob.bin");
    println!("include_bytes_len={}", raw_bytes.len());

    // High-entropy unique phrase routed through every accepted
    // primitive-literal kind (string, int, float, bool, char) so a
    // single scrub assertion proves the round-trip masks the
    // entire concatenated value.
    let concatenated: String =
        mask_concat!("zephyr-quokka-direct-", 1, "-", 2.5, "-", true, "-", 'X');
    println!("concat_len={}", concatenated.len());

    // env! / option_env! use cargo-set vars whose values are
    // environment-dependent; the scrub assertions in
    // example_scrub.rs intentionally skip these (CARGO_PKG_NAME
    // would collide with the basename filter, and unset env vars
    // emit no ciphertext so there's nothing to assert absent).
    let pkg: String = mask_env!("CARGO_PKG_NAME");
    println!("env_pkg_len={}", pkg.len());
    let opt: Option<String> = mask_option_env!("LITMASK_DIRECT_DEMO_DEFINITELY_UNSET_X9Z42");
    println!("option_env_is_none={}", opt.is_none());

    // mask_file!() round-trips a canonicalized source path. The
    // scrub layer can't assert absence cleanly because
    // `core::panic::Location::caller()` embeds the same path at
    // every panic site (`unwrap`, `expect`, etc.), which is
    // outside the proc-macro's reach. The runtime test
    // `tests/mask_file.rs` pins the round-trip behaviour.
    let path: String = mask_file!();
    println!("file_path_len={}", path.len());
}
