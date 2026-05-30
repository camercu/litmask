//! Canonical direct-call form of each `mask_*!` macro: reference
//! for which input each accepts and which type each returns at
//! runtime. For the `#[mask_all]` rewrite of the same forms, see
//! `mask_all_demo.rs`. Verify masking via the strings/grep recipe
//! in `hello_world.rs`.

use litmask::{
    mask_concat, mask_env, mask_file, mask_include_bytes, mask_include_str, mask_option_env,
};

fn main() {
    // ── Returns String ──
    let from_file: String = mask_include_str!("fixtures/quote.txt");
    println!("include_str_len={}", from_file.len());

    // mask_concat accepts string + int + float + bool + char +
    // nested concat!/include_str!/env! — same grammar as stdlib
    // concat!. The single scrub probe `zephyr-quokka-direct`
    // proves every primitive arg gets masked in one blob.
    let concatenated: String =
        mask_concat!("zephyr-quokka-direct-", 1, "-", 2.5, "-", true, "-", 'X');
    println!("concat_len={}", concatenated.len());

    let pkg: String = mask_env!("CARGO_PKG_NAME");
    println!("env_pkg_len={}", pkg.len());

    let path: String = mask_file!();
    println!("file_path_len={}", path.len());

    // ── Returns Vec<u8> ──
    let raw_bytes: Vec<u8> = mask_include_bytes!("fixtures/binary_blob.bin");
    println!("include_bytes_len={}", raw_bytes.len());

    // ── Returns Option<String> ──
    // None when the env var is unset; no ciphertext embedded in
    // that case.
    let opt: Option<String> = mask_option_env!("LITMASK_DIRECT_DEMO_DEFINITELY_UNSET_X9Z42");
    println!("option_env_is_none={}", opt.is_none());
}
