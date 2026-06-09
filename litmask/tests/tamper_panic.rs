//! Locks the tampering-panic policy for `mask!`:
//! - A tampered per-string blob panics at the call site.
//! - No `.expect("...")` or `panic!("...")` with a custom message
//!   survives in the `mask!` decryption path — those messages would
//!   otherwise leak litmask-identifying plaintext into user binaries.

mod common;

use litmask_internal::{NONCE_LEN, TAG_LEN};

const MIN_BLOB_LEN: usize = NONCE_LEN + TAG_LEN;

/// `catch_unwind` rather than `#[should_panic]` so the assertion does
/// not depend on `panic!()`'s default message text ("explicit panic"
/// is a stable-but-implementation-detail string in `core`). Any
/// future Rust release that changes the default panic message leaves
/// this test green; the only thing we assert is that the call
/// unwinds.
#[test]
fn decrypt_panics_on_tampered_blob() {
    common::init_once();

    let _ = common::assert_panic_msg(|| {
        let blob = [0u8; MIN_BLOB_LEN];
        let _ = ::litmask::__internal::__decrypt(&blob, ::litmask::__wrapper_bytes!());
    });
}

/// §5.4 profile-split diagnostics: a tampered-blob panic carries
/// actionable, litmask-identifying text in **debug** builds (so the
/// developer sees the failure on their own machine) but stays a bare,
/// opaque `panic!()` in **release** builds (so no identifying string
/// reaches a shipped binary). The same test binary asserts whichever
/// half matches the profile it was compiled under.
#[test]
fn tampered_blob_panic_message_is_profile_split() {
    common::init_once();

    let msg = common::assert_panic_msg(|| {
        let blob = [0u8; MIN_BLOB_LEN];
        let _ = ::litmask::__internal::__decrypt(&blob, ::litmask::__wrapper_bytes!());
    });

    #[cfg(debug_assertions)]
    assert!(
        msg.contains("litmask:"),
        "debug build must carry actionable text; got {msg:?}",
    );
    #[cfg(not(debug_assertions))]
    assert!(
        !msg.to_ascii_lowercase().contains("litmask"),
        "release build must stay opaque; got {msg:?}",
    );
}

/// Scans every file that contributes text to the user binary's
/// `mask!()` decryption path for `.expect("msg")` and `panic!("msg")`
/// patterns — the two ways a litmask-specific string would leak into
/// user binaries. The scan spans five files:
///
/// - `runtime.rs` — `__decrypt`, `__weak_decode`, lazy-init helpers.
/// - `litmask/src/lib.rs` — `__decrypt_cstring_call!` shim.
/// - `litmask-macros/src/mask.rs` — proc-macro entry point; emits
///   the type-construction wrappers, no `.expect` of its own.
/// - `litmask-macros/src/mask_format.rs` — proc-macro emission for
///   `mask_format!` (`write_fmt` + `format_args!` per placeholder).
/// - `litmask-macros/src/common.rs` — shared `mask_plaintext`
///   helper and `OUT_DIR` artifact loader; every `.expect`/`panic!`
///   here runs at proc-macro expansion time inside rustc, not in
///   the user binary.
///
/// `litmask/src/diagnostics.rs` is deliberately NOT scanned: the whole
/// module is `#[cfg(debug_assertions)]`-gated (§5.4), so its actionable
/// (litmask-identifying) panic messages are never compiled into a
/// release artifact. The release arms in `runtime.rs` keep the bare
/// `panic!()` this scan enforces.
///
/// Each entry pairs a path with an allowlist of substrings whose
/// containing line executes at PROC-MACRO TIME (inside rustc's
/// process) and therefore cannot leak into a user binary. New
/// allowlist entries require security review.
#[test]
fn no_custom_panic_messages_in_decryption_path() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let scans: Vec<(String, Vec<&str>)> = vec![
        (format!("{manifest}/src/runtime.rs"), vec![]),
        (format!("{manifest}/src/lib.rs"), vec![]),
        (format!("{manifest}/../litmask-macros/src/mask.rs"), vec![]),
        (
            format!("{manifest}/../litmask-macros/src/mask_format.rs"),
            vec![],
        ),
        (
            format!("{manifest}/../litmask-macros/src/common.rs"),
            vec![
                // All call sites run at proc-macro expansion time
                // inside rustc — the mask_plaintext helper loads
                // build artifacts and AEAD-encrypts the plaintext
                // before emitting tokens, and read_lit_str_path
                // resolves path-shaped macro arguments against
                // CARGO_MANIFEST_DIR. None reaches the user binary.
                r#".expect("artifact cache mutex poisoned")"#,
                r#"panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))"#,
                r#".expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?")"#,
                r#".expect("AEAD encryption failed during litmask macro expansion")"#,
                r#"panic!("{macro_name}!: CARGO_MANIFEST_DIR not set")"#,
            ],
        ),
    ];

    let custom_panic =
        regex::Regex::new(r#"\.expect\("[^"]+"\)|panic!\("[^"]+""#).expect("regex compiles");

    let mut hits: Vec<(String, usize, String)> = Vec::new();
    for (path, allow) in &scans {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        for (i, line) in src.lines().enumerate() {
            if !custom_panic.is_match(line) {
                continue;
            }
            if allow.iter().any(|s| line.contains(s)) {
                continue;
            }
            hits.push((path.clone(), i + 1, line.to_string()));
        }
    }

    assert!(
        hits.is_empty(),
        "decryption-path files leak custom panic-message text: {hits:#?}",
    );
}
