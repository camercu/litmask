//! Locks the tampering-panic policy for `mask!`:
//! - A tampered per-string blob panics at the call site.
//! - No `.expect("...")` or `panic!("...")` with a custom message
//!   survives in the `mask!` decryption path — those messages would
//!   otherwise leak litmask-identifying plaintext into user binaries.

mod common;

/// `catch_unwind` rather than `#[should_panic]` so the assertion does
/// not depend on `panic!()`'s default message text ("explicit panic"
/// is a stable-but-implementation-detail string in `core`). Any
/// future Rust release that changes the default panic message leaves
/// this test green; the only thing we assert is that the call
/// unwinds.
#[test]
fn decrypt_panics_on_tampered_blob() {
    // `init_once` populates the process-global mask key cell from the
    // production unlock key. The subsequent blob is the minimum valid
    // shape (nonce + zero-byte ciphertext + tag) but zero-filled, so
    // AEAD authentication fails — the panic this asserts is the
    // tampering-detection panic, not a lazy-init env-var miss that
    // would also surface as an unwind.
    common::init_once();

    // Silence the panic message during catch_unwind; without the noop
    // hook the test output is polluted by stderr from std's default
    // panic hook. The race window with other concurrent tests'
    // panic output is acceptable — this is test infrastructure, not
    // production state.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let outcome = std::panic::catch_unwind(|| {
        let blob: [u8; 28] = [0u8; 28];
        let _ = ::litmask::__internal::__decrypt(&blob, ::litmask::__wrapper_bytes!());
    });

    std::panic::set_hook(prev_hook);

    assert!(
        outcome.is_err(),
        "expected __decrypt to panic on tampered blob"
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
/// Each entry pairs a path with an allowlist of substrings whose
/// containing line executes at PROC-MACRO TIME (inside rustc's
/// process) and therefore cannot leak into a user binary. New
/// allowlist entries require security review.
#[test]
fn no_custom_panic_messages_in_decryption_path() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let scans: Vec<(String, Vec<&str>)> = vec![
        (format!("{manifest}/src/runtime.rs"), vec![]),
        (
            format!("{manifest}/src/lib.rs"),
            vec![
                // crate-level doc-comment example — does not compile.
                r#".expect("missing LITMASK_UNLOCK_KEY")"#,
            ],
        ),
        (format!("{manifest}/../litmask-macros/src/mask.rs"), vec![]),
        (
            format!("{manifest}/../litmask-macros/src/mask_format.rs"),
            vec![
                // Runs at proc-macro expansion time on a string the
                // parser has already validated as all-digits; never
                // reaches the user binary.
                r#".expect("all-digits parses as usize")"#,
            ],
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
