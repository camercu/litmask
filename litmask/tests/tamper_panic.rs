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
    let _ = common::assert_panic_msg(|| {
        let blob = [0u8; MIN_BLOB_LEN];
        let _ = ::litmask::__internal::__decrypt(
            &blob,
            ::litmask::__wrapper_bytes!(),
            ::litmask::__seal_tier!(),
        );
    });
}

/// §1.9.5 profile-split diagnostics: a tampered-blob panic carries
/// actionable, litmask-identifying text in **debug** builds (so the
/// developer sees the failure on their own machine) but stays a bare,
/// opaque `panic!()` in **release** builds (so no identifying string
/// reaches a shipped binary). The same test binary asserts whichever
/// half matches the profile it was compiled under.
#[test]
fn tampered_blob_panic_message_is_profile_split() {
    let msg = common::assert_panic_msg(|| {
        let blob = [0u8; MIN_BLOB_LEN];
        let _ = ::litmask::__internal::__decrypt(
            &blob,
            ::litmask::__wrapper_bytes!(),
            ::litmask::__seal_tier!(),
        );
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
/// user binaries. The scan spans every decryption-path file:
///
/// - `runtime/mod.rs` — `__decrypt`, lazy-init helpers.
/// - `runtime/mask_key_store.rs` — the per-wrapper mask-key store the
///   lazy `mask!()` path derives and caches each key through.
/// - `runtime/governor.rs` — the process-global governing provider the
///   lazy path consults to unlock each wrapper.
/// - `runtime/weak.rs` — `__weak_decode*` and the weak caches.
/// - `runtime/cell.rs` — the once-cell every decrypt path borrows
///   its key (or cache) through.
/// - `litmask/src/lib.rs` — crate root; re-exports + public macros.
/// - `litmask/src/macro_plumbing.rs` — the `__decrypt_cstring_call!` /
///   `__weak_decode_cstr_call!` shims, whose `.unwrap()` stays bare.
/// - `litmask-macros/src/mask.rs` — proc-macro entry point; emits
///   the type-construction wrappers, no `.expect` of its own.
/// - `litmask-macros/src/mask_format.rs` — proc-macro emission for
///   `mask_format!` (`write_fmt` + `format_args!` per placeholder).
/// - `litmask-macros/src/common/codegen.rs` + `common/artifact.rs` —
///   the `mask_plaintext` helper and `OUT_DIR` artifact loader; every
///   `.expect`/`panic!` here runs at proc-macro expansion time inside
///   rustc, not in the user binary. The other `common/` submodules are
///   scanned too, with empty allow-lists.
/// - `litmask/src/diagnostics.rs` — the §1.9.5 profile-split entry points.
///   Its actionable messages are permitted *only* because each sits on
///   the line immediately after a `#[cfg(debug_assertions)]` attribute,
///   so it is compiled out of release. The scan enforces that gating
///   (see `gated` below): an ungated message here still fails.
///
/// Each entry pairs a path with an allowlist of substrings whose
/// containing line executes at PROC-MACRO TIME (inside rustc's
/// process) and therefore cannot leak into a user binary. New
/// allowlist entries require security review.
#[test]
fn no_custom_panic_messages_in_decryption_path() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let scans: Vec<(String, Vec<&str>)> = vec![
        (format!("{manifest}/src/runtime/mod.rs"), vec![]),
        (format!("{manifest}/src/runtime/mask_key_store.rs"), vec![]),
        (format!("{manifest}/src/runtime/governor.rs"), vec![]),
        (format!("{manifest}/src/runtime/weak.rs"), vec![]),
        (format!("{manifest}/src/runtime/cell.rs"), vec![]),
        (format!("{manifest}/src/lib.rs"), vec![]),
        (format!("{manifest}/src/macro_plumbing.rs"), vec![]),
        (format!("{manifest}/../litmask-macros/src/mask.rs"), vec![]),
        (
            format!("{manifest}/../litmask-macros/src/mask_format.rs"),
            vec![],
        ),
        (format!("{manifest}/src/diagnostics.rs"), vec![]),
        (
            format!("{manifest}/../litmask-macros/src/common/diagnostics.rs"),
            vec![],
        ),
        (
            format!("{manifest}/../litmask-macros/src/common/parse.rs"),
            vec![],
        ),
        (
            format!("{manifest}/../litmask-macros/src/common/path.rs"),
            vec![],
        ),
        (
            format!("{manifest}/../litmask-macros/src/common/artifact.rs"),
            vec![
                // The OUT_DIR artifact loader runs at proc-macro expansion
                // time inside rustc, reading build artifacts before any
                // tokens are emitted. None reaches the user binary.
                r#".expect("artifact cache mutex poisoned")"#,
                r#"panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))"#,
                r#".expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?")"#,
                "litmask: failed to read {name} from OUT_DIR",
            ],
        ),
        (
            format!("{manifest}/../litmask-macros/src/common/codegen.rs"),
            vec![
                // `mask_plaintext` AEAD-encrypts the literal at expansion
                // time before emitting the decrypt tokens; this expect runs
                // inside rustc, never in the user binary.
                r#".expect("AEAD encryption failed during litmask macro expansion")"#,
            ],
        ),
    ];

    // `(?s)` + `\s*` so a `panic!(` / `.expect(` whose message rustfmt
    // wrapped onto its own line still matches: a per-line regex would miss
    // the wrapped form and let a message-bearing panic slip past unguarded.
    let custom_panic =
        regex::Regex::new(r#"(?s)(?:\.expect|panic!)\(\s*"[^"]+""#).expect("regex compiles");

    let mut hits: Vec<(String, usize, String)> = Vec::new();
    for (path, allow) in &scans {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let lines: Vec<&str> = src.lines().collect();
        for mat in custom_panic.find_iter(&src) {
            // Physical line where the `panic!(` / `.expect(` token opens.
            let open_idx = src[..mat.start()].bytes().filter(|&b| b == b'\n').count();
            let open_line = lines[open_idx];
            // Comment lines (incl. `//!` doc comments) never reach `.rodata`,
            // so a `.expect("…")`/`panic!("…")` quoted in prose — e.g. this
            // file's own policy docs — cannot fingerprint the binary.
            if open_line.trim_start().starts_with("//") {
                continue;
            }
            // Exempt when the line immediately above the opener is
            // `#[cfg(debug_assertions)]` — the message is then compiled out
            // of release, where the opacity contract applies.
            let gated = open_idx > 0 && lines[open_idx - 1].trim() == "#[cfg(debug_assertions)]";
            // Allowlist entries are matched against the whole call text (so a
            // substring on a wrapped message line still exempts) and the
            // opener line (for single-line panics carrying trailing args the
            // capture drops).
            let exempt = allow
                .iter()
                .any(|s| mat.as_str().contains(s) || open_line.contains(s));
            if gated || exempt {
                continue;
            }
            hits.push((path.clone(), open_idx + 1, mat.as_str().to_string()));
        }
    }

    assert!(
        hits.is_empty(),
        "decryption-path files leak custom panic-message text: {hits:#?}",
    );
}
