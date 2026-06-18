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

/// Counts `{` minus `}` while ignoring braces that live inside strings,
/// char literals, or comments — the realistic miscount sources when
/// brace-matching a module to strip it. Block-comment state is carried
/// across lines so a multi-line `/* … */` cannot leak a stray brace.
#[derive(Default)]
struct BraceScanner {
    in_block_comment: bool,
}

impl BraceScanner {
    /// Net `{` minus `}` contributed by `line`, honoring carried
    /// block-comment state and skipping braces inside `"…"` / `r#"…"#`
    /// strings, `'{'` char literals, `//` line comments, and `/* … */`
    /// block comments.
    fn delta(&mut self, line: &str) -> i32 {
        let chars: Vec<char> = line.chars().collect();
        let mut depth = 0i32;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if self.in_block_comment {
                if c == '*' && chars.get(i + 1) == Some(&'/') {
                    self.in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            match c {
                '/' if chars.get(i + 1) == Some(&'/') => break,
                '/' if chars.get(i + 1) == Some(&'*') => {
                    self.in_block_comment = true;
                    i += 2;
                }
                // String literal (plain or raw). Skip to the closing quote,
                // honoring `\"` escapes; raw strings have no escapes but the
                // escape skip is harmless on them. Good enough for the test
                // sources we scan; a raw string containing a `"` is not used.
                '"' => {
                    i += 1;
                    while i < chars.len() {
                        match chars[i] {
                            '\\' => i += 2,
                            '"' => {
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
                // Char literal vs lifetime: `'\\…'` (escape) or `'x'` (one
                // char then a closing quote) is a literal whose contents we
                // skip; a bare `'a` is a lifetime, so the quote is ordinary.
                '\'' if chars.get(i + 1) == Some(&'\\') => {
                    i += 2;
                    while i < chars.len() && chars[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                }
                '\'' if chars.get(i + 2) == Some(&'\'') => i += 3,
                '{' => {
                    depth += 1;
                    i += 1;
                }
                '}' => {
                    depth -= 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        depth
    }
}

/// Drop `#[cfg(test)]` / `#[cfg(all(test, …))]` modules so the scan sees
/// only code that can ship. `test` must be the leading predicate, so a
/// merely test-*reachable* item like `extra_masking_crate_no_std`
/// (`cfg(all(debug_assertions, any(test, …)))`) is kept and judged on its
/// own debug-gating.
fn strip_test_modules(src: &str) -> String {
    let attr = regex::Regex::new(r"^\s*#\[cfg\(\s*(all\(\s*)?test\s*[,)]").expect("regex");
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        if attr.is_match(lines[i]) {
            let mut scanner = BraceScanner::default();
            let mut depth = 0i32;
            let mut opened = false;
            while i < lines.len() {
                depth += scanner.delta(lines[i]);
                if depth > 0 {
                    opened = true;
                }
                i += 1;
                if opened && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        out.push_str(lines[i]);
        out.push('\n');
        i += 1;
    }
    out
}

/// Core scan: return `(line, matched_text)` for every `.expect("…")` /
/// `panic!("…")` in `src` (after stripping test modules) that is NOT
/// exempt. A hit is exempt when its message substring is on `allow`, or —
/// when `gating_exempts` — the line directly above is
/// `#[cfg(debug_assertions)]` (compiled out of release).
fn message_panic_hits(src: &str, allow: &[&str], gating_exempts: bool) -> Vec<(usize, String)> {
    // `(?s)` + `\s*` so a message rustfmt wrapped onto its own line still
    // matches; a per-line regex would let the wrapped form slip past. The
    // raw-string alternative (`r#*".*?"#*`) catches `panic!(r#"…"#)`, which a
    // plain-quote pattern would miss — a leak hiding behind a raw literal.
    let re = regex::Regex::new(r##"(?s)(?:\.expect|panic!)\(\s*(?:"[^"]+"|r#*".*?"#*)"##)
        .expect("regex");
    let stripped = strip_test_modules(src);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut hits = Vec::new();
    for mat in re.find_iter(&stripped) {
        let idx = stripped[..mat.start()]
            .bytes()
            .filter(|&b| b == b'\n')
            .count();
        let line = lines[idx];
        if line.trim_start().starts_with("//") {
            continue;
        }
        let gated =
            gating_exempts && idx > 0 && lines[idx - 1].trim() == "#[cfg(debug_assertions)]";
        let exempt = allow
            .iter()
            .any(|s| mat.as_str().contains(s) || line.contains(s));
        if gated || exempt {
            continue;
        }
        hits.push((idx + 1, mat.as_str().to_string()));
    }
    hits
}

/// Recursively collect `.rs` files under `dir`.
fn rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rs_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// The runtime crate's `mask!()` / `mask_stack!()` decryption path must
/// not leak litmask-identifying `.expect("…")` / `panic!("…")` text into a
/// shipped binary (§1.9.5). Rather than a hand-maintained file list (which
/// silently misses a newly-added decryption-path file), this walks **all**
/// of `litmask/src`, strips test modules, and asserts the only
/// message-panics live in `diagnostics.rs` behind `#[cfg(debug_assertions)]`
/// — the single place actionable text is allowed, compiled out of release.
#[test]
fn no_message_panics_outside_gated_diagnostics() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits: Vec<String> = Vec::new();
    for path in rs_files(&src) {
        let text = std::fs::read_to_string(&path).expect("read source");
        // `diagnostics.rs` is the sanctioned home for actionable text;
        // there a message is allowed iff debug-gated. Everywhere else, any
        // message-panic is a violation — centralizing keeps the policy in
        // one auditable file.
        let is_diagnostics = path.file_name().is_some_and(|n| n == "diagnostics.rs");
        for (line, text) in message_panic_hits(&text, &[], is_diagnostics) {
            hits.push(format!("{}:{line}  {text}", path.display()));
        }
    }
    assert!(
        hits.is_empty(),
        "runtime decryption path must route message-panics through gated diagnostics.rs; found:\n{}",
        hits.join("\n"),
    );
}

/// The proc-macro crate's emission path is scanned separately: its
/// `.expect`/`panic!` calls run at PROC-MACRO TIME inside rustc and never
/// reach a user binary, so the policy is an explicit allowlist of
/// expansion-time call sites rather than the runtime crate's
/// gated-diagnostics rule. Scoped to the files that emit the `mask!()`
/// decryption tokens (the rest of the macro crate is full of legitimate
/// expansion-time `.expect`s on `syn` parsing).
#[test]
fn macro_expansion_path_panics_are_allowlisted() {
    let macros = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../litmask-macros/src");
    let scans: &[(&str, &[&str])] = &[
        ("mask.rs", &[]),
        ("mask_format.rs", &[]),
        ("common/diagnostics.rs", &[]),
        ("common/parse.rs", &[]),
        ("common/path.rs", &[]),
        (
            "common/artifact.rs",
            &[
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
            "common/codegen.rs",
            // `mask_plaintext` AEAD-encrypts the literal at expansion time
            // before emitting the decrypt tokens; this expect runs inside
            // rustc, never in the user binary.
            &[r#".expect("AEAD encryption failed during litmask macro expansion")"#],
        ),
    ];

    let mut hits: Vec<String> = Vec::new();
    for (rel, allow) in scans {
        let path = macros.join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for (line, text) in message_panic_hits(&text, allow, false) {
            hits.push(format!("{rel}:{line}  {text}"));
        }
    }
    assert!(
        hits.is_empty(),
        "macro emission path leaks non-allowlisted message-panic text: {hits:#?}",
    );
}

/// The scan is only as good as its detection: prove `message_panic_hits`
/// fires on a real violation, stays silent on the sanctioned forms, and
/// strips test modules — otherwise a future regression to the scanner
/// itself would let leaks through unnoticed.
#[test]
fn message_panic_scan_detects_and_exempts() {
    // Bare message-panic in shippable code → caught.
    assert_eq!(
        message_panic_hits("fn f() { panic!(\"litmask leak\"); }", &[], false).len(),
        1,
    );
    // Raw-string message in shippable code → caught (a plain-quote regex
    // would miss `r#"…"#`, letting a leak hide behind a raw literal).
    assert_eq!(
        message_panic_hits("fn f() { panic!(r#\"litmask leak\"#); }", &[], false).len(),
        1,
    );
    // Same panic inside a test module → stripped, not caught.
    let in_test = "#[cfg(test)]\nmod tests {\n    fn t() { panic!(\"litmask leak\"); }\n}\n";
    assert!(message_panic_hits(in_test, &[], false).is_empty());
    // A `}` inside a char literal must not prematurely close a test module
    // (an early strip would leak the panic below it into the scanned code).
    let char_brace = "#[cfg(test)]\nmod t {\n    fn x() { let c = '}'; }\n    fn y() { panic!(\"litmask leak\"); }\n}\n";
    assert!(message_panic_hits(char_brace, &[], false).is_empty());
    // A `}` inside a block comment likewise must not close the module early.
    let block_brace =
        "#[cfg(test)]\nmod t {\n    /* } */\n    fn y() { panic!(\"litmask leak\"); }\n}\n";
    assert!(message_panic_hits(block_brace, &[], false).is_empty());
    // Debug-gated message → exempt only when gating is allowed.
    let gated = "    #[cfg(debug_assertions)]\n    panic!(\"litmask leak\");\n";
    assert!(message_panic_hits(gated, &[], true).is_empty());
    assert_eq!(message_panic_hits(gated, &[], false).len(), 1);
    // Allowlisted message → exempt.
    assert!(
        message_panic_hits(
            "fn f() { panic!(\"allowed thing\"); }",
            &["allowed thing"],
            false
        )
        .is_empty()
    );
}
