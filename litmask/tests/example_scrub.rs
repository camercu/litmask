//! Regression net: every example binary is scanned with `strings` for
//! a curated list of forbidden substrings. Any case-insensitive match
//! fails the test, catching the kind of identifier or
//! operational-tooling-vocabulary leak that would weaken the library's
//! "no litmask-identifying plaintext in compiled user binaries"
//! property.
//!
//! The scrub builds examples under the strip-symbols release profile
//! (the recommended deployment configuration). Debug builds always
//! contain crate / type name strings via DWARF; testing them against
//! the dirty-word list would be a guaranteed false-positive that
//! provides no signal.
//!
//! The forbidden list lives in `tests/common/mod.rs`. Add an entry
//! when a new identifiable term enters the codebase. The list is not a
//! proof of leak-freedom; high-entropy-fixture strings checks (see
//! `mask_round_trip.rs`) provide the positive security signal.

mod common;

use common::Profile;

/// Examples cleared for the case-insensitive library-identifier
/// scrub. Add new names here when new examples land under
/// `litmask/examples/`.
///
/// Three examples are intentionally absent because they reference
/// the canonical published env-var name (`LITMASK_UNLOCK_KEY` /
/// `LITMASK_UNLOCK_KEY_FILE`) as a plain string literal — by design,
/// for pedagogical clarity — and that literal contains the
/// `unlock_key` and `litmask` forbidden substrings. Real-world
/// deployments would `weak_mask!()` the env-var name (see
/// `weak_mask_demo`); the identifier-scrub absence is testable
/// there, while these examples are covered by fixture-absence
/// checks only:
///
/// - `static_provider`: cautionary FOR-TESTS-ONLY demo; reads
///   `LITMASK_UNLOCK_KEY` directly so the user can see the
///   plaintext-key flow end-to-end.
/// - `file_provider`: demonstrates `FileProvider`; reads
///   `LITMASK_UNLOCK_KEY_FILE` to find the key file.
/// - `hw_id_provider`: gated behind `--features hw-id` (see
///   [`hw_id_provider_example_masked_fixtures_absent_from_binary`]).
///   The BLAKE3 context literal `"hw-v1"` is hidden by
///   `weak_mask!()` in `HardwareIdProvider`, so it doesn't leak —
///   but the `blake3` crate embeds its own name in internal symbol
///   strings (e.g. `blake3_*` function names) that we can't filter
///   away. The hw_id scrub allow-lists `blake3` specifically.
const EXAMPLES: &[&str] = &[
    "hello_world",
    "weak_mask_demo",
    "byte_cstr_demo",
    "include_str_demo",
    "mask_format_demo",
    "mask_macros_demo",
    "mask_all_demo",
];

#[test]
fn no_forbidden_substrings_in_any_example_binary() {
    for name in EXAMPLES {
        common::build_example(name, Profile::Release);
        let path = common::example_path(name, Profile::Release);
        assert!(path.exists(), "example binary missing: {}", path.display());
        common::assert_no_dirty_words(&path);
    }
}

/// `weak_mask_demo` exercises BOTH masking layers: `weak_mask!`
/// hides the custom env-var name that the bootstrap `EnvVarProvider`
/// reads, and `mask!` hides the AEAD-encrypted payload. Both probes
/// must be absent from the compiled binary — `MYAPP_SECRET_KEY` is
/// the env-var name a passive `strings` scan would otherwise reveal
/// as a lookup target; `emerald-puma-c2d8f4` is the secret payload.
#[test]
fn weak_mask_demo_env_var_name_and_payload_absent_from_binary() {
    common::build_example("weak_mask_demo", Profile::Release);
    let path = common::example_path("weak_mask_demo", Profile::Release);
    // weak_mask!()'d env-var name — visible to `strings(1)` would
    // tell an attacker exactly where the unlock key lives.
    common::assert_substring_absent(&path, "MYAPP_SECRET_KEY");
    // mask!()'d payload — the AEAD layer must hide it even though
    // it's a fixture, since this example doubles as the load-bearing
    // demo of the `weak_mask! → init_with! → mask!` pattern.
    common::assert_substring_absent(&path, "emerald-puma-c2d8f4");
}

/// `mask!(b"...")` and `mask!(c"...")` must keep their fixture bytes
/// out of the compiled binary — all three literal kinds go through
/// AEAD encryption at expansion time. Each fixture is a lexically
/// unusual phrase to keep the absence assertion precise.
#[test]
fn byte_and_cstr_fixtures_absent_from_binary() {
    common::build_example("byte_cstr_demo", Profile::Release);
    let path = common::example_path("byte_cstr_demo", Profile::Release);
    common::assert_substring_absent(&path, "scarlet-onyx-narwhal-c8d7e9");
    common::assert_substring_absent(&path, "navy-velvet-quokka-3f1a7b");
}

/// `mask!(include_str!(...))` must mask the file contents at
/// proc-macro time so the plaintext from the fixture file is absent
/// from the compiled binary.
#[test]
fn include_str_fixture_absent_from_binary() {
    common::build_example("include_str_demo", Profile::Release);
    let path = common::example_path("include_str_demo", Profile::Release);
    common::assert_substring_absent(&path, "vermilion-axolotl-7e2d4a");
}

/// `mask_format!` must mask the literal fragments between placeholders
/// so the template text never appears in plaintext. Each fragment
/// phrase is lexically unusual to make the absence assertion
/// precise.
#[test]
fn mask_format_fragments_absent_from_binary() {
    common::build_example("mask_format_demo", Profile::Release);
    let path = common::example_path("mask_format_demo", Profile::Release);
    common::assert_substring_absent(&path, "saffron-koala-2b8e1c");
    common::assert_substring_absent(&path, "amber-otter-4f3d27");
    common::assert_substring_absent(&path, "indigo-marmot-7a3e8b");
    common::assert_substring_absent(&path, "crimson-bobcat-9d1c47");
    common::assert_substring_absent(&path, "ochre-hedgehog-2f5d8e");
}

/// Every bare string / byte string / C string literal rewritten by
/// `#[mask_all]` must be absent from the compiled binary. Fixtures
/// in `mask_all_demo` are unique-enough phrases that the absence
/// assertion is precise.
#[test]
fn mask_all_literals_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "uranium-walrus-5f8d23-mask-all-bare");
    common::assert_substring_absent(&path, "thorium-loris-2a9b41-mask-all-bare");
    common::assert_substring_absent(&path, "polonium-dingo-7c4e68-mask-all-bare");
}

/// `include_str!` and `concat!` invocations inside a `#[mask_all]`
/// module must be wrapped in `mask!()` so their resulting strings
/// are absent from binary plaintext. The included-file content
/// (`selenium-pangolin-3d8a91-mask-all-macro`) lives only in the fixture
/// file at compile time and would otherwise land in `.rodata`; the
/// concatenated literal (`rhodium-lemur-5c2a93-mask-all-macro`) is assembled
/// by the `concat!` builtin and would similarly be a single
/// `.rodata` string.
#[test]
fn mask_all_include_str_and_concat_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "selenium-pangolin-3d8a91-mask-all-macro");
    common::assert_substring_absent(&path, "rhodium-lemur-5c2a93-mask-all-macro");
}

/// `format!(template, args...)` inside `#[mask_all]` is rewritten
/// to `mask_format!(template, args...)` when `template` is a string
/// literal. The literal-fragment text must be absent from binary
/// plaintext.
#[test]
fn mask_all_format_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "erbium-narwhal-1a4e83-mask-all-macro");
}

/// Output macros (`println!` etc.) with a literal template inside
/// `#[mask_all]` are wrapped so the formatted result flows through
/// `mask_format!` first; the template fragment must be absent from
/// binary plaintext.
#[test]
fn mask_all_println_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "praseodymium-tapir-9f2c14-mask-all-macro");
}

/// `panic!` with a literal message inside `#[mask_all]` is wrapped
/// analogously to the output macros — the message text gets masked
/// while the panic still fires at runtime. The fixture phrase must
/// be absent from the binary plaintext.
#[test]
fn mask_all_panic_message_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "rubidium-yak-7a9c54-mask-all-macro");
}

/// `write!`/`writeln!` with a literal template inside `#[mask_all]`
/// are wrapped via `mask_format!` so the literal text is masked while
/// the writer side-effect is preserved.
#[test]
fn mask_all_write_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "samarium-pika-6e1d35-mask-all-macro");
}

/// Qualified macro paths (`std::format!`, `core::dbg!`, etc.) are
/// recognized by their last path segment, so `std::format!("...")`
/// gets the same rewrite as bare `format!("...")` and its template
/// is masked.
#[test]
fn mask_all_qualified_path_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "ytterbium-finch-4b3a98-mask-all-macro");
}

/// `assert!` / `assert_eq!` / `assert_ne!` with a custom message
/// argument: the message text is masked while the assertion still
/// fires. The `debug_assert!` family is intentionally NOT scrubbed
/// here — its body is dead-code-eliminated in release builds via
/// `cfg!(debug_assertions)`, so absence of the literal is a property
/// of LLVM DCE rather than litmask's masking.
#[test]
fn mask_all_assert_with_message_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "iodine-okapi-9c2e41-mask-all-macro");
    common::assert_substring_absent(&path, "europium-meerkat-2d8c41-mask-all-macro");
    common::assert_substring_absent(&path, "thallium-gerbil-6a4e29-mask-all-macro");
}

/// Remaining `Output` family (`eprintln!`, `print!`, `eprint!`)
/// shares the println rewrite path; each template literal must be
/// absent from binary plaintext.
#[test]
fn mask_all_eprintln_print_eprint_templates_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "zirconium-marten-1b8d47-mask-all-macro");
    common::assert_substring_absent(&path, "vanadium-civet-4a2e83-mask-all-macro");
    common::assert_substring_absent(&path, "niobium-coati-7c5f29-mask-all-macro");
}

/// Remaining panic family (`todo!`, `unimplemented!`, `unreachable!`)
/// shares the panic rewrite path; each message literal must be
/// absent from binary plaintext.
#[test]
fn mask_all_todo_unimplemented_unreachable_messages_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "hafnium-aardvark-8d4e62-mask-all-macro");
    common::assert_substring_absent(&path, "tantalum-shrew-2a9f51-mask-all-macro");
    common::assert_substring_absent(&path, "ruthenium-loris-3c8e74-mask-all-macro");
}

/// `include_bytes!(...)` inside `#[mask_all]` is rewritten to
/// `mask_include_bytes!`, so the file bytes (a unique UTF-8
/// phrase) must be absent from the binary plaintext.
#[test]
fn mask_all_include_bytes_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "cobalt-narwhal-9c4e72-bytes-fixture");
}

/// Direct-call invocations of the six dedicated `mask_*!` macros
/// (not via `#[mask_all]`) MUST mask their plaintext as completely
/// as the rewrite path. `mask_macros_demo` exercises each macro at
/// its canonical form; this test pins absence for the three macros
/// with reliably-distinct fixture phrases. `mask_env!` /
/// `mask_option_env!` aren't asserted (env-dependent values);
/// `mask_file!`'s output is unobservable here because
/// `core::panic::Location::caller()` independently embeds the same
/// path string at every panic site.
#[test]
fn mask_macros_demo_direct_calls_absent_from_binary() {
    common::build_example("mask_macros_demo", Profile::Release);
    let path = common::example_path("mask_macros_demo", Profile::Release);
    // mask_include_str! — file contents.
    common::assert_substring_absent(&path, "vermilion-axolotl-7e2d4a");
    // mask_include_bytes! — file bytes.
    common::assert_substring_absent(&path, "cobalt-narwhal-9c4e72-bytes-fixture");
    // mask_concat! — concatenated string, including the integer /
    // float / bool / char stringifications which must all share
    // the same masked blob.
    common::assert_substring_absent(&path, "zephyr-quokka-direct");
}

/// Placeholder names (named args, implicit captures, dynamic-width
/// refs) MUST NOT appear in the compiled binary. The fixtures below
/// are unique tokens used as placeholder names in `mask_format_demo`;
/// their absence locks the proc-macro's positional rewriting.
#[test]
fn mask_format_placeholder_names_absent_from_binary() {
    common::build_example("mask_format_demo", Profile::Release);
    let path = common::example_path("mask_format_demo", Profile::Release);
    // Named arg.
    common::assert_substring_absent(&path, "vermilion_finch_5c2e9a");
    // Implicit-capture local name.
    common::assert_substring_absent(&path, "cobalt_terrapin_4b6f12");
    // Dynamic-width ref.
    common::assert_substring_absent(&path, "magenta_lemur_3e8a14");
}

/// `hello_world`, `static_provider`, and `file_provider` all mask
/// the same Twain quote — that's the canonical "first example"
/// payload the docs invite users to verify via `strings | grep`.
/// Without this test, a `mask!` regression in any of the three
/// would silently leak the quote and only the identifier scrub
/// would fire — and only if the regression also leaked a library
/// identifier. Probe on `"The reports of my death"` rather than
/// `"greatly exaggerated"` because the latter is common enough
/// English that dependency text could plausibly contain it; the
/// former is unique to the Twain quote.
#[test]
fn twain_fixture_absent_from_canonical_examples() {
    for name in ["hello_world", "static_provider", "file_provider"] {
        common::build_example(name, Profile::Release);
        let path = common::example_path(name, Profile::Release);
        common::assert_substring_absent(&path, "The reports of my death");
    }
}

/// `hw_id_provider` is gated behind `--features hw-id` (per its
/// `required-features` in `Cargo.toml`), so the workspace's default
/// `cargo build --workspace --examples` skips it cleanly and the
/// `test-examples` shell recipe cannot run it (init would fail with
/// `decryption_failed` without a prior `litmask-cli bind` step).
/// The masking property is testable without ever executing the
/// example: build with the feature and scrub the binary.
///
/// The test shells out to `cargo build --features hw-id` directly
/// rather than gating on `#[cfg(feature = "hw-id")]` — the test
/// binary itself doesn't need the feature enabled to invoke cargo
/// with it. That keeps the scrub running under the standard
/// `cargo test --workspace` invocation that CI uses.
///
/// Both scrubs apply: the Twain fixture must be absent (proves
/// `mask!` worked), and the identifier scrub runs with `"blake3"`
/// allow-listed. The `blake3` allow is the one unavoidable leak:
/// the `blake3` crate embeds its own name in internal symbol
/// strings (`blake3_*` function names) regardless of how the
/// downstream code uses it. The BLAKE3 context literal itself
/// (`"hw-v1"`) is hidden by `weak_mask!()` in
/// `HardwareIdProvider::unlock_key`, so it does NOT need an
/// allow-list entry — that's a load-bearing property of the
/// `weak_mask!()` call.
#[test]
fn hw_id_provider_example_masked_fixtures_absent_from_binary() {
    common::build_example_with_features("hw_id_provider", Profile::Release, &["hw-id"]);
    let path = common::example_path("hw_id_provider", Profile::Release);
    assert!(
        path.exists(),
        "hw_id_provider binary missing after build (did `cargo build --features hw-id --example hw_id_provider` succeed?): {}",
        path.display(),
    );
    common::assert_substring_absent(&path, "The reports of my death");
    // `hw-v1` MUST be absent: the runtime `weak_mask!()` is the
    // only thing standing between the BLAKE3 context literal and
    // a `strings(1)`-visible appearance. If a future refactor
    // drops the `weak_mask!()` wrapper, this assertion fires.
    common::assert_substring_absent(&path, "hw-v1");
    common::assert_no_dirty_words_except(&path, &["blake3"]);
}
