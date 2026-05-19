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

/// Every example binary the workspace ships. Add new names here when
/// new examples land under `litmask/examples/`.
const EXAMPLES: &[&str] = &[
    "hello_world",
    "weak_mask_demo",
    "byte_cstr_demo",
    "include_str_demo",
    "mask_fmt_demo",
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

/// `weak_mask!` must obfuscate user-supplied literals so the plaintext
/// is absent from the compiled binary. The fixture is deliberately a
/// lexically unusual phrase so a false-positive against std /
/// dependency strings is implausible.
#[test]
fn weak_mask_fixture_absent_from_binary() {
    common::build_example("weak_mask_demo", Profile::Release);
    let path = common::example_path("weak_mask_demo", Profile::Release);
    common::assert_substring_absent(&path, "yellow-velvet-tortoise-9c4f1a");
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

/// `mask_fmt!` must mask the literal fragments between placeholders
/// so the template text never appears in plaintext. Each fragment
/// phrase is lexically unusual to make the absence assertion
/// precise.
#[test]
fn mask_fmt_fragments_absent_from_binary() {
    common::build_example("mask_fmt_demo", Profile::Release);
    let path = common::example_path("mask_fmt_demo", Profile::Release);
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
/// to `mask_fmt!(template, args...)` when `template` is a string
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
/// `mask_fmt!` first; the template fragment must be absent from
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
/// are wrapped via `mask_fmt!` so the literal text is masked while
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

/// Placeholder names (named args, implicit captures, dynamic-width
/// refs) MUST NOT appear in the compiled binary. The fixtures below
/// are unique tokens used as placeholder names in `mask_fmt_demo`;
/// their absence locks the proc-macro's positional rewriting.
#[test]
fn mask_fmt_placeholder_names_absent_from_binary() {
    common::build_example("mask_fmt_demo", Profile::Release);
    let path = common::example_path("mask_fmt_demo", Profile::Release);
    // Named arg.
    common::assert_substring_absent(&path, "vermilion_finch_5c2e9a");
    // Implicit-capture local name.
    common::assert_substring_absent(&path, "cobalt_terrapin_4b6f12");
    // Dynamic-width ref.
    common::assert_substring_absent(&path, "magenta_lemur_3e8a14");
}
