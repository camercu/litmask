//! Demonstrates `#[mask_all]`. Every bare string-shaped literal in
//! the attributed module is rewritten to `mask!(literal)` at proc-
//! macro time. The fixture phrases are unique enough that the
//! integration test scrub can assert their plaintext absence from
//! the compiled release binary.

use litmask::mask_all;

#[mask_all]
mod demo {
    use std::fmt::Write as _;

    pub fn run() {
        // Each binding here is the rewritten value of a `mask!()`
        // call at runtime — the literal text never landed in
        // `.rodata`. The println below prints the decrypted forms
        // so a human can verify the round-trip, and the scrub
        // test confirms the originals are absent from the binary.
        let banner = "now-you-see-me-now-you-dont";
        let bytes = b"these-bytes-saw-too-much";
        let cstr = c"this-cstring-took-it-to-the-grave";
        // `.expect("...")` would have a string-literal argument that
        // `#[mask_all]` rewrites to `mask!(...)`, producing a `String`
        // where `.expect` wants `&str`. Use `.unwrap()` here to avoid
        // distracting from the demo, or wrap panic messages in
        // `unmasked!(...)` to opt out explicitly.
        let bytes_decoded = std::str::from_utf8(&bytes).unwrap();
        let cstr_decoded = cstr.to_str().unwrap();
        println!("banner={banner}");
        println!("bytes ={bytes_decoded}");
        println!("cstr  ={cstr_decoded}");

        // `include_str!` and `concat!` invocations are wrapped in
        // `mask!()` by the walker so the resulting strings are absent
        // from the binary plaintext.
        let included = include_str!("fixtures/mask_all_include_str.txt");
        let assembled = concat!("decrypt-", "me-", "if-you-can");
        println!("included ={}", included.trim());
        println!("assembled={assembled}");

        // `format!` with a literal template becomes `mask_format!`,
        // masking each fragment between placeholders. The
        // distinctive phrase below must be absent from the binary.
        let n = 7;
        let formatted = format!("this-fragment-survived-the-build={n}");
        println!("formatted={formatted}");

        // `println!` with a literal template is wrapped so the
        // formatted result flows through `mask_format!` first; the
        // template fragment must be absent from the binary.
        let m = 99;
        println!("this-line-is-off-the-record={m}");

        // `panic!` with a literal message — message text masked
        // while the panic still unwinds at runtime. The env-var guard
        // keeps the demo's normal run from actually unwinding; the
        // compiler can't drop the `panic!` call because the branch
        // is taken based on runtime env state.
        if std::env::var_os("LITMASK_DEMO_PANIC").is_some() {
            panic!("oops-the-secret-fell-out");
        }

        // `write!`/`writeln!` with a literal template — the template
        // moves into `mask_format!`, the original macro is re-emitted
        // with a `"{}"` placeholder over the masked result. Writer
        // (first arg) stays positional.
        let mut buf = String::new();
        write!(buf, "scribbled-in-the-margins={n}", n = 13).unwrap();
        println!("written ={buf}");

        // Qualified macro paths (`std::format!`, `core::panic!`,
        // etc.) are recognized by their last segment, so they get
        // the same rewrite as their unqualified forms.
        let qualified = std::format!("path-qualified-and-classified={n}", n = 17);
        println!("qualified={qualified}");

        // assert! with a custom message — the message text is masked
        // while the assertion still fires at runtime.
        let positive = 5;
        assert!(
            positive > 0,
            "this-better-be-true-or-else: value must be positive, got {positive}"
        );
        // assert_eq! / assert_ne! with custom messages — message is
        // masked while the operand comparison still runs. Pick
        // operands such that the assertion holds at runtime.
        let left = 7;
        let right = 7;
        assert_eq!(
            left, right,
            "twins-separated-at-birth: left={left} right={right}"
        );
        let differ_left = 11;
        let differ_right = 13;
        assert_ne!(
            differ_left, differ_right,
            "as-different-as-night-and-day: l={differ_left} r={differ_right}"
        );

        // The remaining `Output` family (`eprintln!`, `print!`,
        // `eprint!`) shares the println rewrite path. Each fixture
        // template fragment lands in `mask_format!` and the surrounding
        // macro is re-emitted with a `"{}"` placeholder.
        let err_n = 1;
        eprintln!("whispered-to-stderr={err_n}");
        let print_n = 2;
        print!("printed-in-invisible-ink={print_n}");
        // Force a newline so the stdout reader sees a clean line.
        println!();
        let eprint_n = 3;
        eprint!("muttered-under-my-breath={eprint_n}");
        eprintln!();

        // The rest of the panic family (`todo!`, `unimplemented!`,
        // `unreachable!`) shares the panic rewrite path. The env-var
        // guard keeps the demo's normal run from unwinding while the
        // compiler keeps the panic-arm reachable.
        if std::env::var_os("LITMASK_DEMO_TODO").is_some() {
            todo!("build-the-secret-lair-later: gating in progress");
        }
        if std::env::var_os("LITMASK_DEMO_UNIMPL").is_some() {
            unimplemented!("teleporter-not-invented-yet: experimental path");
        }
        if std::env::var_os("LITMASK_DEMO_UNREACH").is_some() {
            unreachable!("the-butler-definitely-did-it: invariant violated");
        }

        // `include_bytes!(...)` is rewritten to `mask_include_bytes!`,
        // so the file's raw bytes never appear in `.rodata`.
        let raw_bytes = include_bytes!("fixtures/binary_blob.bin");
        let raw_str = std::str::from_utf8(&raw_bytes).unwrap();
        println!("bytes_fixture={raw_str}");

        // `file!()` is rewritten to `mask_file!()` so the source path
        // (which would otherwise land verbatim in `.rodata`) is
        // masked.
        let path: String = file!();
        println!("file_path_len={}", path.len());
    }
}

fn main() {
    demo::run();
}
