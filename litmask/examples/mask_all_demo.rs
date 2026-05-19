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
        let banner = "uranium-walrus-5f8d23-mask-all-bare";
        let bytes = b"thorium-loris-2a9b41-mask-all-bare";
        let cstr = c"polonium-dingo-7c4e68-mask-all-bare";
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
        let included = include_str!("examples/fixtures/mask_all_include_str.txt");
        let assembled = concat!("rhodium-", "lemur-", "5c2a93-mask-all-macro");
        println!("included ={}", included.trim());
        println!("assembled={assembled}");

        // `format!` with a literal template becomes `mask_fmt!`,
        // masking each fragment between placeholders. The
        // high-entropy phrase below must be absent from the binary.
        let n = 7;
        let formatted = format!("erbium-narwhal-1a4e83-mask-all-macro={n}");
        println!("formatted={formatted}");

        // `println!` with a literal template is wrapped so the
        // formatted result flows through `mask_fmt!` first; the
        // template fragment must be absent from the binary.
        let m = 99;
        println!("praseodymium-tapir-9f2c14-mask-all-macro={m}");

        // `panic!` with a literal message — message text masked
        // while the panic still unwinds at runtime. The env-var guard
        // keeps the demo's normal run from actually unwinding; the
        // compiler can't drop the `panic!` call because the branch
        // is taken based on runtime env state.
        if std::env::var_os("LITMASK_DEMO_PANIC").is_some() {
            panic!("rubidium-yak-7a9c54-mask-all-macro");
        }

        // `write!`/`writeln!` with a literal template — the template
        // moves into `mask_fmt!`, the original macro is re-emitted
        // with a `"{}"` placeholder over the masked result. Writer
        // (first arg) stays positional.
        let mut buf = String::new();
        write!(buf, "samarium-pika-6e1d35-mask-all-macro={n}", n = 13).unwrap();
        println!("written ={buf}");

        // Qualified macro paths (`std::format!`, `core::panic!`,
        // etc.) are recognized by their last segment, so they get
        // the same rewrite as their unqualified forms.
        let qualified = std::format!("ytterbium-finch-4b3a98-mask-all-macro={n}", n = 17);
        println!("qualified={qualified}");

        // assert! with a custom message — the message text is masked
        // while the assertion still fires at runtime.
        let positive = 5;
        assert!(
            positive > 0,
            "iodine-okapi-9c2e41-mask-all-macro: value must be positive, got {positive}"
        );
        // assert_eq! / assert_ne! with custom messages — message is
        // masked while the operand comparison still runs. Pick
        // operands such that the assertion holds at runtime.
        let left = 7;
        let right = 7;
        assert_eq!(
            left, right,
            "europium-meerkat-2d8c41-mask-all-macro: left={left} right={right}"
        );
        let differ_left = 11;
        let differ_right = 13;
        assert_ne!(
            differ_left, differ_right,
            "thallium-gerbil-6a4e29-mask-all-macro: l={differ_left} r={differ_right}"
        );

        // The remaining `Output` family (`eprintln!`, `print!`,
        // `eprint!`) shares the println rewrite path. Each fixture
        // template fragment lands in `mask_fmt!` and the surrounding
        // macro is re-emitted with a `"{}"` placeholder.
        let err_n = 1;
        eprintln!("zirconium-marten-1b8d47-mask-all-macro={err_n}");
        let print_n = 2;
        print!("vanadium-civet-4a2e83-mask-all-macro={print_n}");
        // Force a newline so the stdout reader sees a clean line.
        println!();
        let eprint_n = 3;
        eprint!("niobium-coati-7c5f29-mask-all-macro={eprint_n}");
        eprintln!();

        // The rest of the panic family (`todo!`, `unimplemented!`,
        // `unreachable!`) shares the panic rewrite path. The env-var
        // guard keeps the demo's normal run from unwinding while the
        // compiler keeps the panic-arm reachable.
        if std::env::var_os("LITMASK_DEMO_TODO").is_some() {
            todo!("hafnium-aardvark-8d4e62-mask-all-macro: gating in progress");
        }
        if std::env::var_os("LITMASK_DEMO_UNIMPL").is_some() {
            unimplemented!("tantalum-shrew-2a9f51-mask-all-macro: experimental path");
        }
        if std::env::var_os("LITMASK_DEMO_UNREACH").is_some() {
            unreachable!("ruthenium-loris-3c8e74-mask-all-macro: invariant violated");
        }
    }
}

fn main() {
    demo::run();
}
