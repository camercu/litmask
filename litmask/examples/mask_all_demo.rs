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
        let banner = "uranium-walrus-5f8d23-task12";
        let bytes = b"thorium-loris-2a9b41-task12";
        let cstr = c"polonium-dingo-7c4e68-task12";
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
        let included = include_str!("examples/fixtures/task13_include_str.txt");
        let assembled = concat!("rhodium-", "lemur-", "5c2a93-task13");
        println!("included ={}", included.trim());
        println!("assembled={assembled}");

        // `format!` with a literal template becomes `maskfmt!`,
        // masking each fragment between placeholders. The
        // high-entropy phrase below must be absent from the binary.
        let n = 7;
        let formatted = format!("erbium-narwhal-1a4e83-task13={n}");
        println!("formatted={formatted}");

        // `println!` with a literal template is wrapped so the
        // formatted result flows through `maskfmt!` first; the
        // template fragment must be absent from the binary.
        let m = 99;
        println!("praseodymium-tapir-9f2c14-task13={m}");

        // `panic!` with a literal message — message text masked
        // while the panic still unwinds at runtime. The env-var guard
        // keeps the demo's normal run from actually unwinding; the
        // compiler can't drop the `panic!` call because the branch
        // is taken based on runtime env state.
        if std::env::var_os("LITMASK_DEMO_PANIC").is_some() {
            panic!("rubidium-yak-7a9c54-task13");
        }

        // `write!`/`writeln!` with a literal template — the template
        // moves into `maskfmt!`, the original macro is re-emitted
        // with a `"{}"` placeholder over the masked result. Writer
        // (first arg) stays positional.
        let mut buf = String::new();
        write!(buf, "samarium-pika-6e1d35-task13={n}", n = 13).unwrap();
        println!("written ={buf}");

        // Qualified macro paths (`std::format!`, `core::panic!`,
        // etc.) are recognized by their last segment, so they get
        // the same rewrite as their unqualified forms.
        let qualified = std::format!("ytterbium-finch-4b3a98-task13={n}", n = 17);
        println!("qualified={qualified}");

        // assert! with a custom message — the message text is masked
        // while the assertion still fires at runtime.
        let positive = 5;
        assert!(
            positive > 0,
            "iodine-okapi-9c2e41-task13: value must be positive, got {positive}"
        );
    }
}

fn main() {
    demo::run();
}
