//! `mask_format!` — masked `format!`. Each literal fragment between
//! placeholders is encrypted separately; placeholder names never
//! land in the binary.
//!
//! Verify masking via the strings/grep recipe in `hello_world.rs`.

use litmask::mask_format;

fn main() {
    // ── Realistic usage ──
    // The static fragments (`saffron-...` and `amber-...`) are
    // masked; the runtime values are spliced in at format time.
    let user_id = 42;
    let amount = 99.95;
    let s = mask_format!(
        "saffron-koala-2b8e1c={} amber-otter-4f3d27={:.2}",
        user_id,
        amount
    );
    println!("{s}");

    // ── Placeholder-name probes ──
    // The unusual identifier names below double as scrub fixtures:
    // the example_scrub test asserts they're absent from the
    // compiled binary, proving `mask_format!` rewrites named /
    // implicit-capture / dynamic-width references to positional
    // form before emission.
    let named = mask_format!(
        "indigo-marmot-7a3e8b={vermilion_finch_5c2e9a}",
        vermilion_finch_5c2e9a = 1u32,
    );
    println!("{named}");

    let cobalt_terrapin_4b6f12 = "ok";
    let captured = mask_format!("crimson-bobcat-9d1c47={cobalt_terrapin_4b6f12}");
    println!("{captured}");

    let dynamic = mask_format!(
        "ochre-hedgehog-2f5d8e={:>magenta_lemur_3e8a14$}",
        "x",
        magenta_lemur_3e8a14 = 4,
    );
    println!("{dynamic}");
}
