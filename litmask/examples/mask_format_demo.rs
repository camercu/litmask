//! `mask_format!` — masked `format!`. Each literal fragment between
//! placeholders is encrypted separately; placeholder names never
//! land in the binary.
//!
//! Verify masking via the strings/grep recipe in `hello_world.rs`.

use litmask::mask_format;

fn main() {
    // ── Realistic usage ──
    // The static fragments (`account `, ` drained $`, and `, blame
    // the raccoons`) are masked; the runtime values are spliced in at
    // format time.
    let user_id = 42;
    let amount = 99.95;
    let s = mask_format!(
        "account {} drained ${:.2}, blame the raccoons",
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
        "this-name-is-a-secret={nobody_will_ever_guess_this}",
        nobody_will_ever_guess_this = 1u32,
    );
    println!("{named}");

    let the_secret_ingredient = "ok";
    let captured = mask_format!("captured-and-hidden={the_secret_ingredient}");
    println!("{captured}");

    let dynamic = mask_format!(
        "width-on-a-need-to-know-basis={:>eyes_only_field_width$}",
        "x",
        eyes_only_field_width = 4,
    );
    println!("{dynamic}");
}
