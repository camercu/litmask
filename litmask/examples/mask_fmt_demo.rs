//! Demonstrates `mask_fmt!`. The fragment phrases between placeholders
//! plus the unique placeholder names exercised below are unique
//! enough that the integration test scrub can assert they are absent
//! from the compiled release binary.

use litmask::mask_fmt;

fn main() {
    let user_id = 42;
    let amount = 99.95;
    let s = mask_fmt!(
        "saffron-koala-2b8e1c={} amber-otter-4f3d27={:.2}",
        user_id,
        amount
    );
    println!("{s}");

    // Named arg: the binary must not carry the placeholder name
    // `vermilion_finch_5c2e9a`.
    let named = mask_fmt!(
        "indigo-marmot-7a3e8b={vermilion_finch_5c2e9a}",
        vermilion_finch_5c2e9a = 1u32,
    );
    println!("{named}");

    // Implicit capture: the binary must not carry the local name
    // `cobalt_terrapin_4b6f12`, which we capture against
    // `{cobalt_terrapin_4b6f12}` in the template.
    let cobalt_terrapin_4b6f12 = "ok";
    let captured = mask_fmt!("crimson-bobcat-9d1c47={cobalt_terrapin_4b6f12}");
    println!("{captured}");

    // Dynamic width: the binary must not carry the dynamic-ref name
    // `magenta_lemur_3e8a14`.
    let dynamic = mask_fmt!(
        "ochre-hedgehog-2f5d8e={:>magenta_lemur_3e8a14$}",
        "x",
        magenta_lemur_3e8a14 = 4,
    );
    println!("{dynamic}");
}
