//! `#[mask_all]` applies only to module items. Other targets
//! (functions, structs, etc.) must fail with a typed error naming
//! the constraint — not the opaque syn "expected `mod`" parse error
//! that an unguarded `parse_macro_input!` would emit.

use litmask::mask_all;

#[mask_all]
fn not_a_module() {
    let _ = "wrong target";
}

fn main() {
    not_a_module();
}
