//! End-to-end example for `mask_stack!`: decrypt a literal into a
//! stack-resident, zero-alloc guard that wipes itself on drop.
//!
//! Like `hello_world`, the fixture below is AEAD-encrypted at compile
//! time and absent from the binary's `.rodata`. Unlike `mask!` (which
//! returns a heap `String`), `mask_stack!` decrypts straight into an
//! inline `[u8; N]` — no allocation — and the guard derefs to `str`.
//!
//! ```sh
//! cargo build --example stack_demo --features stack
//! strings target/debug/examples/stack_demo | grep "parsnip clavicle"
//! # (no output — the plaintext is absent from the binary)
//!
//! ./target/debug/examples/stack_demo
//! # prints the decrypted fixture; the Embedded tier self-initializes
//! ```
//!
//! The fixture is high-entropy nonsense so the `strings` grep above
//! cannot false-positive against std or dependency text.

use litmask::mask_stack;

fn main() {
    let secret = mask_stack!("stack-resident secret: parsnip clavicle 8842");
    proprietary_gonculator(&secret);
}

fn proprietary_gonculator(data: &str) {
    // do magic stuff
    println!("{data}");
}
