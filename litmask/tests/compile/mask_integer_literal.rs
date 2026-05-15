//! §2.1.1.5/§2.1.1.6: `mask!` must reject non-string/byte/c-string
//! literals with the required substring "mask! accepts string, byte
//! string, or C string literals".

use litmask::mask;

fn main() {
    let _ = mask!(42);
}
