//! `MaskedSerialize` must reject generic structs while the prototype
//! does not yet emit bounded impls.

use litmask::MaskedSerialize;

#[derive(MaskedSerialize)]
struct Wrapper<T> {
    inner: T,
}

fn main() {}
