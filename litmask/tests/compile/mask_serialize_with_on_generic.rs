//! `with` / `serialize_with` / `deserialize_with` is not yet supported
//! on a generic type — the generated adapter is a local item that
//! cannot name the surrounding impl's generic parameters.

use litmask::MaskSerialize;

fn to_wire<S: serde::Serializer, T>(_value: &T, _serializer: S) -> Result<S::Ok, S::Error> {
    unimplemented!()
}

#[derive(MaskSerialize)]
struct ExfilManifest<T> {
    #[serde(serialize_with = "to_wire")]
    value: T,
}

fn main() {}
