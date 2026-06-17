//! Runtime support for the `MaskDeserialize` derive (`serde`).
//!
//! `#[doc(hidden)]` — referenced only by macro-generated code through
//! `::litmask::__serde_support::...`. The derive cannot use
//! `serde::__private` (semver-exempt), so the two pieces of the plain
//! derive's expansion that live there are replicated here against
//! serde's public API, preserving behavior byte-for-byte.

use core::fmt;
use core::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, Error, Expected, Visitor};

/// Resolve a field that never appeared in the input, mirroring
/// `serde::__private::de::missing_field`: `Option<T>` (and any type
/// whose `Deserialize` handles `deserialize_option`) resolves to its
/// "absent" value, every other type fails with
/// `Error::missing_field(field)`. Without this split, a missing
/// `Option<T>` field would error where the plain derive yields `None`.
pub fn missing_field<'de, V, E>(field: &'static str) -> Result<V, E>
where
    V: Deserialize<'de>,
    E: Error,
{
    struct MissingFieldDeserializer<E>(&'static str, PhantomData<E>);

    impl<'de, E> Deserializer<'de> for MissingFieldDeserializer<E>
    where
        E: Error,
    {
        type Error = E;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, E>
        where
            V: Visitor<'de>,
        {
            Err(Error::missing_field(self.0))
        }

        fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, E>
        where
            V: Visitor<'de>,
        {
            visitor.visit_none()
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    Deserialize::deserialize(MissingFieldDeserializer(field, PhantomData))
}

/// `Expected` payload for `Error::invalid_length` whose text matches
/// the plain derive's compile-time literal (`"struct Config with 2
/// elements"`, singular `"… with 1 element"`). The plain derive bakes
/// the type name into a `&'static str` literal; the masked derive
/// must compose the same text at runtime from the decrypted name.
pub struct ExpectedElements {
    /// Shape prefix exactly as serde words it: `"struct"`,
    /// `"tuple struct"`, `"tuple variant"`, or `"struct variant"`.
    pub shape: &'static str,
    /// Decrypted container name.
    pub name: &'static str,
    /// Decrypted variant name, rendered as `Name::Variant` — serde's
    /// wording for tuple/struct variants.
    pub variant: Option<&'static str>,
    pub count: usize,
}

impl Expected for ExpectedElements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.shape, self.name)?;
        if let Some(variant) = self.variant {
            write!(formatter, "::{variant}")?;
        }
        if self.count == 1 {
            write!(formatter, " with 1 element")
        } else {
            write!(formatter, " with {} elements", self.count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(expected: &dyn Expected) -> std::string::String {
        use std::string::ToString;
        // `Expected` renders through `Display` of this adapter — the
        // same path `serde::de::Error::invalid_length` uses.
        struct Adapter<'a>(&'a dyn Expected);
        impl fmt::Display for Adapter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Expected::fmt(self.0, f)
            }
        }
        Adapter(expected).to_string()
    }

    #[test]
    fn expected_elements_pluralizes_like_serde_derive() {
        let one = ExpectedElements {
            shape: "struct",
            name: "Config",
            variant: None,
            count: 1,
        };
        assert_eq!(render(&one), "struct Config with 1 element");
        let two = ExpectedElements {
            shape: "tuple struct",
            name: "Pair",
            variant: None,
            count: 2,
        };
        assert_eq!(render(&two), "tuple struct Pair with 2 elements");
        let variant = ExpectedElements {
            shape: "tuple variant",
            name: "Channel",
            variant: Some("Jitter"),
            count: 2,
        };
        assert_eq!(
            render(&variant),
            "tuple variant Channel::Jitter with 2 elements"
        );
    }

    #[test]
    fn missing_field_yields_none_for_option() {
        let value: Option<u32> =
            missing_field::<'_, _, serde::de::value::Error>("retry_budget").expect("Option");
        assert_eq!(value, None);
    }

    #[test]
    fn missing_field_errors_for_required_type() {
        use std::string::ToString;
        let err = missing_field::<'_, u32, serde::de::value::Error>("retry_budget")
            .expect_err("required type must fail");
        assert_eq!(err.to_string(), "missing field `retry_budget`");
    }
}
