# litmask-macros

Internal proc-macro crate for [`litmask`](https://crates.io/crates/litmask).
Implements `mask!`, `mask_all!`, and the related compile-time encryption
macros, which `litmask` re-exports.

**Not a public API.** Do not depend on this crate directly — its macros are
meant to be used through [`litmask`](https://crates.io/crates/litmask), which
re-exports them alongside the runtime they require.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT)
at your option.
