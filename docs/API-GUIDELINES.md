# Rust API Guidelines

Checklist from [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/). Organized into actionable review list. ([Rust Programming Language][1])

## Naming

- Crate/module/function names follow Rust conventions. Reason: ecosystem consistency. Use `snake_case` for values, `UpperCamelCase` for types. ([Rust Programming Language][2])
- Acronyms normalized. Reason: idiomatic naming. Use `Uuid`, not `UUID`. ([Rust Programming Language][2])
- Conversion methods use standard prefixes. Reason: predictable semantics.
  - `as_*` cheap ref/view conversion
  - `to_*` expensive owned conversion
  - `into_*` consuming conversion ([Rust Programming Language][1])

- Getter names omit `get_`. Reason: Rust convention. Use `len()`, not `get_len()`. Reserve `get()` for fallible indexing. ([Rust Programming Language][1])
- Collection iterators named consistently. Reason: discoverability.
  - `iter()` shared
  - `iter_mut()` mutable
  - `into_iter()` consuming ([Rust Programming Language][1])

- Iterator type names mirror methods. Reason: API predictability. `Vec::iter()` → `Iter`. ([Rust Programming Language][1])
- Feature flags use meaningful names. Reason: cargo UX. Avoid `default`, `extras`, `stuff`. ([Rust Programming Language][1])
- Word order consistent across API. Reason: grepability. Pick one pattern. Keep everywhere. ([Rust Programming Language][1])

## Trait Interop

- Implement common traits eagerly. Reason: ecosystem integration. Check:
  - `Copy`
  - `Clone`
  - `Eq`
  - `PartialEq`
  - `Ord`
  - `PartialOrd`
  - `Hash`
  - `Debug`
  - `Display`
  - `Default` ([Rust Programming Language][1])

- Use standard conversion traits. Reason: composability. Prefer `From`, `Into`, `AsRef`, `AsMut`. Avoid custom conversion APIs. ([Rust Programming Language][1])
- Collections implement `FromIterator` + `Extend`. Reason: iterator ecosystem compatibility. Support `.collect()` + extension patterns. ([Rust Programming Language][1])
- Data types implement Serde traits when appropriate. Reason: serialization interoperability. Add `Serialize` + `Deserialize`. ([Rust Programming Language][1])
- Types become `Send` + `Sync` when possible. Reason: concurrency support. Avoid unnecessary `Rc<RefCell<_>>` in public structures. ([Rust Programming Language][1])
- Error types carry useful context. Reason: diagnosability. Implement `std::error::Error`, `Display`, source chaining. ([Rust Programming Language][1])
- Binary numeric types implement formatting traits. Reason: tooling/debug utility. Add `Binary`, `Octal`, `LowerHex`, `UpperHex`. ([Rust Programming Language][1])
- Reader/writer generics take ownership. Reason: flexibility. Prefer:

```rust
fn read<R: Read>(r: R)
```

not:

```rust
fn read<R: Read>(r: &mut R)
```

unless borrow required. ([Rust Programming Language][1])

## Macros

- Macro input syntax resembles output syntax. Reason: readability. Macros should “feel” like expanded code. ([Rust Programming Language][1])
- Macros compose with attributes. Reason: tooling + ergonomics. Support `#[derive]`, visibility, docs cleanly. ([Rust Programming Language][1])
- Item macros work anywhere item valid. Reason: composability. Support module/file nesting. ([Rust Programming Language][1])
- Item macros support visibility specifiers. Reason: API control. Accept `pub`, `pub(crate)`, etc. ([Rust Programming Language][1])
- Type fragments flexible. Reason: macro usability. Accept generics, paths, lifetimes, trait objects. ([Rust Programming Language][1])
- Avoid macros when normal API sufficient. Reason: compile-time + tooling costs. Prefer functions/builders first. ([Reddit][3])

## Documentation

- Crate-level docs comprehensive. Reason: onboarding. Include overview, goals, examples, feature flags. ([Rust Programming Language][4])
- Every public item documented. Reason: API usability. Include rustdoc examples. ([Rust Programming Language][4])
- Examples show “why”, not only “how”. Reason: practical comprehension. Demonstrate realistic use. ([Rust Programming Language][4])
- Examples use `?`. Reason: idiomatic error handling. Avoid `unwrap()` + obsolete `try!`. ([Rust Programming Language][1])
- Docs include failure semantics. Reason: safety. Document:
  - Errors
  - Panics
  - Unsafe requirements ([Rust Programming Language][1])

- Docs hyperlink related APIs/types. Reason: navigability. Use rustdoc intra-doc links. ([Rust Programming Language][1])
- `Cargo.toml` metadata complete. Reason: discoverability. Include:
  - description
  - license
  - repository
  - homepage
  - docs
  - keywords
  - categories ([Rust Programming Language][1])

- Release notes maintained. Reason: upgrade safety. Document breaking + behavioral changes. ([Rust Programming Language][1])
- Hide irrelevant implementation details in docs. Reason: signal/noise ratio. Use `#[doc(hidden)]` carefully. ([Rust Programming Language][1])

## Predictability

- Smart pointers avoid inherent methods. Reason: deref confusion. Put methods on pointee type. ([Rust Programming Language][1])
- Conversions live on most specific type. Reason: discoverability. Avoid unrelated helper namespaces. ([Rust Programming Language][1])
- Functions with obvious receiver become methods. Reason: fluent API. Example:

```rust
socket.connect()
```

not:

```rust
connect(socket)
```

([Rust Programming Language][1])

- Avoid out-parameters. Reason: ownership clarity. Return values directly. ([Rust Programming Language][1])
- Operator overloads remain unsurprising. Reason: semantic clarity. `+` means addition/combine, not network call. ([Rust Programming Language][1])
- Only smart pointers implement `Deref`. Reason: method resolution sanity. Avoid fake inheritance. ([Rust Programming Language][1])
- Constructors become inherent static methods. Reason: discoverability. Use `new`, `with_capacity`, `from_*`. ([Rust Programming Language][1])

## Flexibility

- Expose intermediate results. Reason: avoid recomputation. Let callers reuse parsing/planning phases. ([Rust Programming Language][1])
- Caller controls allocation/copy placement. Reason: performance flexibility. Accept output buffers/slices when useful. ([Rust Programming Language][1])
- APIs minimize assumptions using generics. Reason: ergonomics. Prefer:

```rust
impl AsRef<Path>
impl IntoIterator
impl Into<String>
```

over concrete types. ([Rust Programming Language][1])

- Avoid generic explosion. Reason: code bloat + compile cost. Use concrete types when polymorphism adds no value. ([Reddit][5])
- Traits object-safe when trait objects useful. Reason: dynamic dispatch support. Avoid unnecessary `Self: Sized`. ([Rust Programming Language][1])

## Type Safety

- Use newtypes for semantic distinction. Reason: prevent argument mixups. Example:

```rust
struct UserId(u64);
struct ProductId(u64);
```

([Rust Programming Language][1])

- Encode meaning in types, not booleans/options. Reason: self-documenting APIs. Replace:

```rust
fn open(path, true)
```

with enum/builder. ([Rust Programming Language][1])

- Flag sets use `bitflags`. Reason: combinability. Avoid giant enums for bitmask semantics. ([Rust Programming Language][1])
- Builders construct complex types. Reason: readability + forward compatibility. Especially many optional params. ([Rust Programming Language][1])

## Dependability

- Validate inputs early. Reason: fail fast. Reject invalid states immediately. ([Rust Programming Language][1])
- Destructors never fail. Reason: panic safety. `Drop` must not panic. ([Rust Programming Language][1])
- Blocking cleanup gets explicit API. Reason: runtime predictability. Avoid blocking in `Drop`; provide `close()`/`shutdown()`. ([Rust Programming Language][1])

## Debuggability

- Every public type implements `Debug`. Reason: diagnostics. Missing `Debug` harms tooling/tests. ([Rust Programming Language][1])
- `Debug` output never empty/useless. Reason: troubleshooting. Include meaningful state. ([Rust Programming Language][1])

## Future Proofing

- Seal extension traits when downstream impls unsafe. Reason: semver flexibility. Use private sealed trait pattern. ([Rust Programming Language][1])
- Public structs keep fields private. Reason: nonbreaking evolution. Add accessors/builders instead. ([Rust Programming Language][1])
- Use newtypes to hide implementation details. Reason: swap internals later. Avoid leaking dependencies. ([Rust Programming Language][1])
- Avoid redundant trait bounds on structs. Reason: future compatibility. Put bounds on impls/functions instead. ([Rust Programming Language][1])
- Avoid exposing unstable dependency types. Reason: semver stability. Public dependency becomes API commitment. ([Rust Programming Language][6])
- Be careful exposing enums. Reason: adding variants breaks matches. Use `#[non_exhaustive]` or structs where growth expected. ([Reddit][7])

## Necessities

- Stable crate exposes only stable public deps. Reason: semver correctness. Audit public signatures carefully. ([Rust Programming Language][6])
- Crate + deps use permissive licenses. Reason: adoption compatibility. Prefer MIT/Apache-2.0 dual-license pattern. ([Rust Programming Language][1])

## High-value meta patterns

- Design public API first. Reason: implementation should serve UX, not inverse. Prototype usage before internals. ([Reddit][7])
- Keep public API minimal. Reason: semver surface area reduction. Expose intent, hide machinery. ([Reddit][7])
- Prefer conventions over novelty. Reason: Rust usability depends heavily on predictability. ([arXiv][8])
- Use Clippy + rustfmt aggressively. Reason: automated convention enforcement. Treat warnings seriously. ([Reddit][9])

[1]: https://rust-lang.github.io/api-guidelines/checklist.html "Checklist - Rust API Guidelines"
[2]: https://rust-lang.github.io/api-guidelines/naming.html "Naming - Rust API Guidelines"
[3]: https://www.reddit.com/r/rust/comments/11t14vz "Resources for writing good proc-macros?"
[4]: https://rust-lang.github.io/api-guidelines/documentation.html "Documentation - Rust API Guidelines"
[5]: https://www.reddit.com/r/rust/comments/126qzbw "What is the proper guidance on using generics as parameters for an API"
[6]: https://rust-lang.github.io/api-guidelines/necessities.html "Necessities - Rust API Guidelines"

[7]: https://www.reddit.com/r/rust/comments/n3gjv3 "Writing libraries: \"Am I doing this right?\""
[8]: https://arxiv.org/abs/2601.16705 "Developer Perspectives on REST API Usability: A Study of REST API Guidelines"
[9]: https://www.reddit.com/r/rust/comments/1sepzz8/rust_best_practices/ "Rust \"Best\" Practices"
