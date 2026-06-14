//! Once-init cell shared by the mask-key cell and the `weak_mask!()`
//! per-call-site caches.
//!
//! `std::sync::OnceLock` and `once_cell::race::OnceBox` have
//! differently-shaped APIs (`OnceBox` stores `Box<T>` and its
//! `get_or_init` closure must return one); this wrapper normalizes
//! both behind one interface so every consumer stays
//! feature-flag-free and the `std`/`no_std` split lives in exactly
//! one place.

/// At-most-once initialized cell. `pub` (not `pub(crate)`) because the
/// `weak_mask!()` cache aliases in [`super::weak`] expose it — via
/// `crate::__internal` — to macro-expanded code in consumer crates,
/// where its `const fn new` and `get_or_init` are called directly.
#[doc(hidden)]
pub struct OnceCell<T> {
    #[cfg(feature = "std")]
    inner: std::sync::OnceLock<T>,
    #[cfg(not(feature = "std"))]
    inner: once_cell::race::OnceBox<T>,
}

impl<T> OnceCell<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::OnceLock::new(),
            #[cfg(not(feature = "std"))]
            inner: once_cell::race::OnceBox::new(),
        }
    }

    /// Best-effort set: the first value wins and a racing loser is
    /// dropped silently. Both init seams rely on this — a repeat
    /// explicit `init!` call is a no-op, never an error (the debug
    /// init-after-lazy guard fires before any `try_set`).
    pub fn try_set(&self, value: T) {
        #[cfg(feature = "std")]
        let _ = self.inner.set(value);
        #[cfg(not(feature = "std"))]
        let _ = self.inner.set(alloc::boxed::Box::new(value));
    }

    pub fn is_set(&self) -> bool {
        self.inner.get().is_some()
    }

    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        #[cfg(feature = "std")]
        {
            self.inner.get_or_init(f)
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner.get_or_init(|| alloc::boxed::Box::new(f()))
        }
    }
}

impl<T> Default for OnceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_init_initializes_once_and_caches() {
        let cell = OnceCell::new();
        let calls = core::cell::Cell::new(0u8);
        let first = *cell.get_or_init(|| {
            calls.set(calls.get() + 1);
            7u32
        });
        // The second initializer must never run; the cached value wins.
        let second = *cell.get_or_init(|| {
            calls.set(calls.get() + 1);
            9u32
        });
        assert_eq!((first, second, calls.get()), (7, 7, 1));
    }

    #[test]
    fn try_set_first_value_wins_and_loser_is_ignored() {
        let cell = OnceCell::new();
        cell.try_set(1u32);
        cell.try_set(2u32);
        assert_eq!(cell.get_or_init(|| 3), &1);
    }

    #[test]
    fn is_set_transitions_after_first_set() {
        let cell = OnceCell::new();
        assert!(!cell.is_set());
        cell.try_set(5u32);
        assert!(cell.is_set());
    }
}
