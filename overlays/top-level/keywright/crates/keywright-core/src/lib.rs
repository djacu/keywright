//! Keywright core engine (UI-agnostic). Real modules land in Plan 2.

/// Returns the compiled crate version (proves the lib builds and is testable).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }
}
