//! Keywright core engine (UI-agnostic). Real modules land in Plan 2.

// Spec §9: a build with panic="abort" would skip the RAII Drop guards that
// zeroize secrets and unlink tmpfs state. Fail the build rather than ship that.
#[cfg(panic = "abort")]
compile_error!("keywright-core requires panic=unwind (see workspace Cargo.toml profiles, spec §9)");

pub mod errors;
pub mod registry;

pub use errors::{Error, Result};

/// Returns the compiled crate version (proves the lib builds and is testable).                     
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_nonempty() {
        // WHY: build-smoke — the lib compiles and is testable.
        assert!(!version().is_empty());
    }
}
