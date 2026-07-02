//! Crate-wide typed errors. No `process::exit` anywhere — every fallible op
//! returns `Result<_, Error>` so RAII guards unwind (foundation §2.1).
//! WHY: a variant must never embed a secret value (§3) — carry an id + reason.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("decision {id}: {reason}")] // reason is non-secret (e.g. "pin too short: len < 8")
    Resolve { id: &'static str, reason: String },
    #[error("identity: {0}")]
    KeyIdentity(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("runner: {0}")]
    Runner(String),
    #[error("compliance: {0}")] // regime-qualified, non-secret (Plan 2b maps ComplianceError here)
    Compliance(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_error_carries_id_and_nonsecret_reason() {
        // WHY (§3): a resolution error must surface the decision id + a non-secret
        // reason and NEVER the secret value.
        let e = Error::Resolve {
            id: "pin-min-length",
            reason: "len < 8".into(),
        };
        let rendered = e.to_string();
        assert!(rendered.contains("pin-min-length"));
        assert!(rendered.contains("len < 8"));
    }
}
