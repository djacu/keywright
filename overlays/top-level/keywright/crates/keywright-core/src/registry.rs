//! The decision registry — every operator decision declared once (§3).
//! CLI flags, TOML keys, audit fields all derive from this one slice.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Bool,
    Compliance,
    CnsaUse,
    PinSource,
    AdminPin,
    Failure,
    Uint,
    Expiry,
    AlgoProfile,
    DeviceList,
    Pin,
    Str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionEnumValues {
    Compliance(ComplianceProfile),
    CnsaUse(CnsaUseCase),
    PinSource(PinSource),
    AdminPin(AdminPinScope),
    Failure(FailureBehavior),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceProfile {
    DrDuh,
    Fips,
    Cnsa,
    Bsi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnsaUseCase {
    Nss2030,
    Nss2033,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    Generated,
    Chosen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPinScope {
    PerCard,
    FleetShared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureBehavior {
    AbortLeaveClean,
    FactoryResetAndAbort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Ed25519,
    Ed448,
    Cv25519,
    Rsa(u16),
    NistP(u16),
    Brainpool(u16),
    Secp256k1,
} // Ed448/secp256k1: representable so Plan 2b's compliance can forbid them under fips (§5)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Never,
    Days(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Certify,
    Sign,
    Auth,
    Encrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgoSpec {
    pub algo: Algo,
    pub expiry: Expiry,
}

#[derive(Debug, Clone, Copy)]
pub enum DefaultValue {
    None,
    Bool(bool),
    DecisionEnum(DecisionEnumValues),
    Uint(u64),
    Expiry(Expiry),
    Str(&'static str),
    DeviceList(&'static [&'static str]), // empty slice = "[]" default
    Algo(&'static [(Role, AlgoSpec)]),
}

#[derive(Debug, Clone, Copy)]
pub struct Decision {
    /// canonical id → CLI flag (--kebab), TOML key, audit field
    pub id: &'static str,
    pub value_type: ValueType,
    pub default_value: DefaultValue,
    /// non-interactive + unsupplied + no default ⇒ hard error
    pub required: bool,
    /// may a policy lock this field?
    pub lockable: bool,
    /// exposed as a CLI flag?
    pub cli: bool,
    /// accepted from TOML?
    pub config: bool,
    /// value is a secret → fd/stdin entry only (skipped by resolve())
    pub secret: bool,
    /// redact in audit + dry-run preview
    pub audit_redact: bool,
    /// single-source human description → CLI --help / dry-run preview / audit
    pub doc: &'static str,
}

const ED: Algo = Algo::Ed25519;
const CV: Algo = Algo::Cv25519;
const Y2: Expiry = Expiry::Days(730);
const NEVER: Expiry = Expiry::Never;

static DEFAULT_ALGO: &[(Role, AlgoSpec)] = &[
    (
        Role::Certify,
        AlgoSpec {
            algo: ED,
            expiry: NEVER,
        },
    ),
    (
        Role::Sign,
        AlgoSpec {
            algo: ED,
            expiry: Y2,
        },
    ),
    (
        Role::Auth,
        AlgoSpec {
            algo: ED,
            expiry: Y2,
        },
    ),
    (
        Role::Encrypt,
        AlgoSpec {
            algo: CV,
            expiry: Y2,
        },
    ),
];

/// Every decision, declared once (spec §3 table). The consistency tests below enforce the
/// per-surface rules.
// Each row's final arg is `doc`: the single-source human description (→ CLI --help, dry-run
// preview, audit). The consistency test asserts every doc is non-empty.
pub static DECISIONS: &[Decision] = &[
    Decision {
        id: "compliance-profile",
        value_type: ValueType::Compliance,
        default_value: DefaultValue::DecisionEnum(DecisionEnumValues::Compliance(
            ComplianceProfile::DrDuh,
        )),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Compliance regime to enforce: drduh (standalone) or fips/cnsa/bsi. Gates algorithms, key sizes, and expiry.",
    },
    Decision {
        id: "cnsa-use-case",
        value_type: ValueType::CnsaUse,
        default_value: DefaultValue::DecisionEnum(DecisionEnumValues::CnsaUse(
            CnsaUseCase::Nss2030,
        )),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "CNSA 2.0 transitional use case selecting the expiry ceiling: nss-2030 (default) or nss-2033.",
    },
    Decision {
        id: "algo",
        value_type: ValueType::AlgoProfile,
        default_value: DefaultValue::Algo(DEFAULT_ALGO),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Per-role key algorithm + expiry profile for certify/sign/auth/encrypt.",
    },
    Decision {
        id: "subkey-expiry",
        value_type: ValueType::Expiry,
        default_value: DefaultValue::Expiry(Y2),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Default expiry for the sign/auth/encrypt subkeys; the certify key never expires.",
    },
    Decision {
        id: "pin-min-length",
        value_type: ValueType::Uint,
        default_value: DefaultValue::Uint(6),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Minimum YubiKey PIN length (card minimum 6; FIPS requires >= 8).",
    },
    Decision {
        id: "pin-source",
        value_type: ValueType::PinSource,
        default_value: DefaultValue::DecisionEnum(DecisionEnumValues::PinSource(
            PinSource::Generated,
        )),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Whether PINs are tool-generated or operator-chosen (entered via fd/stdin).",
    },
    Decision {
        id: "admin-pin-scope",
        value_type: ValueType::AdminPin,
        default_value: DefaultValue::DecisionEnum(DecisionEnumValues::AdminPin(
            AdminPinScope::PerCard,
        )),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Admin PIN scope: per-card (default) or fleet-shared (a documented single point of compromise).",
    },
    Decision {
        id: "reset-code",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(true),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Generate a Reset Code so a user can reset their own User PIN without the Admin PIN.",
    },
    Decision {
        id: "factory-reset-required",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(true),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Require a factory reset of a fresh or dirty card before provisioning.",
    },
    Decision {
        id: "audit-required",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(true),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Require a signed, hash-chained audit record for every provisioning; refuse to proceed without it.",
    },
    Decision {
        id: "allow-bootstrap",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(true),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Allow a bootstrap User PIN to be set for first use, to be changed by the user on first login.",
    },
    Decision {
        id: "device-allowlist",
        value_type: ValueType::DeviceList,
        default_value: DefaultValue::DeviceList(&[]),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "by-id allowlist of internal (rule-2) disks usable as backup/export targets; never re-includes a rule-1 (in-use) disk.",
    },
    Decision {
        id: "on-failure",
        value_type: ValueType::Failure,
        default_value: DefaultValue::DecisionEnum(DecisionEnumValues::Failure(
            FailureBehavior::AbortLeaveClean,
        )),
        required: false,
        lockable: true,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Behavior when a provisioning step fails: abort-leave-clean, or factory-reset-and-abort.",
    },
    Decision {
        id: "target-card-serial",
        value_type: ValueType::Str,
        default_value: DefaultValue::None,
        required: false,
        lockable: false,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "If set, the provisioned card's serial must match this value or the run aborts.",
    },
    Decision {
        id: "asserted-date",
        value_type: ValueType::Str,
        default_value: DefaultValue::None,
        required: false,
        lockable: false,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "Operator-asserted current date (RFC-3339 UTC) for non-interactive runs; the clock upper bound, must be >= the baked floor.",
    },
    Decision {
        id: "real-name",
        value_type: ValueType::Str,
        default_value: DefaultValue::None,
        required: true,
        lockable: false,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "OpenPGP UID real name for this identity. (Required.)",
    },
    Decision {
        id: "email",
        value_type: ValueType::Str,
        default_value: DefaultValue::None,
        required: true,
        lockable: false,
        cli: true,
        config: true,
        secret: false,
        audit_redact: false,
        doc: "OpenPGP UID email for this identity (RFC-5322 subset). (Required.)",
    },
    // secrets: fd/stdin only — cli=false, config=false, audit_redact=true; resolve() skips them
    Decision {
        id: "user-pin",
        value_type: ValueType::Pin,
        default_value: DefaultValue::None,
        required: false,
        lockable: false,
        cli: false,
        config: false,
        secret: true,
        audit_redact: true,
        doc: "YubiKey User PIN; entered via fd/stdin only, never argv/config.",
    },
    Decision {
        id: "admin-pin",
        value_type: ValueType::Pin,
        default_value: DefaultValue::None,
        required: false,
        lockable: false,
        cli: false,
        config: false,
        secret: true,
        audit_redact: true,
        doc: "YubiKey Admin PIN; entered via fd/stdin only, never argv/config.",
    },
    Decision {
        id: "certify-passphrase",
        value_type: ValueType::Pin,
        default_value: DefaultValue::None,
        required: false,
        lockable: false,
        cli: false,
        config: false,
        secret: true,
        audit_redact: true,
        doc: "Passphrase protecting the offline certify key; entered via fd/stdin only.",
    },
    Decision {
        id: "confirm-format",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(false),
        required: false,
        lockable: false,
        cli: true,
        config: false,
        secret: false,
        audit_redact: false,
        doc: "Explicit acknowledgement to format/erase a selected target drive. CLI-only; distinct from confirm-keytocard and force.",
    },
    Decision {
        id: "confirm-keytocard",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(false),
        required: false,
        lockable: false,
        cli: true,
        config: false,
        secret: false,
        audit_redact: false,
        doc: "Explicit acknowledgement of the irreversible keytocard (moving subkeys onto the card). CLI-only; distinct from confirm-format and force.",
    },
    Decision {
        id: "force",
        value_type: ValueType::Bool,
        default_value: DefaultValue::Bool(false),
        required: false,
        lockable: false,
        cli: true,
        config: false,
        secret: false,
        audit_redact: false,
        doc: "Override the single-shot idempotency guard (re-format a drive that already holds a Keywright backup, or re-provision an identity already backed up here). Does NOT bypass device safety or any other gate. CLI-only.",
    },
];

pub fn decision_by_id(id: &str) -> Option<&'static Decision> {
    DECISIONS.iter().find(|d| d.id == id)
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn surface_invariant_secret_implies_no_cli_no_config_and_redacted() {
        // WHY (§3): a secret decision must never become a --flag or a TOML key,
        // and must be redacted — the structural guard that a PIN can't land in
        // argv or a plaintext config. Enforced for the whole slice.
        for decision in DECISIONS {
            if decision.secret {
                assert!(
                    !decision.cli,
                    "secret decision {} must not be a CLI flag",
                    decision.id
                );
                assert!(
                    !decision.config,
                    "secret decision {} must not be a TOML key",
                    decision.id
                );
                assert!(
                    decision.audit_redact,
                    "secret decision {} must be audit_redact",
                    decision.id
                );
            }
        }
    }

    #[test]
    fn ids_are_unique_and_kebab() {
        // WHY: ids derive CLI flags / TOML keys / audit fields — collisions or
        // non-kebab ids would break the derivation surface.
        let mut seen = std::collections::BTreeSet::new();
        for decision in DECISIONS {
            assert!(
                seen.insert(decision.id),
                "duplicate decision id {}",
                decision.id
            );
            assert!(
                decision
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "non-kebab id {}",
                decision.id
            );
        }
    }

    #[test]
    fn every_decision_has_a_nonempty_doc() {
        // WHY (§3): `doc` is the single source of the CLI --help / dry-run preview /
        // audit description; an empty doc would ship a flag/field with no text.
        for decision in DECISIONS {
            assert!(
                !decision.doc.trim().is_empty(),
                "decision {} has no doc string",
                decision.id
            );
        }
    }

    #[test]
    fn destructive_tokens_are_cli_only_and_independent() {
        // WHY (§4/§10): confirm-format / confirm-keytocard / force are distinct,
        // CLI-only acknowledgements — never config-settable, never aliased, each
        // defaulting to false so satisfying one never satisfies another.
        let ids = ["confirm-format", "confirm-keytocard", "force"];
        for id in ids {
            let decision = decision_by_id(id).unwrap();
            assert!(decision.cli && !decision.config, "{id} must be CLI-only");
            assert!(
                matches!(decision.default_value, DefaultValue::Bool(false)),
                "{id} must default to false"
            );
        }
        let set: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 3, "the three tokens must be distinct ids");
    }

    #[test]
    fn only_real_name_and_email_are_required() {
        // WHY (§3): the precedence 'non-interactive hard error' must fire only for
        // genuinely required decisions — a UID's name + email — not for optional
        // fields (target-card-serial, asserted-date) or out-of-band secrets.
        for decision in DECISIONS {
            let expect = decision.id == "real-name" || decision.id == "email";
            assert_eq!(
                decision.required, expect,
                "required flag wrong for {}",
                decision.id
            );
        }
    }
}
