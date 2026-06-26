# Keywright Plan 2a — Resolution & Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the decision-resolution spine + storage primitives of `keywright-core` — the typed error model, the data-driven decision registry, config/policy resolution into a provenance-tagged `ResolvedSet`, and the typed command-runner + structured storage parsers — all unit-tested via the pure package build, no secret key material, no card, no device classification, no dry-run.

**Architecture:** Adds six modules to the existing `keywright-core` library crate (Plan 1 left it a stub exposing `version()`). The registry declares every operator decision once as a `static &[Decision]`; `resolve()` walks `policy-locked > CLI > config > default > (interactive | hard error for required)` to produce a `ResolvedSet` of `{value, provenance}`. The runner is the single typed chokepoint for read-only storage subprocesses, with secrets type-fenced out of argv. The parsers turn `lsblk`/`findmnt`/`/proc/swaps`/`/proc/self/mountinfo` output into the mount/swap topology types Plan 2b's `device` module consumes.

**Tech Stack:** Rust (edition 2024) · `thiserror` · `serde` + `toml` + `serde_json` · `unicode-normalization` · `zeroize` · `rustPlatform.buildRustPackage` (committed `Cargo.lock`) · treefmt rustfmt.

## Global Constraints

- **This is Plan 2a of the L0–L3 layer** (spec `docs/superpowers/specs/2026-06-22-keywright-core-decision-layer-design.md`). 2a delivers `error`, `registry`, `runner`, `parse`, `config`, `policy`. **Out of 2a (Plan 2b):** `compliance`, `secret`, `device`, `plan`/`--dry-run`, the clock step, `PlanResult` assembly, and the storage **source-resolution** parsers (`zpool`/`mdadm`/`bcache`) that the `device` recursion consumes.
- **`resolve()` in 2a returns `ResolvedSet`** (decisions resolved by precedence with provenance). The spec's `PlanResult { resolved, validated_now, compliance_data_version }` is assembled in **Plan 2b** (it needs the §7 clock step + the §5 compliance-data edition). 2a does **not** import `time` and does **not** produce `validated_now`/`compliance_data_version`.
- **TEST/VERIFY GATE — pure package build.** `rustPlatform.buildRustPackage` defaults `doCheck = true`; its `checkPhase` runs `cargo test` hermetically in the sandbox (`--offline`, only `/nix/store` visible). The verification command for every task is therefore **`nix build .#keywright -L`** — a failing test surfaces as a `checkPhase` failure in the `-L` log. Do **not** run impure `cargo` (`nix run nixpkgs#cargo` has no C toolchain → `linker cc not found`; host paths like `/run/current-system` do not exist in the sandbox or CI).
  - **`git add` before every `nix build`.** The flake source is the **git-tracked** tree; a newly created `.rs`/fixture file is invisible to `nix build` until staged (you'll see `warning: Git tree … is dirty` and a stale build otherwise). Stage new files (and `Cargo.toml`/`Cargo.lock`) before building.
  - **Lockfile regen (only direct-cargo step):** after editing a crate `Cargo.toml`, run **`nix develop .#keywright -c cargo generate-lockfile`** (falls back to the package's build environment, which has cargo + the toolchain) and commit the updated `Cargo.lock`. This is lockfile metadata maintenance, not test execution.
- **No `process::exit` anywhere; every fallible op returns `Result<_, Error>`** (foundation §2.1). **`panic = "unwind"` is mandatory** (spec §9): RAII `Drop` guards must run; `panic = "abort"` would silently void every secret-zeroize/secret-file-unlink guarantee. Enforced by `[profile.*] panic = "unwind"` in the workspace `Cargo.toml` **plus** a `#[cfg(panic = "abort")] compile_error!` guard in `lib.rs` (Task 1).
- **Edition 2024**; crate `keywright-core` stays `version = "0.0.1"`.
- **Dependencies are pinned by the committed `Cargo.lock`** (crates.io checksums); `buildRustPackage { cargoLock.lockFile }` auto-vendors them. **No `outputHashes`** (all 2a deps are registry crates).
- **Secrets never in argv/env/log:** the `runner` accepts secret payloads only via a distinct `Secret` type its argv builder cannot take (compile-time barrier); `SecretString` + `ResolvedValue::Pin` redact in `Debug`/`Display` (`[REDACTED]`) and zeroize on drop; `SecretString::expose()` is the single audited read path and must never be logged.
- **Per-surface registry invariant:** `secret=true ⇒ cli=false ∧ config=false ∧ audit_redact=true` (a registry-consistency unit test enforces it for the whole slice).
- **Tests document *why*:** every test/assertion carries a comment tying it to the requirement it guards (`tests-document-why`). Tests need **no hardware, no card, no real block devices**, and **must pass in the `nix build` sandbox** (only `/nix/store` + `/bin/sh`; resolve any helper binary from a build-injected `/nix/store` path).
- **Formatting:** run `nix fmt` before each commit (treefmt rustfmt). **Commits are GPG-signed** with the maintainer's YubiKey (`commit.gpgsign=true`); a pinentry prompt is expected — never `--no-gpg-sign`.
- Work from `/home/djacu/dev/djacu/yubikey-loader` on the execution branch; the crate is `overlays/top-level/keywright/crates/keywright-core/`; the workspace root `Cargo.toml` is `overlays/top-level/keywright/Cargo.toml`; the build recipe is `overlays/top-level/keywright/package.nix`.

______________________________________________________________________

## File Structure

```
overlays/top-level/keywright/
  Cargo.toml                         # MODIFY (Task 1): add [profile.*] panic="unwind"
  Cargo.lock                         # regenerated via `nix develop … cargo generate-lockfile`
  package.nix                        # MODIFY (Task 6): nativeCheckInputs=[coreutils] + preCheck env for the runner spawn test
  crates/keywright-core/
    Cargo.toml                       # MODIFY: add deps (thiserror, serde, toml, serde_json,
                                     #         unicode-normalization, zeroize)
    src/
      lib.rs                         # MODIFY: panic guard; declare modules; re-export public API
      error.rs                       # NEW (Task 1): Error enum (thiserror)
      registry.rs                    # NEW (Task 2,5): Decision/ValueType/… + DECISIONS slice;
                                     #                 Provenance/Resolved/ResolvedSet + resolve()
      config.rs                      # NEW (Task 3): Config (TOML) + identity input
      policy.rs                      # NEW (Task 4): Policy (/nix/store load) + lockable fields
      runner.rs                      # NEW (Task 6): typed subprocess runner + Secret type
      parse.rs                       # NEW (Task 7): lsblk/findmnt/swaps/mountinfo parsers
    tests/fixtures/                  # NEW (Task 7): captured probe outputs (json/text)
```

Module dependency order (drives task order): `error` → `registry`(types) → `config`/`policy` → `registry`(resolve) → `runner` → `parse`.

______________________________________________________________________

### Task 1: `error` module + panic-discipline guard

**Files:**

- Modify: `overlays/top-level/keywright/Cargo.toml` (workspace — add `[profile.*] panic="unwind"`)
- Modify: `crates/keywright-core/Cargo.toml` (add `thiserror`)
- Create: `crates/keywright-core/src/error.rs`
- Modify: `crates/keywright-core/src/lib.rs`

**Interfaces:**

- Produces: `pub enum Error` (variants grow per module) + `pub type Result<T> = core::result::Result<T, Error>;`. **Variant rule:** no variant embeds a secret value — carry a decision `id` + a non-secret reason string.

- [ ] **Step 1: Add the panic profiles + the compile-time guard**

Append to `overlays/top-level/keywright/Cargo.toml` (the **workspace root** — `[profile.*]` is ignored in non-root members):

```toml
# Spec §9: RAII Drop guards (secret zeroize, tmpfs unlink) MUST run on every
# unwind path. panic="abort" would skip them and silently void the secret
# guarantees, so it is forbidden in every profile.
[profile.dev]
panic = "unwind"

[profile.release]
panic = "unwind"

[profile.test]
panic = "unwind"
```

`crates/keywright-core/src/lib.rs` (replace the stub body, keep `version()`):

```rust
//! Keywright core engine (UI-agnostic). Plan 2a: resolution + primitives.

// Spec §9: a build with panic="abort" would skip the RAII Drop guards that
// zeroize secrets and unlink tmpfs state. Fail the build rather than ship that.
#[cfg(panic = "abort")]
compile_error!("keywright-core requires panic=unwind (see workspace Cargo.toml profiles, spec §9)");

pub mod error;

pub use error::{Error, Result};

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
```

(Add `pub mod registry; pub mod config; pub mod policy; pub mod runner; pub mod parse;` as each later task lands — declare only modules that exist so the crate compiles after every task.)

- [ ] **Step 2: Add `thiserror` and write `error.rs`**

In `crates/keywright-core/Cargo.toml`:

```toml
[dependencies]
thiserror = "2"
```

`crates/keywright-core/src/error.rs`:

```rust
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
    Identity(String),
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
        let e = Error::Resolve { id: "pin-min-length", reason: "len < 8".into() };
        let rendered = e.to_string();
        assert!(rendered.contains("pin-min-length"));
        assert!(rendered.contains("len < 8"));
    }
}
```

- [ ] **Step 3: Regenerate the lockfile, build + test (pure)**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright
nix develop .#keywright -c cargo generate-lockfile
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/Cargo.toml overlays/top-level/keywright/crates/keywright-core/src/error.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
```

Expected: `Cargo.lock` gains `thiserror`; the build's `checkPhase` runs and reports `test result: ok` including `resolve_error_carries_id_and_nonsecret_reason` and `version_is_nonempty`.

- [ ] **Step 4: Format and commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader && nix fmt
git add -A overlays/top-level/keywright
git commit -m "feat(core): typed Error model + panic=unwind guard (no process::exit; no secret in any variant)"
```

______________________________________________________________________

### Task 2: `registry` — decision types + the `DECISIONS` slice

**Files:**

- Create: `crates/keywright-core/src/registry.rs`
- Modify: `crates/keywright-core/src/lib.rs` (`pub mod registry;`)

**Interfaces:**

- Consumes: `Error` (Task 1).
- Produces: `ValueType`, `Algo`, `Expiry`, `Role`, `AlgoSpec`, `DefaultVal` (incl. `DeviceList(&'static [&'static str])`), `Decision` (with `required: bool` + a `doc: &'static str` single-source description), `pub static DECISIONS: &[Decision]`, `pub fn decision(id: &str) -> Option<&'static Decision>`. Tasks 3/5 consume these; `doc` feeds the later CLI `--help` / preview / audit.

> **Design note (refines spec §3 struct):** `Decision` gains `required: bool`. The spec's precedence terminal is "(interactive prompt | non-interactive **hard error**)" — but that hard error must fire only for decisions that genuinely must have a value. `required=true` for `real-name`/`email` (no key without a UID); everything else is `required=false` (has a default, is optional, or is a secret resolved out-of-band). `device-allowlist` carries an empty-list default (`[]`, matching the spec table), not `None`.

- [ ] **Step 1: Write `registry.rs` (types + slice)**

`crates/keywright-core/src/registry.rs`:

```rust
//! The decision registry — every operator decision declared once (§3).
//! CLI flags, TOML keys, audit fields all derive from this one slice.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType { Bool, Enum(&'static [&'static str]), Uint, Expiry, AlgoProfile, DeviceList, Pin, Str }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo { Ed25519, Ed448, Cv25519, Rsa(u16), NistP(u16), Brainpool(u16), Secp256k1 } // Ed448/secp256k1: representable so Plan 2b's compliance can forbid them under fips (§5)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry { Never, Days(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role { Certify, Sign, Auth, Encrypt }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgoSpec { pub algo: Algo, pub expiry: Expiry }

#[derive(Debug, Clone, Copy)]
pub enum DefaultVal {
    None,
    Bool(bool),
    Enum(&'static str),
    Uint(u64),
    Expiry(Expiry),
    Str(&'static str),
    DeviceList(&'static [&'static str]),          // empty slice = "[]" default
    Algo(&'static [(Role, AlgoSpec)]),
}

#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub id: &'static str,   // canonical id → CLI flag (--kebab), TOML key, audit field
    pub value_type: ValueType,
    pub default: DefaultVal,
    pub required: bool,     // non-interactive + unsupplied + no default ⇒ hard error
    pub lockable: bool,     // may a policy lock this field?
    pub cli: bool,          // exposed as a CLI flag?
    pub config: bool,       // accepted from TOML?
    pub secret: bool,       // value is a secret → fd/stdin entry only (skipped by resolve())
    pub audit_redact: bool, // redact in audit + dry-run preview
    pub doc: &'static str,  // single-source human description → CLI --help / dry-run preview / audit
}

const ED: Algo = Algo::Ed25519;
const CV: Algo = Algo::Cv25519;
const Y2: Expiry = Expiry::Days(730);
const NEVER: Expiry = Expiry::Never;

static DEFAULT_ALGO: &[(Role, AlgoSpec)] = &[
    (Role::Certify, AlgoSpec { algo: ED, expiry: NEVER }),
    (Role::Sign,    AlgoSpec { algo: ED, expiry: Y2 }),
    (Role::Auth,    AlgoSpec { algo: ED, expiry: Y2 }),
    (Role::Encrypt, AlgoSpec { algo: CV, expiry: Y2 }),
];

/// Every decision, declared once (spec §3 table). The consistency tests below
/// enforce the per-surface rules.
// Each row's final arg is `doc`: the single-source human description (→ CLI --help,
// dry-run preview, audit). The consistency test asserts every doc is non-empty.
pub static DECISIONS: &[Decision] = &[
    d("compliance-profile", ValueType::Enum(&["drduh","fips","cnsa","bsi"]), DefaultVal::Enum("drduh"), false, true, true, true, false, false,
      "Compliance regime to enforce: drduh (standalone) or fips/cnsa/bsi. Gates algorithms, key sizes, and expiry."),
    d("cnsa-use-case",      ValueType::Enum(&["nss-2030","nss-2033"]),        DefaultVal::Enum("nss-2030"), false, true, true, true, false, false,
      "CNSA 2.0 transitional use case selecting the expiry ceiling: nss-2030 (default) or nss-2033."),
    d("algo",               ValueType::AlgoProfile, DefaultVal::Algo(DEFAULT_ALGO), false, true, true, true, false, false,
      "Per-role key algorithm + expiry profile for certify/sign/auth/encrypt."),
    d("subkey-expiry",      ValueType::Expiry, DefaultVal::Expiry(Y2), false, true, true, true, false, false,
      "Default expiry for the sign/auth/encrypt subkeys; the certify key never expires."),
    d("pin-min-length",     ValueType::Uint,   DefaultVal::Uint(6),    false, true, true, true, false, false,
      "Minimum YubiKey PIN length (card minimum 6; FIPS requires >= 8)."),
    d("pin-source",         ValueType::Enum(&["generated","chosen"]), DefaultVal::Enum("generated"), false, true, true, true, false, false,
      "Whether PINs are tool-generated or operator-chosen (entered via fd/stdin)."),
    d("admin-pin-scope",    ValueType::Enum(&["per-card","fleet-shared"]), DefaultVal::Enum("per-card"), false, true, true, true, false, false,
      "Admin PIN scope: per-card (default) or fleet-shared (a documented single point of compromise)."),
    d("reset-code",         ValueType::Bool, DefaultVal::Bool(true),  false, true, true, true, false, false,
      "Generate a Reset Code so a user can reset their own User PIN without the Admin PIN."),
    d("factory-reset-required", ValueType::Bool, DefaultVal::Bool(true), false, true, true, true, false, false,
      "Require a factory reset of a fresh or dirty card before provisioning."),
    d("audit-required",     ValueType::Bool, DefaultVal::Bool(true),  false, true, true, true, false, false,
      "Require a signed, hash-chained audit record for every provisioning; refuse to proceed without it."),
    d("allow-bootstrap",    ValueType::Bool, DefaultVal::Bool(true),  false, true, true, true, false, false,
      "Allow a bootstrap User PIN to be set for first use, to be changed by the user on first login."),
    d("device-allowlist",   ValueType::DeviceList, DefaultVal::DeviceList(&[]), false, true, true, true, false, false,
      "by-id allowlist of internal (rule-2) disks usable as backup/export targets; never re-includes a rule-1 (in-use) disk."),
    d("on-failure",         ValueType::Enum(&["abort-leave-clean","factory-reset-and-abort"]), DefaultVal::Enum("abort-leave-clean"), false, true, true, true, false, false,
      "Behavior when a provisioning step fails: abort-leave-clean, or factory-reset-and-abort."),
    d("target-card-serial", ValueType::Str, DefaultVal::None, false, false, true, true, false, false,
      "If set, the provisioned card's serial must match this value or the run aborts."),
    d("asserted-date",      ValueType::Str, DefaultVal::None, false, false, true, true, false, false,
      "Operator-asserted current date (RFC-3339 UTC) for non-interactive runs; the clock upper bound, must be >= the baked floor."),
    d("real-name",          ValueType::Str, DefaultVal::None, true,  false, true, true, false, false,
      "OpenPGP UID real name for this identity. (Required.)"),
    d("email",              ValueType::Str, DefaultVal::None, true,  false, true, true, false, false,
      "OpenPGP UID email for this identity (RFC-5322 subset). (Required.)"),
    // secrets: fd/stdin only — cli=false, config=false, audit_redact=true; resolve() skips them
    d("user-pin",           ValueType::Pin, DefaultVal::None, false, false, false, false, true, true,
      "YubiKey User PIN; entered via fd/stdin only, never argv/config."),
    d("admin-pin",          ValueType::Pin, DefaultVal::None, false, false, false, false, true, true,
      "YubiKey Admin PIN; entered via fd/stdin only, never argv/config."),
    d("certify-passphrase", ValueType::Pin, DefaultVal::None, false, false, false, false, true, true,
      "Passphrase protecting the offline certify key; entered via fd/stdin only."),
    // destructive tokens: CLI-only — config=false
    d("confirm-format",     ValueType::Bool, DefaultVal::Bool(false), false, false, true, false, false, false,
      "Explicit acknowledgement to format/erase a selected target drive. CLI-only; distinct from confirm-keytocard and force."),
    d("confirm-keytocard",  ValueType::Bool, DefaultVal::Bool(false), false, false, true, false, false, false,
      "Explicit acknowledgement of the irreversible keytocard (moving subkeys onto the card). CLI-only; distinct from confirm-format and force."),
    d("force",              ValueType::Bool, DefaultVal::Bool(false), false, false, true, false, false, false,
      "Override the single-shot idempotency guard (re-format a drive that already holds a Keywright backup, or re-provision an identity already backed up here). Does NOT bypass device safety or any other gate. CLI-only."),
];

#[allow(clippy::too_many_arguments)]
const fn d(id: &'static str, value_type: ValueType, default: DefaultVal, required: bool,
           lockable: bool, cli: bool, config: bool, secret: bool, audit_redact: bool,
           doc: &'static str) -> Decision {
    Decision { id, value_type, default, required, lockable, cli, config, secret, audit_redact, doc }
}

pub fn decision(id: &str) -> Option<&'static Decision> {
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
        for d in DECISIONS {
            if d.secret {
                assert!(!d.cli,    "secret decision {} must not be a CLI flag", d.id);
                assert!(!d.config, "secret decision {} must not be a TOML key", d.id);
                assert!(d.audit_redact, "secret decision {} must be audit_redact", d.id);
            }
        }
    }

    #[test]
    fn ids_are_unique_and_kebab() {
        // WHY: ids derive CLI flags / TOML keys / audit fields — collisions or
        // non-kebab ids would break the derivation surface.
        let mut seen = std::collections::BTreeSet::new();
        for d in DECISIONS {
            assert!(seen.insert(d.id), "duplicate decision id {}", d.id);
            assert!(d.id.chars().all(|c| c.is_ascii_lowercase() || c == '-'), "non-kebab id {}", d.id);
        }
    }

    #[test]
    fn every_decision_has_a_nonempty_doc() {
        // WHY (§3): `doc` is the single source of the CLI --help / dry-run preview /
        // audit description; an empty doc would ship a flag/field with no text.
        for d in DECISIONS {
            assert!(!d.doc.trim().is_empty(), "decision {} has no doc string", d.id);
        }
    }

    #[test]
    fn destructive_tokens_are_cli_only_and_independent() {
        // WHY (§4/§10): confirm-format / confirm-keytocard / force are distinct,
        // CLI-only acknowledgements — never config-settable, never aliased, each
        // defaulting to false so satisfying one never satisfies another.
        let ids = ["confirm-format", "confirm-keytocard", "force"];
        for id in ids {
            let d = decision(id).unwrap();
            assert!(d.cli && !d.config, "{id} must be CLI-only");
            assert!(matches!(d.default, DefaultVal::Bool(false)), "{id} must default to false");
        }
        let set: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 3, "the three tokens must be distinct ids");
    }

    #[test]
    fn only_real_name_and_email_are_required() {
        // WHY (§3): the precedence 'non-interactive hard error' must fire only for
        // genuinely required decisions — a UID's name + email — not for optional
        // fields (target-card-serial, asserted-date) or out-of-band secrets.
        for d in DECISIONS {
            let expect = d.id == "real-name" || d.id == "email";
            assert_eq!(d.required, expect, "required flag wrong for {}", d.id);
        }
    }
}
```

Add `pub mod registry;` to `lib.rs`.

- [ ] **Step 2: Build + test, then format and commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/registry.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): decision registry types + DECISIONS slice + surface/required invariants"
```

Expected: `checkPhase` runs 4 `registry_tests` + the Task-1 tests, all `ok`.

______________________________________________________________________

### Task 3: `config` — operator TOML + identity input

**Files:**

- Modify: `crates/keywright-core/Cargo.toml` (add `serde`, `toml`, `unicode-normalization`)
- Create: `crates/keywright-core/src/config.rs`
- Modify: `crates/keywright-core/src/lib.rs` (`pub mod config;`)

**Interfaces:**

- Consumes: `Error`, `Result` (Task 1).

- Produces: `pub struct Config { pub values: BTreeMap<String, toml::Value>, pub identities: Vec<Identity> }`, `pub struct Identity { pub real_name: String, pub email: String }`, `pub fn parse_config(toml_text: &str) -> Result<Config>`, `pub fn parse_identity(real_name: &str, email: &str) -> Result<Identity>`, `pub fn is_interactive(batch: bool, non_interactive: bool, stdin_is_tty: bool) -> bool`. Task 5 (`resolve`) reads `Config::values`.

- [ ] **Step 1: Add deps; write identity parsing**

Add to `crates/keywright-core/Cargo.toml`:

```toml
serde = { version = "1", features = ["derive"] }
toml = "0.8"
unicode-normalization = "0.1"
```

`crates/keywright-core/src/config.rs`:

```rust
//! Operator TOML config + identity input (§4). Resolution-against-config is in
//! `registry::resolve` (Task 5); this module only parses + validates inputs.

use crate::{Error, Result};
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity { pub real_name: String, pub email: String }

#[derive(Debug, Default)]
pub struct Config {
    /// Decision id → raw TOML value (validated against the registry in Task 5).
    pub values: BTreeMap<String, toml::Value>,
    /// `[[identity]]` batch, file order = audit order.
    pub identities: Vec<Identity>,
}

/// RFC-5322-subset email check: one `@`, non-empty local + dotted domain,
/// no spaces/control chars. WHY (§4): reject malformed UIDs at input.
fn valid_email(s: &str) -> bool {
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 { return false; }
    let (local, domain) = (parts[0], parts[1]);
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

pub fn parse_identity(real_name: &str, email: &str) -> Result<Identity> {
    // WHY (§4): NFC-normalize at input, before any audit serialization.
    let real_name: String = real_name.trim().nfc().collect();
    let email: String = email.trim().nfc().collect();
    if real_name.is_empty() {
        return Err(Error::Identity("real name is empty".into()));
    }
    if !valid_email(&email) {
        return Err(Error::Identity(format!("invalid email: {email}")));
    }
    Ok(Identity { real_name, email })
}

pub fn parse_config(toml_text: &str) -> Result<Config> {
    let root: toml::Value = toml_text.parse::<toml::Value>()
        .map_err(|e| Error::Config(e.to_string()))?;
    let table = root.as_table().ok_or_else(|| Error::Config("config root is not a table".into()))?;

    let mut cfg = Config::default();
    for (k, v) in table {
        if k == "identity" {
            let arr = v.as_array().ok_or_else(|| Error::Config("`identity` must be an array of tables".into()))?;
            for item in arr {
                let t = item.as_table().ok_or_else(|| Error::Config("each identity must be a table".into()))?;
                let rn = t.get("real_name").and_then(|x| x.as_str()).unwrap_or("");
                let em = t.get("email").and_then(|x| x.as_str()).unwrap_or("");
                cfg.identities.push(parse_identity(rn, em)?);
            }
        } else {
            cfg.values.insert(k.clone(), v.clone());
        }
    }

    // WHY (§4): duplicate emails in a batch are rejected (one cert per identity).
    let mut seen = std::collections::BTreeSet::new();
    for id in &cfg.identities {
        if !seen.insert(id.email.clone()) {
            return Err(Error::Identity(format!("duplicate email in batch: {}", id.email)));
        }
    }
    Ok(cfg)
}

/// Non-interactive iff `--batch`/`--non-interactive` OR stdin is not a TTY (§4).
pub fn is_interactive(batch: bool, non_interactive: bool, stdin_is_tty: bool) -> bool {
    !(batch || non_interactive) && stdin_is_tty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_nfc_normalizes_at_input() {
        // WHY (§4/§8): NFC at input so the audit/UID is canonical. "José" given as
        // NFD (e + U+0301) must compose to the single codepoint U+00E9.
        let decomposed = "Jose\u{0301}";
        let id = parse_identity(decomposed, "jose@example.com").unwrap();
        assert_eq!(id.real_name, "Jos\u{00e9}");
    }

    #[test]
    fn identity_rejects_bad_email() {
        // WHY (§4): RFC-5322-subset validation rejects malformed UIDs at input.
        assert!(parse_identity("A", "no-at-sign").is_err());
        assert!(parse_identity("A", "a@nodot").is_err());
        assert!(parse_identity("A", "a b@x.com").is_err());
        assert!(parse_identity("", "a@x.com").is_err());
        assert!(parse_identity("A", "a@x.com").is_ok());
    }

    #[test]
    fn batch_rejects_duplicate_emails_and_preserves_order() {
        // WHY (§4): file order = audit order; duplicate emails rejected.
        let ok = parse_config("[[identity]]\nreal_name='A'\nemail='a@x.com'\n[[identity]]\nreal_name='B'\nemail='b@x.com'\n").unwrap();
        assert_eq!(ok.identities.iter().map(|i| i.email.as_str()).collect::<Vec<_>>(), ["a@x.com","b@x.com"]);
        let dup = parse_config("[[identity]]\nreal_name='A'\nemail='a@x.com'\n[[identity]]\nreal_name='B'\nemail='a@x.com'\n");
        assert!(dup.is_err());
    }

    #[test]
    fn interactive_determination() {
        // WHY (§4): non-interactive iff --batch/--non-interactive or stdin not a TTY.
        assert!(is_interactive(false, false, true));
        assert!(!is_interactive(true, false, true));
        assert!(!is_interactive(false, true, true));
        assert!(!is_interactive(false, false, false));
    }
}
```

Add `pub mod config;` to `lib.rs`.

- [ ] **Step 2: Regenerate lockfile, build + test, commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright && nix develop .#keywright -c cargo generate-lockfile
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/Cargo.toml overlays/top-level/keywright/crates/keywright-core/src/config.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): config TOML parse + identity input (NFC, RFC-5322 subset, batch)"
```

Expected: `checkPhase` runs 4 config tests, all `ok`.

______________________________________________________________________

### Task 4: `policy` — `/nix/store` canonicalized load

**Files:**

- Create: `crates/keywright-core/src/policy.rs`
- Modify: `crates/keywright-core/src/lib.rs` (`pub mod policy;`)

**Interfaces:**

- Consumes: `Error`, `Result` (Task 1); `decision()` (Task 2).

- Produces: `pub struct Policy { locked: BTreeMap<String, toml::Value> }` with `#[derive(Default)]`, `pub fn load_policy(path: &Path) -> Result<Policy>`, `pub fn load_policy_under(path: &Path, store_root: &Path) -> Result<Policy>` (testable seam), `Policy::locked(&self, id: &str) -> Option<&toml::Value>`, `Policy::is_locked(&self, id: &str) -> bool`. Task 5 reads locked values at the top of the precedence chain.

- [ ] **Step 1: Write `policy.rs` with the canonicalization guard + tests**

`crates/keywright-core/src/policy.rs`:

```rust
//! Policy file load (§4/§9). Policy is baked read-only into /nix/store at ISO
//! build time; we refuse any path that does not canonicalize to under the store.
//! WHY (§9): policy authenticity == store integrity — loading from a writable
//! path (or a symlink that escapes the store) collapses the locked-precedence model.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default)]
pub struct Policy {
    locked: BTreeMap<String, toml::Value>,
}

impl Policy {
    pub fn locked(&self, id: &str) -> Option<&toml::Value> { self.locked.get(id) }
    pub fn is_locked(&self, id: &str) -> bool { self.locked.contains_key(id) }
}

/// Production entry: pin to the real store.
pub fn load_policy(path: &Path) -> Result<Policy> {
    load_policy_under(path, Path::new("/nix/store"))
}

/// Canonicalize `path` (resolving EVERY symlink) and refuse it unless the
/// canonical path is under the canonical `store_root`. A symlink that lives
/// under the store but points outside, and any `..`-traversal, are resolved by
/// canonicalize() and then rejected by the component-wise prefix check.
pub fn load_policy_under(path: &Path, store_root: &Path) -> Result<Policy> {
    let canon = path.canonicalize()
        .map_err(|e| Error::Policy(format!("cannot canonicalize policy path {}: {e}", path.display())))?;
    let canon_root = store_root.canonicalize()
        .map_err(|e| Error::Policy(format!("cannot canonicalize store root: {e}")))?;
    if !canon.starts_with(&canon_root) {
        return Err(Error::Policy(format!("policy path {} is not under {}", canon.display(), canon_root.display())));
    }
    let text = std::fs::read_to_string(&canon)?;
    parse_policy(&text)
}

fn parse_policy(text: &str) -> Result<Policy> {
    let root: toml::Value = text.parse().map_err(|e: toml::de::Error| Error::Policy(e.to_string()))?;
    let table = root.as_table().ok_or_else(|| Error::Policy("policy root is not a table".into()))?;
    let mut p = Policy::default();
    for (k, v) in table {
        // WHY (§9): only lockable decisions may be locked by policy.
        match crate::registry::decision(k) {
            Some(d) if d.lockable => { p.locked.insert(k.clone(), v.clone()); }
            Some(_) => return Err(Error::Policy(format!("decision {k} is not lockable"))),
            None => return Err(Error::Policy(format!("unknown decision in policy: {k}"))),
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("kwtest-{tag}-{}", std::process::id()))
    }

    #[test]
    fn loads_policy_under_store_root() {
        // WHY (§9): a file under the canonical store root loads; lockable only.
        let dir = tmp("policy-ok");
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("policy.toml");
        fs::write(&f, "compliance-profile = 'fips'\n").unwrap();
        let p = load_policy_under(&f, &dir).unwrap();
        assert!(p.is_locked("compliance-profile"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_symlink_escaping_store_root() {
        // WHY (§4/§9/§10): a symlink that LIVES under the store but POINTS outside
        // is the primary escape vector; canonicalize() resolves the link target,
        // and the prefix check rejects it.
        let base = tmp("policy-symesc");
        let store = base.join("store");
        fs::create_dir_all(&store).unwrap();
        let outside = base.join("real-policy.toml");
        fs::write(&outside, "compliance-profile = 'fips'\n").unwrap();
        let link = store.join("policy.toml");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(load_policy_under(&link, &store).is_err(), "symlink escaping store must be rejected");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rejects_dotdot_traversal_path() {
        // WHY (§10): a ../ path resolving outside the store is caught by canonicalize.
        let base = tmp("policy-dotdot");
        let store = base.join("store");
        fs::create_dir_all(&store).unwrap();
        let outside = base.join("policy.toml");
        fs::write(&outside, "compliance-profile = 'fips'\n").unwrap();
        let traversal = store.join("../policy.toml");
        assert!(load_policy_under(&traversal, &store).is_err(), "../ traversal outside store must be rejected");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rejects_non_lockable_and_unknown() {
        // WHY (§9): non-lockable (target-card-serial) and unknown ids are refused.
        let dir = tmp("policy-bad");
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.toml");
        fs::write(&f, "target-card-serial = 'x'\n").unwrap();
        assert!(load_policy_under(&f, &dir).is_err());
        fs::write(&f, "no-such-decision = 1\n").unwrap();
        assert!(load_policy_under(&f, &dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
```

Add `pub mod policy;` to `lib.rs`.

- [ ] **Step 2: Build + test, commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/policy.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): policy load pinned + canonicalized under /nix/store (symlink/.. escape rejected); lockable-only"
```

Expected: `checkPhase` runs 4 policy tests (incl. symlink-escape + `..`-traversal), all `ok`.

______________________________________________________________________

### Task 5: `registry::resolve` — precedence + provenance → `ResolvedSet`

**Files:**

- Modify: `crates/keywright-core/Cargo.toml` (add `zeroize`)
- Modify: `crates/keywright-core/src/registry.rs` (append the resolution half + one test mod)

**Interfaces:**

- Consumes: `DECISIONS`/`decision()`/`DefaultVal`/`Decision`/`Algo`/`Expiry`/`Role`/`AlgoSpec` (Task 2); `Config` (Task 3); `Policy` (Task 4); `Error` (Task 1).

- Produces: `Provenance` (6 variants incl. `SessionFile`), `SecretString`, `ResolvedValue`, `Resolved`, `ResolvedSet`, `CliArgs { values: BTreeMap<String,String>, algo: BTreeMap<Role, AlgoSpec> }`, `pub fn resolve(cli: &CliArgs, config: &Config, policy: &Policy, interactive: bool) -> Result<ResolvedSet>`. **Plan 2b** wraps the returned `ResolvedSet` into `PlanResult`.

- [ ] **Step 1: Add `zeroize`; append the resolution types**

Add to `crates/keywright-core/Cargo.toml`:

```toml
zeroize = { version = "1", features = ["derive"] }
```

Append to `registry.rs`:

```rust
use crate::config::Config;
use crate::policy::Policy;
use crate::{Error, Result};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// A secret string that zeroizes on drop and never prints its contents.
pub struct SecretString(String);
impl SecretString {
    pub fn new(s: String) -> Self { SecretString(s) }
    /// The ONLY way to read the secret. WHY (§3): callers must never log this.
    pub fn expose(&self) -> &str { &self.0 }
}
impl Drop for SecretString { fn drop(&mut self) { self.0.zeroize(); } }
impl std::fmt::Debug for SecretString { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("[REDACTED]") } }
impl std::fmt::Display for SecretString { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("[REDACTED]") } }

/// `SessionFile` is reserved for Plan 2b's SessionSecretFile cache (spec §7);
/// 2a never emits it, but the variant must exist so the seam is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance { PolicyLocked, Cli, Config, Default, Interactive, SessionFile }

#[derive(Debug)]
pub enum ResolvedValue {
    Bool(bool),
    Enum(&'static str),
    Uint(u64),
    Expiry(Expiry),
    AlgoProfile(BTreeMap<Role, AlgoSpec>),
    DeviceList(Vec<String>),
    Pin(SecretString),     // Debug delegates to SecretString → [REDACTED]
    Str(String),
}

#[derive(Debug)]
pub struct Resolved { pub value: ResolvedValue, pub provenance: Provenance }

#[derive(Debug, Default)]
pub struct ResolvedSet(BTreeMap<&'static str, Resolved>);
impl ResolvedSet {
    pub fn get(&self, id: &str) -> Option<&Resolved> { self.0.get(id) }
    pub fn iter(&self) -> impl Iterator<Item = (&&'static str, &Resolved)> { self.0.iter() }
}

/// CLI overrides. `values` holds scalar decision overrides (id → raw string,
/// only `cli=true` decisions). `algo` holds per-role `--algo-<role>` overrides
/// (spec §3), merged onto the resolved profile in resolve().
#[derive(Debug, Default)]
pub struct CliArgs {
    pub values: BTreeMap<String, String>,
    pub algo: BTreeMap<Role, AlgoSpec>,
}
```

- [ ] **Step 2: Append `resolve()` + helpers**

Append to `registry.rs`:

```rust
/// Resolve every decision by precedence: policy-locked > CLI > config > default
/// > (interactive prompt | non-interactive hard error, for `required` only).
/// Secrets are skipped (entered via fd/stdin, provenance SessionFile, Plan 3).
/// Returns a ResolvedSet; Plan 2b wraps it into PlanResult.
pub fn resolve(cli: &CliArgs, config: &Config, policy: &Policy, interactive: bool) -> Result<ResolvedSet> {
    let mut out = ResolvedSet::default();
    for d in DECISIONS {
        // Secrets never flow through the precedence chain in 2a.
        if d.secret { continue; }

        // AlgoProfile has its own per-role merge path.
        if matches!(d.value_type, ValueType::AlgoProfile) {
            out.0.insert(d.id, resolve_algo(d, cli, config, policy)?);
            continue;
        }

        // Policy-locked: the lock wins, but a CONFLICTING lower-precedence override
        // (CLI/config supplies a DIFFERENT value) is a named error (§3); a redundant
        // same-value override is accepted.
        if let Some(locked) = policy.locked(d.id) {
            let locked_val = coerce(d, RawVal::Toml(locked.clone()))?;
            if d.cli {
                if let Some(s) = cli.values.get(d.id) {
                    if !values_equal(&locked_val, &coerce(d, RawVal::Str(s.clone()))?) {
                        return Err(Error::Resolve { id: d.id, reason: "policy-locked; CLI value conflicts".into() });
                    }
                }
            }
            if d.config {
                if let Some(v) = config.values.get(d.id) {
                    if !values_equal(&locked_val, &coerce(d, RawVal::Toml(v.clone()))?) {
                        return Err(Error::Resolve { id: d.id, reason: "policy-locked; config value conflicts".into() });
                    }
                }
            }
            out.0.insert(d.id, Resolved { value: locked_val, provenance: Provenance::PolicyLocked });
            continue;
        }

        // Not locked: CLI > config > default > (required hard error | leave unresolved).
        let resolved = if d.cli && cli.values.contains_key(d.id) {
            Resolved { value: coerce(d, RawVal::Str(cli.values[d.id].clone()))?, provenance: Provenance::Cli }
        } else if d.config && config.values.contains_key(d.id) {
            Resolved { value: coerce(d, RawVal::Toml(config.values[d.id].clone()))?, provenance: Provenance::Config }
        } else {
            match default_value(d) {
                Some(v) => Resolved { value: v, provenance: Provenance::Default },
                // No default supplied:
                None if d.required && !interactive =>
                    return Err(Error::Resolve { id: d.id, reason: "required, not supplied (non-interactive)".into() }),
                None => continue, // optional, or interactive (prompt wired in Plan 3/4) → leave unresolved
            }
        };
        out.0.insert(d.id, resolved);
    }
    Ok(out)
}

/// AlgoProfile: policy-locked table wins wholesale; else start from config table
/// or the default profile, then overlay any per-role CLI overrides.
fn resolve_algo(d: &Decision, cli: &CliArgs, config: &Config, policy: &Policy) -> Result<Resolved> {
    let err = |reason: String| Error::Resolve { id: d.id, reason };
    if let Some(v) = policy.locked(d.id) {
        let parse = |raw: &RawVal| parse_algo_profile(raw).map_err(|e| Error::Resolve { id: d.id, reason: e });
        let locked = parse(&RawVal::Toml(v.clone()))?;
        // a CONFLICTING config [algo] table or per-role CLI override is a named error.
        if let Some(cv) = config.values.get(d.id) {
            if parse(&RawVal::Toml(cv.clone()))? != locked {
                return Err(Error::Resolve { id: d.id, reason: "policy-locked; config algo conflicts".into() });
            }
        }
        if !cli.algo.is_empty() {
            let mut merged = locked.clone();
            for (r, s) in &cli.algo { merged.insert(*r, *s); }
            if merged != locked {
                return Err(Error::Resolve { id: d.id, reason: "policy-locked; CLI algo conflicts".into() });
            }
        }
        return Ok(Resolved { value: ResolvedValue::AlgoProfile(locked), provenance: Provenance::PolicyLocked });
    }
    // base = config [algo] table, else default profile
    let (mut profile, base_prov) = if let Some(v) = config.values.get(d.id) {
        (parse_algo_profile(&RawVal::Toml(v.clone())).map_err(err)?, Provenance::Config)
    } else {
        let DefaultVal::Algo(rows) = d.default else { unreachable!("algo decision must default to Algo") };
        (rows.iter().copied().collect::<BTreeMap<Role, AlgoSpec>>(), Provenance::Default)
    };
    // overlay per-role CLI overrides
    let prov = if cli.algo.is_empty() { base_prov } else { Provenance::Cli };
    for (role, spec) in &cli.algo { profile.insert(*role, *spec); }
    Ok(Resolved { value: ResolvedValue::AlgoProfile(profile), provenance: prov })
}

enum RawVal { Str(String), Toml(toml::Value) }

/// Value equality for the policy-lock conflict check (non-secret variants only;
/// lockable fields are never `Pin`). A locked field whose lower-precedence value
/// differs is a named error in `resolve`.
fn values_equal(a: &ResolvedValue, b: &ResolvedValue) -> bool {
    use ResolvedValue::*;
    match (a, b) {
        (Bool(x), Bool(y)) => x == y,
        (Enum(x), Enum(y)) => x == y,
        (Uint(x), Uint(y)) => x == y,
        (Expiry(x), Expiry(y)) => x == y,
        (AlgoProfile(x), AlgoProfile(y)) => x == y,
        (DeviceList(x), DeviceList(y)) => x == y,
        (Str(x), Str(y)) => x == y,
        _ => false, // Pin (unreachable for lockable) or mismatched variants
    }
}

fn coerce(d: &Decision, raw: RawVal) -> Result<ResolvedValue> {
    let err = |reason: String| Error::Resolve { id: d.id, reason };
    match d.value_type {
        ValueType::Bool => Ok(ResolvedValue::Bool(as_bool(&raw).ok_or_else(|| err("expected bool".into()))?)),
        ValueType::Uint => {
            let n = as_uint(&raw).ok_or_else(|| err("expected unsigned int".into()))?;
            if d.id == "pin-min-length" && n < 6 { return Err(err("pin-min-length below card minimum 6".into())); }
            Ok(ResolvedValue::Uint(n))
        }
        ValueType::Enum(opts) => {
            let s = as_str(&raw).ok_or_else(|| err("expected string".into()))?;
            let m = opts.iter().copied().find(|o| *o == s).ok_or_else(|| err(format!("not one of {opts:?}")))?;
            Ok(ResolvedValue::Enum(m))
        }
        ValueType::Str => Ok(ResolvedValue::Str(as_str(&raw).ok_or_else(|| err("expected string".into()))?)),
        ValueType::Expiry => Ok(ResolvedValue::Expiry(parse_expiry(&as_str(&raw).ok_or_else(|| err("expected string".into()))?).ok_or_else(|| err("bad expiry".into()))?)),
        ValueType::DeviceList => Ok(ResolvedValue::DeviceList(as_str_list(&raw).ok_or_else(|| err("expected list of strings".into()))?)),
        ValueType::AlgoProfile => unreachable!("AlgoProfile handled by resolve_algo"),
        ValueType::Pin => unreachable!("Pin decisions are secret and skipped by resolve()"),
    }
}

fn default_value(d: &Decision) -> Option<ResolvedValue> {
    match d.default {
        DefaultVal::None => None,
        DefaultVal::Bool(b) => Some(ResolvedValue::Bool(b)),
        DefaultVal::Enum(s) => Some(ResolvedValue::Enum(s)),
        DefaultVal::Uint(n) => Some(ResolvedValue::Uint(n)),
        DefaultVal::Expiry(e) => Some(ResolvedValue::Expiry(e)),
        DefaultVal::Str(s) => Some(ResolvedValue::Str(s.to_string())),
        DefaultVal::DeviceList(xs) => Some(ResolvedValue::DeviceList(xs.iter().map(|s| s.to_string()).collect())),
        DefaultVal::Algo(rows) => Some(ResolvedValue::AlgoProfile(rows.iter().copied().collect())),
    }
}

// --- raw-value helpers (full bodies; small + total) ---
fn as_bool(r: &RawVal) -> Option<bool> { match r { RawVal::Str(s) => s.parse().ok(), RawVal::Toml(v) => v.as_bool() } }
fn as_uint(r: &RawVal) -> Option<u64> { match r { RawVal::Str(s) => s.parse().ok(), RawVal::Toml(v) => v.as_integer().and_then(|i| u64::try_from(i).ok()) } }
fn as_str(r: &RawVal) -> Option<String> { match r { RawVal::Str(s) => Some(s.clone()), RawVal::Toml(v) => v.as_str().map(String::from) } }
fn as_str_list(r: &RawVal) -> Option<Vec<String>> {
    match r {
        RawVal::Str(s) => Some(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        RawVal::Toml(v) => v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
    }
}
fn parse_expiry(s: &str) -> Option<Expiry> {
    if s == "never" { return Some(Expiry::Never); }
    if let Some(n) = s.strip_suffix('y') { return n.parse::<u32>().ok().map(|y| Expiry::Days(y * 365)); }
    if let Some(n) = s.strip_suffix('d') { return n.parse::<u32>().ok().map(Expiry::Days); }
    None
}
fn parse_algo_profile(r: &RawVal) -> std::result::Result<BTreeMap<Role, AlgoSpec>, String> {
    let RawVal::Toml(v) = r else { return Err("algo must be a TOML table, not a flat value".into()); };
    let t = v.as_table().ok_or("algo must be a [algo] table")?;
    let mut m = BTreeMap::new();
    for (role_key, spec) in t {
        let role = match role_key.as_str() { "certify" => Role::Certify, "sign" => Role::Sign, "auth" => Role::Auth, "encrypt" => Role::Encrypt, other => return Err(format!("unknown role {other}")) };
        let st = spec.as_table().ok_or("each role must be a table { algo, expiry }")?;
        let algo = parse_algo(st.get("algo").and_then(|x| x.as_str()).ok_or("missing algo")?)?;
        let expiry = parse_expiry(st.get("expiry").and_then(|x| x.as_str()).unwrap_or("never")).ok_or("bad expiry")?;
        m.insert(role, AlgoSpec { algo, expiry });
    }
    Ok(m)
}
fn parse_algo(s: &str) -> std::result::Result<Algo, String> {
    match s {
        "ed25519" => Ok(Algo::Ed25519),
        "ed448" => Ok(Algo::Ed448),
        "cv25519" => Ok(Algo::Cv25519),
        "secp256k1" => Ok(Algo::Secp256k1),
        _ if s.starts_with("rsa") => s[3..].parse().map(Algo::Rsa).map_err(|_| format!("bad rsa size {s}")),
        _ if s.starts_with("nistp") => s[5..].parse().map(Algo::NistP).map_err(|_| format!("bad nist curve {s}")),
        _ if s.starts_with("brainpool") => s[9..].parse().map(Algo::Brainpool).map_err(|_| format!("bad brainpool {s}")),
        _ => Err(format!("unknown algo {s}")),
    }
}
```

- [ ] **Step 3: Append ONE complete test mod (avoids the stray-brace pitfall)**

Append to `registry.rs` (a single, self-contained `mod` — do not reopen `registry_tests`):

```rust
#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::config::parse_config;
    use crate::policy::{load_policy_under, Policy};

    fn empty_cli() -> CliArgs { CliArgs::default() }

    #[test]
    fn secret_string_and_pin_redact_but_expose() {
        // WHY (§3/§10): SecretString AND ResolvedValue::Pin must never leak via
        // Debug/Display; the engine still reads the value via expose().
        let s = SecretString::new("123456".into());
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(s.expose(), "123456");
        let pin = ResolvedValue::Pin(SecretString::new("s3cr3t".into()));
        let dbg = format!("{pin:?}");
        assert!(dbg.contains("[REDACTED]") && !dbg.contains("s3cr3t"), "Pin Debug leaked: {dbg}");
    }

    #[test]
    fn default_provenance_for_unsupplied_decisions() {
        // WHY (§3): with only the required UID supplied, every OTHER decision takes
        // its default with Default provenance; device-allowlist resolves to an empty
        // list (not absent). real-name/email are required, so a non-interactive
        // resolve cannot succeed without them — supply them to exercise the rest.
        let cfg = parse_config("real-name='A'\nemail='a@x.com'\n").unwrap();
        let set = resolve(&empty_cli(), &cfg, &Policy::default(), false).unwrap();
        let r = set.get("compliance-profile").unwrap();
        assert!(matches!(r.value, ResolvedValue::Enum("drduh")));
        assert_eq!(r.provenance, Provenance::Default);
        assert!(matches!(set.get("device-allowlist").unwrap().value, ResolvedValue::DeviceList(ref v) if v.is_empty()));
    }

    fn locked_profile_policy(tag: &str) -> (Policy, std::path::PathBuf) {
        // a policy that locks compliance-profile = fips, under a temp store root.
        let dir = std::env::temp_dir().join(format!("kwtest-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.toml"); std::fs::write(&f, "compliance-profile='fips'\n").unwrap();
        (load_policy_under(&f, &dir).unwrap(), dir)
    }

    #[test]
    fn policy_lock_wins_and_redundant_same_value_is_accepted() {
        // WHY (§3): a policy lock wins; a config setting the SAME value is a
        // redundant (non-conflicting) override → accepted, provenance PolicyLocked.
        let (pol, dir) = locked_profile_policy("lock-ok");
        let cfg = parse_config("real-name='A'\nemail='a@x.com'\ncompliance-profile='fips'\n").unwrap();
        let set = resolve(&empty_cli(), &cfg, &pol, false).unwrap();
        assert!(matches!(set.get("compliance-profile").unwrap().value, ResolvedValue::Enum("fips")));
        assert_eq!(set.get("compliance-profile").unwrap().provenance, Provenance::PolicyLocked);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn policy_locked_conflicting_override_is_named_error() {
        // WHY (§3): a lower-precedence source supplying a DIFFERENT value than the
        // lock is a named error (fail-loud), not a silent substitution — for config
        // AND for CLI.
        let (pol, dir) = locked_profile_policy("lock-conf");
        let cfg_conf = parse_config("real-name='A'\nemail='a@x.com'\ncompliance-profile='cnsa'\n").unwrap();
        let e = resolve(&empty_cli(), &cfg_conf, &pol, false).unwrap_err();
        assert!(e.to_string().contains("compliance-profile") && e.to_string().contains("policy-locked"));
        let mut cli = CliArgs::default(); cli.values.insert("compliance-profile".into(), "bsi".into());
        let cfg = parse_config("real-name='A'\nemail='a@x.com'\n").unwrap();
        assert!(resolve(&cli, &cfg, &pol, false).is_err(), "conflicting CLI override of a locked field must error");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_beats_config_when_unlocked() {
        // WHY (§3): with no policy lock, CLI > config > default.
        let cfg = parse_config("real-name='A'\nemail='a@x.com'\ncompliance-profile='cnsa'\n").unwrap();
        let mut cli = CliArgs::default(); cli.values.insert("compliance-profile".into(), "bsi".into());
        let set = resolve(&cli, &cfg, &Policy::default(), false).unwrap();
        assert!(matches!(set.get("compliance-profile").unwrap().value, ResolvedValue::Enum("bsi")));
        assert_eq!(set.get("compliance-profile").unwrap().provenance, Provenance::Cli);
    }

    #[test]
    fn invalid_enum_value_is_a_named_resolve_error() {
        // WHY (§3): per-value validation; the error names the id, not a secret.
        let cfg = parse_config("compliance-profile='nope'\n").unwrap();
        let e = resolve(&empty_cli(), &cfg, &Policy::default(), false).unwrap_err();
        assert!(e.to_string().contains("compliance-profile"));
    }

    #[test]
    fn non_interactive_missing_required_field_is_hard_error() {
        // WHY (§3/§10): a required decision (real-name/email) unsupplied in
        // non-interactive mode must hard-error naming the decision — not skip.
        let cfg = parse_config("").unwrap();
        let e = resolve(&empty_cli(), &cfg, &Policy::default(), false).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("real-name") || s.contains("email"), "must name the missing field, got: {s}");
    }

    #[test]
    fn optional_missing_field_is_left_unresolved_not_an_error() {
        // WHY (§3): optional no-default fields (target-card-serial) are simply
        // absent when unsupplied, even non-interactive — NOT a hard error. We can
        // only observe this once required fields are supplied, so supply them.
        let cfg = parse_config("real-name='A'\nemail='a@x.com'\n").unwrap();
        let set = resolve(&empty_cli(), &cfg, &Policy::default(), false).unwrap();
        assert!(set.get("target-card-serial").is_none());
        assert!(set.get("real-name").is_some());
    }

    #[test]
    fn algo_profile_toml_round_trips_and_cli_overrides() {
        // WHY (§3/§10): [algo] nested TOML parses to per-role AlgoSpec; a per-role
        // --algo-<role> CLI override merges on top.
        let toml = "real-name='A'\nemail='a@x.com'\n[algo]\ncertify={algo='rsa4096',expiry='never'}\nsign={algo='ed25519',expiry='2y'}\nauth={algo='ed25519',expiry='2y'}\nencrypt={algo='cv25519',expiry='2y'}\n";
        let cfg = parse_config(toml).unwrap();
        let mut cli = CliArgs::default();
        cli.algo.insert(Role::Sign, AlgoSpec { algo: Algo::NistP(256), expiry: Expiry::Days(365) });
        let set = resolve(&cli, &cfg, &Policy::default(), false).unwrap();
        let ResolvedValue::AlgoProfile(m) = &set.get("algo").unwrap().value else { panic!("expected AlgoProfile") };
        assert!(matches!(m[&Role::Certify].algo, Algo::Rsa(4096)));   // from config
        assert!(matches!(m[&Role::Sign].algo, Algo::NistP(256)));     // CLI override won
        assert_eq!(set.get("algo").unwrap().provenance, Provenance::Cli);
    }
}
```

- [ ] **Step 4: Regenerate lockfile, build + test, commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright && nix develop .#keywright -c cargo generate-lockfile
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/Cargo.toml overlays/top-level/keywright/crates/keywright-core/src/registry.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): resolve() — precedence/provenance/required + algo merge → ResolvedSet"
```

Expected: `checkPhase` runs the `registry_tests` + 7 `resolve_tests`, all `ok`.

______________________________________________________________________

### Task 6: `runner` — typed subprocess + the `Secret` argv barrier

**Files:**

- Modify: `overlays/top-level/keywright/package.nix` (add `coreutils` to `nativeCheckInputs`; inject `KEYWRIGHT_TEST_CAT`)
- Create: `crates/keywright-core/src/runner.rs`
- Modify: `crates/keywright-core/src/lib.rs` (`pub mod runner;`)

**Interfaces:**

- Consumes: `Error`, `Result` (Task 1); `SecretString` (Task 5, for the `Secret` payload).
- Produces: `pub struct Command`, `Command::new(bin: &str) -> Result<Self>`, `Command::arg(self, &str) -> Self` (NON-secret only), `Command::secret_stdin(self, Secret) -> Self`, `Command::args_ref(&self) -> &[String]`, `Command::run(&self) -> Result<Output>`, `pub struct Output { pub stdout: String, pub status_ok: bool }`, `pub struct Secret(pub SecretString)`. Plan 2b's `device`/§7 use this; Plan 3 adds gpg/cryptsetup.

**Why the `Secret` type:** `arg()` takes `&str`; `secret_stdin()` takes `Secret`. There is no `arg(Secret)` overload, so a secret **cannot** be placed in argv — a compile error, not a review item (§3).

- [ ] **Step 1: Make the package inject a sandbox-pure helper-binary path**

`buildRustPackage` runs the unit tests in the sandbox (only `/nix/store` + `/bin/sh`). For the one test that actually spawns a process, the package provides a real `/nix/store` `cat` and exports its absolute path. Edit `overlays/top-level/keywright/package.nix`:

- add `coreutils` to the function args:

```nix
{
  lib,
  rustPlatform,
  coreutils,
}:
```

- add under the derivation attrs:

```nix
  nativeCheckInputs = [ coreutils ];
  # The runner spawn-test needs a real, absolute /nix/store binary to prove
  # stdin delivery; inject it so the test stays pure (no /run/current-system).
  preCheck = ''
    export KEYWRIGHT_TEST_CAT=${lib.getExe' coreutils "cat"}
  '';
```

- [ ] **Step 2: Write `runner.rs`**

`crates/keywright-core/src/runner.rs`:

```rust
//! Typed subprocess runner (§2.3). Build argv, pin binary to an absolute
//! /nix/store path, feed secrets ONLY via stdin behind a `Secret` type the argv
//! builder cannot take, capture structured output. Plan 2a: read-only probes.

use crate::registry::SecretString;
use crate::{Error, Result};
use std::process::Stdio;

/// A secret payload destined for child stdin. `arg()` cannot accept this type,
/// so "secret in argv" is a compile error (§3).
pub struct Secret(pub SecretString);

pub struct Command { bin: String, args: Vec<String>, stdin: Option<Secret> }

#[derive(Debug)]
pub struct Output { pub stdout: String, pub status_ok: bool }

impl Command {
    /// `bin` must be an absolute path (/nix/store-pinned in production); a bare
    /// command name (PATH lookup) is refused.
    pub fn new(bin: impl Into<String>) -> Result<Self> {
        let bin = bin.into();
        if !bin.starts_with('/') {
            return Err(Error::Runner(format!("binary path must be absolute: {bin}")));
        }
        Ok(Command { bin, args: Vec::new(), stdin: None })
    }
    pub fn arg(mut self, a: impl Into<String>) -> Self { self.args.push(a.into()); self } // NON-secret only
    pub fn secret_stdin(mut self, s: Secret) -> Self { self.stdin = Some(s); self }
    pub fn args_ref(&self) -> &[String] { &self.args } // test/inspection accessor

    pub fn run(&self) -> Result<Output> {
        use std::io::Write;
        let mut cmd = std::process::Command::new(&self.bin);
        cmd.args(&self.args).stdout(Stdio::piped()).stderr(Stdio::null());
        if self.stdin.is_some() { cmd.stdin(Stdio::piped()); }
        let mut child = cmd.spawn()?;
        if let Some(s) = &self.stdin {
            child.stdin.take().unwrap().write_all(s.0.expose().as_bytes())?;
        }
        let out = child.wait_with_output()?;
        Ok(Output { stdout: String::from_utf8_lossy(&out.stdout).into_owned(), status_ok: out.status.success() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bare_binary_name_requires_absolute() {
        // WHY (§2.3): binaries are absolute /nix/store paths; a bare name is refused.
        assert!(Command::new("cat").is_err());
        assert!(Command::new("/nix/store/whatever/bin/cat").is_ok());
    }

    #[test]
    fn secret_is_not_in_argv_only_in_stdin_field() {
        // WHY (§3): the secret routes via the stdin field, never argv. This is a
        // pure structural check (no process spawned) and runs in any sandbox.
        let c = Command::new("/bin/sh").unwrap()
            .arg("-c").arg("true")
            .secret_stdin(Secret(SecretString::new("s3cr3t".into())));
        assert!(!c.args_ref().iter().any(|a| a.contains("s3cr3t")), "secret leaked into argv");
        assert_eq!(c.args_ref(), &["-c", "true"]);
    }

    #[test]
    fn secret_is_delivered_via_stdin() {
        // WHY (§3): prove stdin delivery end-to-end with a REAL absolute /nix/store
        // binary injected by package.nix (KEYWRIGHT_TEST_CAT). Skips if unset
        // (e.g. a non-Nix run); under `nix build` the env is always set.
        let Ok(cat) = std::env::var("KEYWRIGHT_TEST_CAT") else { return; };
        let out = Command::new(cat).unwrap()
            .secret_stdin(Secret(SecretString::new("s3cr3t".into())))
            .run().unwrap();
        assert!(out.stdout.contains("s3cr3t"), "secret was delivered via stdin");
    }
}
```

Add `pub mod runner;` to `lib.rs`. *(The `arg`-can't-take-`Secret` barrier is structural — no runtime test exercises it; the type design is the guarantee.)*

- [ ] **Step 3: Build + test, commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/package.nix overlays/top-level/keywright/crates/keywright-core/src/runner.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): typed runner; Secret-via-stdin argv barrier; absolute-path pin; sandbox-pure tests"
```

Expected: `checkPhase` runs 3 runner tests (the stdin-delivery test uses the injected `KEYWRIGHT_TEST_CAT`), all `ok`.

______________________________________________________________________

### Task 7: `parse` — mount/swap-topology parsers (fixtures)

**Files:**

- Modify: `crates/keywright-core/Cargo.toml` (add `serde_json`)
- Create: `crates/keywright-core/src/parse.rs`
- Create: `crates/keywright-core/tests/fixtures/lsblk-simple.json`, `findmnt-simple.json`, `proc-swaps-file.txt`, `mountinfo-simple.txt`
- Modify: `crates/keywright-core/src/lib.rs` (`pub mod parse;`)

**Scope:** 2a delivers the **mount + swap** topology parsers — `lsblk --json`, `findmnt --json`, `/proc/swaps`, `/proc/self/mountinfo`. The **storage source-resolution** parsers (`zpool status`, `mdadm`/sysfs, `bcache` sysfs) that map a dm/md/zvol device back to its physical members are delivered in **Plan 2b** alongside the `device` source-resolution recursion that consumes them.

**Interfaces:**

- Consumes: `Error`, `Result` (Task 1).

- Produces: `pub struct BlockDevice { pub name: String, pub fstype: Option<String>, pub mountpoints: Vec<String>, pub children: Vec<BlockDevice> }`, `pub fn parse_lsblk_json(s: &str) -> Result<Vec<BlockDevice>>`; `pub struct MountEntry { pub source: String, pub target: String, pub fstype: String }`, `pub fn parse_findmnt_json(s: &str) -> Result<Vec<MountEntry>>`, `pub fn parse_mountinfo(s: &str) -> Result<Vec<MountEntry>>`; `pub enum SwapKind { Partition, File }`, `pub struct SwapEntry { pub source: String, pub kind: SwapKind }`, `pub fn parse_proc_swaps(s: &str) -> Result<Vec<SwapEntry>>`. **Plan 2b's `device`** consumes these.

- [ ] **Step 1: Add `serde_json`; create fixtures**

Add to `crates/keywright-core/Cargo.toml`:

```toml
serde_json = "1"
```

`tests/fixtures/lsblk-simple.json`:

```json
{ "blockdevices": [
  { "name": "sda", "fstype": null, "mountpoints": [null],
    "children": [
      { "name": "sda1", "fstype": "vfat", "mountpoints": ["/boot"], "children": [] },
      { "name": "sda2", "fstype": "ext4", "mountpoints": ["/"], "children": [] } ] },
  { "name": "sdb", "fstype": null, "mountpoints": [null], "children": [] }
] }
```

`tests/fixtures/findmnt-simple.json`:

```json
{ "filesystems": [
  { "source": "/dev/sda2", "target": "/", "fstype": "ext4",
    "children": [ { "source": "/dev/sda1", "target": "/boot", "fstype": "vfat" } ] }
] }
```

`tests/fixtures/proc-swaps-file.txt`:

```
Filename                                Type            Size            Used            Priority
/swapfile                               file            8388604         0               -2
```

`tests/fixtures/mountinfo-simple.txt`:

```
36 35 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
37 36 8:1 / /boot rw,relatime shared:2 - vfat /dev/sda1 rw
```

- [ ] **Step 2: Write `parse.rs`**

`crates/keywright-core/src/parse.rs`:

```rust
//! Pure parsers for read-only mount/swap probes (§6). Plan 2a: mount + swap
//! topology; Plan 2b adds zpool/mdadm/bcache source-resolution parsers. No
//! process spawning here — fixtures only.

use crate::{Error, Result};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDevice {
    pub name: String,
    pub fstype: Option<String>,
    pub mountpoints: Vec<String>, // null entries dropped
    pub children: Vec<BlockDevice>,
}

#[derive(Deserialize)]
struct RawDev { name: String, fstype: Option<String>, #[serde(default)] mountpoints: Vec<Option<String>>, #[serde(default)] children: Vec<RawDev> }
#[derive(Deserialize)]
struct RawLsblk { blockdevices: Vec<RawDev> }

impl From<RawDev> for BlockDevice {
    fn from(r: RawDev) -> Self {
        BlockDevice {
            name: r.name,
            fstype: r.fstype,
            mountpoints: r.mountpoints.into_iter().flatten().collect(),
            children: r.children.into_iter().map(BlockDevice::from).collect(),
        }
    }
}

pub fn parse_lsblk_json(s: &str) -> Result<Vec<BlockDevice>> {
    let raw: RawLsblk = serde_json::from_str(s).map_err(|e| Error::Parse(format!("lsblk json: {e}")))?;
    Ok(raw.blockdevices.into_iter().map(BlockDevice::from).collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry { pub source: String, pub target: String, pub fstype: String }

#[derive(Deserialize)]
struct RawMnt { source: String, target: String, fstype: String, #[serde(default)] children: Vec<RawMnt> }
#[derive(Deserialize)]
struct RawFindmnt { filesystems: Vec<RawMnt> }

fn flatten_mnt(m: RawMnt, out: &mut Vec<MountEntry>) {
    out.push(MountEntry { source: m.source, target: m.target, fstype: m.fstype });
    for c in m.children { flatten_mnt(c, out); }
}

pub fn parse_findmnt_json(s: &str) -> Result<Vec<MountEntry>> {
    let raw: RawFindmnt = serde_json::from_str(s).map_err(|e| Error::Parse(format!("findmnt json: {e}")))?;
    let mut out = Vec::new();
    for m in raw.filesystems { flatten_mnt(m, &mut out); }
    Ok(out)
}

/// /proc/self/mountinfo: fields after " - " are fstype, source, superopts.
pub fn parse_mountinfo(s: &str) -> Result<Vec<MountEntry>> {
    let mut out = Vec::new();
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let (pre, post) = line.split_once(" - ").ok_or_else(|| Error::Parse(format!("mountinfo: no separator in {line}")))?;
        let target = pre.split_whitespace().nth(4).ok_or_else(|| Error::Parse("mountinfo: missing target".into()))?;
        let mut fields = post.split_whitespace();
        let fstype = fields.next().ok_or_else(|| Error::Parse("mountinfo: missing fstype".into()))?;
        let source = fields.next().ok_or_else(|| Error::Parse("mountinfo: missing source".into()))?;
        out.push(MountEntry { source: source.to_string(), target: target.to_string(), fstype: fstype.to_string() });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapKind { Partition, File }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry { pub source: String, pub kind: SwapKind }

pub fn parse_proc_swaps(s: &str) -> Result<Vec<SwapEntry>> {
    let mut out = Vec::new();
    for line in s.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(source), Some(kind)) = (cols.next(), cols.next()) else { continue };
        let kind = match kind { "partition" => SwapKind::Partition, "file" => SwapKind::File, other => return Err(Error::Parse(format!("unknown swap type {other}"))) };
        out.push(SwapEntry { source: source.to_string(), kind });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsblk_aggregates_children_and_drops_null_mountpoints() {
        // WHY (§6): the parser exposes child mountpoints (/,/boot on sda1/sda2) so
        // device source-resolution (Plan 2b) can roll them up to the whole disk;
        // null mountpoints are dropped.
        let devs = parse_lsblk_json(include_str!("../tests/fixtures/lsblk-simple.json")).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].name, "sda");
        assert!(devs[0].mountpoints.is_empty());
        let cm: Vec<_> = devs[0].children.iter().flat_map(|c| c.mountpoints.clone()).collect();
        assert!(cm.contains(&"/".to_string()) && cm.contains(&"/boot".to_string()));
    }

    #[test]
    fn findmnt_flattens_children_to_source_target_pairs() {
        // WHY (§6): findmnt is the authoritative mount source; / and /boot must
        // both surface with their backing devices for in-use detection.
        let m = parse_findmnt_json(include_str!("../tests/fixtures/findmnt-simple.json")).unwrap();
        assert!(m.iter().any(|e| e.target == "/" && e.source == "/dev/sda2"));
        assert!(m.iter().any(|e| e.target == "/boot" && e.source == "/dev/sda1"));
    }

    #[test]
    fn mountinfo_parses_source_after_separator() {
        // WHY (§6): /proc/self/mountinfo is the kernel-authoritative fallback;
        // the device is the field after " - ".
        let m = parse_mountinfo(include_str!("../tests/fixtures/mountinfo-simple.txt")).unwrap();
        assert!(m.iter().any(|e| e.target == "/" && e.source == "/dev/sda2" && e.fstype == "ext4"));
    }

    #[test]
    fn proc_swaps_distinguishes_file_from_partition() {
        // WHY (§6): a swapFILE is a path with Type=file (not a device); device
        // resolution must map it to its containing fs. The parser surfaces the kind.
        let sw = parse_proc_swaps(include_str!("../tests/fixtures/proc-swaps-file.txt")).unwrap();
        assert_eq!(sw, vec![SwapEntry { source: "/swapfile".into(), kind: SwapKind::File }]);
    }
}
```

Add `pub mod parse;` to `lib.rs`.

- [ ] **Step 3: Regenerate lockfile, build + full suite, commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright && nix develop .#keywright -c cargo generate-lockfile
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/src/parse.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs overlays/top-level/keywright/crates/keywright-core/tests/fixtures
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): mount/swap-topology parsers (lsblk/findmnt/mountinfo/swaps) + fixtures"
```

Expected: `checkPhase` runs the FULL `keywright-core` suite; 4 parse tests `ok`.

______________________________________________________________________

### Task 8: Final whole-crate verification

**Files:** none (verification + a `style:` commit only if `nix fmt` touches anything).

**Interfaces:** Consumes everything above. Produces: a buildable `pkgs.keywright` whose `keywright-core` carries the 2a modules and whose `checkPhase` runs the whole suite green.

- [ ] **Step 1: Clean build from a staged tree**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add -A overlays/top-level/keywright
nix build .#keywright -L --rebuild   # force a fresh checkPhase even if cached
./result/bin/keywright --version
```

Expected: build exits 0; `checkPhase` shows every module's tests `ok` (error/registry/config/policy/runner/parse); `keywright 0.0.1`.

- [ ] **Step 2: Format idempotence**

```bash
cd /home/djacu/dev/djacu/yubikey-loader && nix fmt && git status --porcelain
```

Expected: `git status` clean. If `nix fmt` changed anything, `git add -A && git commit -m "style: treefmt"`.

______________________________________________________________________

## Self-Review

**1. Spec coverage (2a subset, §2–§4/§9):**

- `error` + no-`process::exit` + **panic=unwind profile & compile_error! guard** (§9) → Task 1. ✓
- `registry` types + `DECISIONS` + per-surface invariant + `required` + destructive-token independence (§3/§4) → Task 2. ✓
- `config` TOML + identity (NFC, RFC-5322 subset, batch, dup-email, interactive) (§4) → Task 3. ✓
- `policy` `/nix/store` canonicalization incl. **symlink-escape + `..`-traversal** + lockable-only (§4/§9) → Task 4. ✓
- `resolve()` precedence/provenance/required + secret-skip + **`SessionFile` variant** + **AlgoProfile TOML + per-role CLI merge** + `SecretString`/`Pin` redaction (§3) → Task 5. ✓
- `runner` typed subprocess + `Secret`-via-stdin barrier + absolute-path pin + **sandbox-pure tests** (§2.3/§3) → Task 6. ✓
- `parse` lsblk/findmnt/mountinfo/swaps + fixtures (§6) → Task 7. ✓
- **Deferred to 2b (correctly absent):** compliance, secret/preflight/clock, device classification, plan/`--dry-run`, `PlanResult`, and zpool/mdadm/bcache source-resolution parsers. `resolve()` returns `ResolvedSet`; 2b wraps it. `SecretString` zeroize-on-drop behavior is asserted in 2b (where it's exercised with real secrets); 2a ships the type + redaction tests.

**2. Placeholder scan:** every code step shows real code; the only explicit deferrals (zeroize-on-drop test; zpool/md/bcache parsers; the structural `arg(Secret)` barrier) are stated scope decisions, not missing implementations.

**3. Type consistency:** `Error`/`Result` (T1) everywhere; `Decision`/`DefaultVal`(+`DeviceList`)/`Algo`/`Expiry`/`Role`/`AlgoSpec`/`required` (T2) consumed by T5; `Config` (T3) + `Policy` (T4) consumed by `resolve()`; `SecretString` (T5) wrapped by `runner::Secret` (T6); `CliArgs{values,algo}` (T5) matches the per-role CLI seam; `Provenance` has all 6 spec variants; `coerce()` Enum arm uses `.copied()` (no `&&str` mismatch). `resolve` returns `ResolvedSet` (2a) vs `PlanResult` (2b) — stated in Global Constraints + T5 interfaces.

______________________________________________________________________

## Execution Handoff

Plan complete. Two execution options (subagent-driven recommended — fresh subagent per task + per-task review, as in Plan 1).
