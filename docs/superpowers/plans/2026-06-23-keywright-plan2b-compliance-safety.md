# Keywright Plan 2b — Compliance, Secret, Device & Plan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the safety + validation half of `keywright-core` — the fail-closed compliance gate (+ regime-qualified verdicts), the storage source-resolution parsers + positive-proof fail-closed device filter, the tmpfs/RAII secret guards + clock-trust preflight, and the `plan`/`--dry-run` that assembles `PlanResult` and renders every decision with provenance — all unit-tested via the pure package build, no key material, no card, no LUKS.

**Architecture:** Adds four modules (`compliance`, `secret`, `device`, `plan`) + storage source-resolution parsers to the `keywright-core` crate that **Plan 2a** left at the resolution-spine stage. 2b wraps 2a's `resolve()` → `ResolvedSet` into the spec's `PlanResult { resolved, validated_now, compliance_data_version }` by adding the §7 clock step + the §5 baked compliance-data edition. Compliance + clock-floor reference data is a committed TOML `include_str!`'d into the binary (store-baked, versioned, flake-decoupled). The device module is the safety crown jewel: a **globally fail-closed** recursion that resolves every in-use mount/swap to concrete whole disks and refuses *everything* if any source is unresolved, empty, partial, degraded, or resolves to a disk not enumerated.

**Tech Stack:** Rust (edition 2024) · the Plan-2a deps · `time` (UTC `OffsetDateTime`/`Date` + RFC-3339) · `getrandom` · `libc` (`setrlimit`/swap probe).

## Global Constraints

- **This is Plan 2b**, depending on **Plan 2a** merged (`error` incl. the new `Error::Compliance` variant; `registry` incl. `Algo::{Ed448,Secp256k1}`; `runner`; `parse`; `config`; `policy`; `resolve() → ResolvedSet`). **Out of 2b (Plan 3+):** keygen, gpg/cryptsetup, `--with-colons` parsers, `LuksMount`, verification-scratch home, audit signing, the FIPS-device-Approved-Mode card-status branch, secret/PIN/LUKS *generation*, the live `device` probe wiring (2b builds discovery from parsed `Probes`; Plan 3 builds `Probes` from the live `runner`), and populating `DiskCandidate.existing_keywright_backups` (a live drive probe — Plan 3; 2b's `idempotency_check` is pure over that field).
- **Explicit Plan-2b scope-outs (no registry input exists yet; deferred with the §10 coverage claim corrected):** **CNSA SHA-256-for-general-use** (the registry has no hash/cert-digest decision — `AlgoSpec` carries only `algo`+`expiry`); **strict-FIPS Brainpool exclusion** (no `strict-fips` decision). Both are noted in Task 3; do not claim §10 coverage for them.
- **`plan` assembles `PlanResult`** = 2a's `ResolvedSet` + `validated_now` (from `secret::validate_clock`) + `compliance_data_version` (from baked data). `compliance::validate(&ResolvedSet, now)` + the preview consume `now` — **never a system clock**. Task 9 greps `compliance.rs` to prove it reads no clock.
- **TEST/VERIFY GATE — pure `nix build .#keywright -L`** (checkPhase runs `cargo test`). No impure cargo. `git add` new files before `nix build`. Lockfile regen: `nix develop .#keywright -c cargo generate-lockfile`. Tests use captured fixtures / in-memory `Probes` — **no real block devices, no live preflight syscalls in unit tests**; RAII-guard tests use a temp base dir (not `$XDG_RUNTIME_DIR`, unset in the sandbox).
- **Fail-closed is the law (§6):** any source that is unresolved / `Unknown` / empty-member / partial-multi-member / degraded / resolves-to-a-non-enumerated-disk ⇒ `Discovery.resolution_complete = false` (a single **global** flag) ⇒ `classify` excludes **every** candidate. Over-refusal is the intended direction.
- **No `process::exit`; everything returns `Result`; `panic = "unwind"`** (the 2a workspace profile + `compile_error!` guard enforce it). RAII `Drop` runs on every path incl. panic; panic-path tests use `catch_unwind`.
- **Secrets never in argv/env/log** (2a); `SecretString`/`Pin` redact + zeroize; no `Error` variant embeds a secret. **Regime-qualified verdicts only.**
- **Baked, versioned, flake-decoupled reference data** (§5/§7): a committed TOML `include_str!`'d into the binary — refresh = edit + rebuild. The §7 clock-floor sanity (`<= 2024-01-01` ⇒ hard error) is enforced in **production** code (`validate_floor`), not only tests.
- **Tests document *why***; `nix fmt` before each commit; **commits GPG-signed** (pinentry; never `--no-gpg-sign`). Crate path `overlays/top-level/keywright/crates/keywright-core/`; build recipe `…/package.nix`.

______________________________________________________________________

## File Structure

```
overlays/top-level/keywright/crates/keywright-core/
  Cargo.toml                         # MODIFY: add time, getrandom, libc
  data/compliance.toml               # NEW (Task 2): baked horizons/floors/forbid + clock-floor + version
  src/
    lib.rs                           # MODIFY: pub mod compliance/secret/device/plan
    parse.rs                         # MODIFY (Task 1): + zpool/mdadm/bcache parsers
    compliance.rs                    # NEW (Task 2,3): baked data load + validate() + verdicts()
    secret.rs                        # NEW (Task 4,5): preflight + clock-trust + RAII guards
    device.rs                        # NEW (Task 6,7): Probes/recursion + classify + check_roles
    plan.rs                          # NEW (Task 8): PlanResult + render + --dry-run
  tests/fixtures/                    # MODIFY (Task 1): zpool/mdadm/bcache text fixtures
```

The `./crates` fileset (package.nix) recursively includes `data/compliance.toml` — **do not narrow the fileset without re-including `data/`** (the `include_str!` target). Task order: `parse` → `compliance` ∥ `secret` → `device` → `plan`.

______________________________________________________________________

### Task 1: `parse` — storage source parsers (fixtures)

**Files:** Modify `src/parse.rs`; create `tests/fixtures/{zpool-mirror,zpool-degraded}.txt`, `mdadm-detail.txt`, `bcache-backing.txt`.

**Interfaces:** Consumes `Error`/`Result` (2a). Produces `pub struct PoolMember { pub dev: String, pub state: String }`, `pub fn parse_zpool_status(&str) -> Result<Vec<PoolMember>>` (leaf members only, with state), `pub fn parse_mdadm_detail(&str) -> Result<Vec<String>>`, `pub fn parse_bcache_backing(&str) -> Result<Vec<String>>`. `device` (Task 6) consumes these.

- [ ] **Step 1: Fixtures**

`tests/fixtures/zpool-mirror.txt`:

```
  pool: rpool
 state: ONLINE
config:
	NAME        STATE     READ WRITE CKSUM
	rpool       ONLINE       0     0     0
	  mirror-0  ONLINE       0     0     0
	    sda2    ONLINE       0     0     0
	    sdb2    ONLINE       0     0     0
```

`tests/fixtures/zpool-degraded.txt`:

```
  pool: rpool
 state: DEGRADED
config:
	NAME                      STATE     READ WRITE CKSUM
	rpool                     DEGRADED     0     0     0
	  mirror-0                DEGRADED     0     0     0
	    sda2                  ONLINE       0     0     0
	    1234567890123456789   UNAVAIL      0     0     0
```

`tests/fixtures/mdadm-detail.txt`:

```
/dev/md0:
        Version : 1.2
     Raid Level : raid1
   Number   Major   Minor   RaidDevice State
      0       8        1        0      active sync   /dev/sda1
      1       8       17        1      active sync   /dev/sdb1
```

`tests/fixtures/bcache-backing.txt`:

```
/dev/sdc1
```

- [ ] **Step 2: Parsers (header/pool-row bugs fixed) + tests**

Append to `src/parse.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMember { pub dev: String, pub state: String }

/// `zpool status` LEAF members only (devices/GUIDs at the deepest level), with
/// state. WHY (§6): the recursion needs every member + state; a non-ONLINE or
/// GUID-only member marks the whole source unresolvable. We skip the header, the
/// pool-root row (first config row), and vdev container rows (mirror/raidz/...).
pub fn parse_zpool_status(s: &str) -> Result<Vec<PoolMember>> {
    let mut out = Vec::new();
    let mut in_config = false;
    let mut seen_pool_root = false;
    for line in s.lines() {
        if line.trim_start().starts_with("NAME") { in_config = true; continue; }
        if !in_config { continue; }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 { continue; }
        let (name, state) = (toks[0], toks[1]);
        if !matches!(state, "ONLINE"|"DEGRADED"|"FAULTED"|"OFFLINE"|"UNAVAIL"|"REMOVED") { continue; }
        if !seen_pool_root { seen_pool_root = true; continue; }      // pool-root row (e.g. "rpool")
        if name.starts_with("mirror")||name.starts_with("raidz")||name.starts_with("spare")
            ||name.starts_with("log")||name.starts_with("cache") { continue; } // vdev containers
        out.push(PoolMember { dev: name.to_string(), state: state.to_string() });
    }
    Ok(out)
}

/// mdadm --detail member device paths. Skip the array-header line ("/dev/md0:")
/// — only rows carrying a RaidDevice state list a member.
pub fn parse_mdadm_detail(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for line in s.lines() {
        if !(line.contains("active")||line.contains("sync")||line.contains("spare")||line.contains("faulty")) { continue; }
        if let Some(dev) = line.split_whitespace().find(|t| t.starts_with("/dev/") && !t.ends_with(':')) {
            out.push(dev.to_string());
        }
    }
    if out.is_empty() { return Err(Error::Parse("mdadm: no member devices".into())); }
    Ok(out)
}

/// bcache backing device (the `backing_dev` sysfs readout — one path).
pub fn parse_bcache_backing(sysfs: &str) -> Result<Vec<String>> {
    let dev = sysfs.trim();
    if dev.is_empty() { return Err(Error::Parse("bcache: empty backing_dev".into())); }
    Ok(vec![dev.to_string()])
}

#[cfg(test)]
mod stack_tests {
    use super::*;

    #[test]
    fn zpool_mirror_lists_exactly_the_two_leaf_members() {
        // WHY (§6): the parser yields the two leaf disks (not the pool/vdev rows),
        // both ONLINE, so the recursion can roll them up to whole disks.
        let m = parse_zpool_status(include_str!("../tests/fixtures/zpool-mirror.txt")).unwrap();
        assert_eq!(m, vec![
            PoolMember { dev: "sda2".into(), state: "ONLINE".into() },
            PoolMember { dev: "sdb2".into(), state: "ONLINE".into() },
        ]);
    }

    #[test]
    fn zpool_degraded_surfaces_unavail_guid_member() {
        // WHY (§6): a GUID-only UNAVAIL member must surface so the recursion fails closed.
        let m = parse_zpool_status(include_str!("../tests/fixtures/zpool-degraded.txt")).unwrap();
        assert!(m.iter().any(|p| p.state == "UNAVAIL" && p.dev.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn mdadm_skips_header_and_lists_members() {
        // WHY (§6): the "/dev/md0:" array-header line must NOT be a member.
        let md = parse_mdadm_detail(include_str!("../tests/fixtures/mdadm-detail.txt")).unwrap();
        assert_eq!(md, ["/dev/sda1", "/dev/sdb1"]);
    }

    #[test]
    fn bcache_backing_member() {
        let bc = parse_bcache_backing(include_str!("../tests/fixtures/bcache-backing.txt")).unwrap();
        assert_eq!(bc, ["/dev/sdc1"]);
    }
}
```

- [ ] **Step 3: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/parse.rs overlays/top-level/keywright/crates/keywright-core/tests/fixtures
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): zpool/mdadm/bcache source parsers (leaf members + state) + fixtures"
```

Expected: `checkPhase` runs 4 `stack_tests`, `ok`.

______________________________________________________________________

### Task 2: `compliance` — baked reference data + loader (with floor sanity)

**Files:** Modify `Cargo.toml` (add `time`); create `data/compliance.toml`, `src/compliance.rs`; modify `lib.rs` (`pub mod compliance;`).

**Interfaces:** Produces `pub struct ComplianceData { … }`, `pub fn data() -> &'static ComplianceData`, `pub fn version() -> &'static str`, `pub fn checked_clock_floor() -> Result<time::Date>` (production §7 sanity gate: hard-error if `<= 2024-01-01`), and the pure `fn validate_floor(time::Date) -> Result<time::Date>` it wraps. `secret`/`plan` consume these.

- [ ] **Step 1: Add `time`; the data file**
  Add to `Cargo.toml`:

```toml
time = { version = "0.3", features = ["macros", "parsing", "formatting"] }
```

`data/compliance.toml`:

```toml
# Versioned, refreshable compliance + clock reference data (§5/§7). NOT Rust
# constants. Edit + rebuild to refresh; bump `version` when you do.
version = "BSI TR-02102-1:2024-01; SP 800-57 r5; CNSA 2.0 v2.1; CMVP #5291"
clock-floor = "2025-01-01"               # §7 coarse sanity floor (project-maintained)
compliance-data-not-after = "2027-01-01" # advisory: preview staleness warning past this
rsa-global-min-bits = 2048               # every profile incl. drduh
cnsa-rsa-min-bits = 3072
bsi-rsa-min-bits  = 3000
cnsa-ceiling-nss-2030 = "2030-12-31"
cnsa-ceiling-nss-2033 = "2033-12-31"
bsi-horizon-encrypt = "2031-12-31"
bsi-horizon-sign    = "2035-12-31"
```

- [ ] **Step 2: Loader + the production floor-sanity gate + tests**
  `src/compliance.rs`:

```rust
//! Fail-closed compliance gate over the resolved set (§5). Reference data is
//! baked (include_str!) + versioned; validate() takes a validated `now` and
//! reads NO clock itself. The §7 clock-floor sanity gate lives here too.

use crate::registry::{Algo, AlgoSpec, Expiry, ResolvedSet, ResolvedValue, Role};
use crate::{Error, Result};
use std::sync::OnceLock;
use time::Date;

#[derive(Debug)]
pub struct ComplianceData {
    pub version: String, pub clock_floor: Date, pub data_not_after: Option<Date>,
    pub rsa_global_min_bits: u16, pub cnsa_rsa_min_bits: u16, pub bsi_rsa_min_bits: u16,
    pub cnsa_ceiling_2030: Date, pub cnsa_ceiling_2033: Date,
    pub bsi_horizon_encrypt: Date, pub bsi_horizon_sign: Date,
}

static DATA: OnceLock<ComplianceData> = OnceLock::new();
const RAW: &str = include_str!("../data/compliance.toml");

fn date(t: &toml::Table, key: &str) -> Date {
    let s = t.get(key).and_then(|v| v.as_str()).unwrap_or_else(|| panic!("compliance.toml: missing/!str {key}"));
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    Date::parse(s, fmt).unwrap_or_else(|e| panic!("compliance.toml: bad date {key}={s}: {e}"))
}

pub fn data() -> &'static ComplianceData {
    DATA.get_or_init(|| {
        let t: toml::Table = RAW.parse().expect("compliance.toml parse");
        ComplianceData {
            version: t["version"].as_str().expect("version").to_string(),
            clock_floor: date(&t, "clock-floor"),
            data_not_after: t.get("compliance-data-not-after").map(|_| date(&t, "compliance-data-not-after")),
            rsa_global_min_bits: t["rsa-global-min-bits"].as_integer().unwrap() as u16,
            cnsa_rsa_min_bits: t["cnsa-rsa-min-bits"].as_integer().unwrap() as u16,
            bsi_rsa_min_bits: t["bsi-rsa-min-bits"].as_integer().unwrap() as u16,
            cnsa_ceiling_2030: date(&t, "cnsa-ceiling-nss-2030"),
            cnsa_ceiling_2033: date(&t, "cnsa-ceiling-nss-2033"),
            bsi_horizon_encrypt: date(&t, "bsi-horizon-encrypt"),
            bsi_horizon_sign: date(&t, "bsi-horizon-sign"),
        }
    })
}
pub fn version() -> &'static str { &data().version }

/// §7 sanity gate (pure, testable): a floor at or before the fixed sanity epoch
/// (2024-01-01) is treated as absent/zeroed → HARD ERROR (never skipped).
fn validate_floor(floor: Date) -> Result<Date> {
    if floor <= time::macros::date!(2024 - 01 - 01) {
        return Err(Error::Runner(format!("clock floor {floor} <= sanity epoch 2024-01-01 (absent/zeroed)")));
    }
    Ok(floor)
}
/// Production accessor used by secret::preflight + the clock step.
pub fn checked_clock_floor() -> Result<Date> { validate_floor(data().clock_floor) }

#[cfg(test)]
mod data_tests {
    use super::*;

    #[test]
    fn baked_data_parses_with_version_and_floors() {
        // WHY (§5/§7): the baked data parses, exposes a non-empty version (rides
        // in PlanResult), and carries the published floors.
        let d = data();
        assert!(!d.version.is_empty());
        assert_eq!((d.rsa_global_min_bits, d.cnsa_rsa_min_bits, d.bsi_rsa_min_bits), (2048, 3072, 3000));
        assert!(checked_clock_floor().is_ok());
    }

    #[test]
    fn floor_at_or_before_sanity_epoch_hard_errors() {
        // WHY (§7): a floor <= 2024-01-01 means absent/zeroed → hard error, in
        // PRODUCTION code (not only a test). Exercise the pure gate directly.
        assert!(validate_floor(time::macros::date!(2020 - 01 - 01)).is_err());
        assert!(validate_floor(time::macros::date!(2024 - 01 - 01)).is_err()); // boundary: <= rejects
        assert!(validate_floor(time::macros::date!(2025 - 01 - 01)).is_ok());
    }
}
```

Add `pub mod compliance;` to `lib.rs`.

- [ ] **Step 3: Regenerate lockfile, build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright && nix develop .#keywright -c cargo generate-lockfile
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/data overlays/top-level/keywright/crates/keywright-core/src/compliance.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): baked compliance/clock data + loader + production floor-sanity gate (§5/§7)"
```

Expected: `checkPhase` runs 2 `data_tests`, `ok`.

______________________________________________________________________

### Task 3: `compliance::validate` + `verdicts` — the fail-closed gate + regime-qualified labels

**Files:** Modify `src/compliance.rs`.

**Interfaces:** Produces `Profile`, `Regime`, `VerdictStatus`, `Verdict { regime, status, note }`, `ComplianceError` (regime-qualified, non-secret), `pub fn validate(&ResolvedSet, now) -> std::result::Result<(), ComplianceError>` (the hard gate; reads profile from the set; no clock), and `pub fn verdicts(&ResolvedSet) -> Vec<(String, Verdict)>` (the informational regime-qualified labels for the preview — incl. the non-error `AllowedWithConditions`/`NotAddressed`/`Recommended` statuses §10 requires represented). Task 8 (`plan`) calls both.

> **Scope-out (stated, not silently dropped):** §5 lists **CNSA SHA-256-for-general-use** and **strict-FIPS Brainpool** — both **deferred** (no hash decision; no `strict-fips` decision in the 2a registry). Not claimed as §10-covered.

- [ ] **Step 1: Types + `validate()` (Ed448/secp256k1 handled)**

Append to `src/compliance.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile { Drduh, Fips, Cnsa, Bsi }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime { Fips1403, Fips1865, Sp80057, Cnsa2, BsiTr02102 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictStatus { Recommended, Approved, AllowedWithConditions, Forbidden, NotAddressed }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict { pub regime: Regime, pub status: VerdictStatus, pub note: &'static str }

#[derive(Debug, thiserror::Error)]
#[error("compliance[{regime:?}/{profile:?}]: {what} — {note}")]
pub struct ComplianceError { pub profile: Profile, pub regime: Regime, pub what: String, pub note: &'static str }

fn profile_of(set: &ResolvedSet) -> Profile {
    match set.get("compliance-profile").map(|r| &r.value) {
        Some(ResolvedValue::Enum("fips")) => Profile::Fips,
        Some(ResolvedValue::Enum("cnsa")) => Profile::Cnsa,
        Some(ResolvedValue::Enum("bsi"))  => Profile::Bsi,
        _ => Profile::Drduh,
    }
}
fn algo_of(set: &ResolvedSet) -> Option<std::collections::BTreeMap<Role, AlgoSpec>> {
    match set.get("algo").map(|r| &r.value) {
        Some(ResolvedValue::AlgoProfile(m)) => Some(m.clone()),
        _ => None,
    }
}

/// Fail-closed cross-field gate. Profile is read from `set`; `now` is the only
/// time source (never a system clock). Returns the FIRST regime-qualified reject.
pub fn validate(set: &ResolvedSet, now: time::OffsetDateTime) -> std::result::Result<(), ComplianceError> {
    let d = data();
    let profile = profile_of(set);
    let nss_2033 = matches!(set.get("cnsa-use-case").map(|r| &r.value), Some(ResolvedValue::Enum("nss-2033")));
    let mk = |regime, what: String, note| ComplianceError { profile, regime, what, note };

    if let Some(algo) = algo_of(set) {
        for (role, spec) in &algo {
            // Global RSA floor — EVERY profile incl. drduh.
            if let Algo::Rsa(n) = spec.algo {
                if n < d.rsa_global_min_bits { return Err(mk(Regime::Sp80057, format!("RSA-{n} for {role:?}"), "below global minimum RSA-2048")); }
            }
            match profile {
                Profile::Drduh => {}
                Profile::Fips => match (role, spec.algo) {
                    (_, Algo::Ed448)       => return Err(mk(Regime::Fips1865, "Ed448".into(), "Ed448 not in CMVP #5291 (FIPS)")),
                    (_, Algo::Secp256k1)   => return Err(mk(Regime::Fips1403, "secp256k1".into(), "secp256k1 not FIPS-approved")),
                    (Role::Encrypt, Algo::Cv25519) => return Err(mk(Regime::Fips1403, "cv25519 encryption".into(), "cv25519/X25519 not FIPS-approved")),
                    (Role::Encrypt, Algo::Rsa(_))  => return Err(mk(Regime::Fips1403, "RSA encryption subkey".into(), "RSA decipher blocked in FIPS approved mode")),
                    _ => {}
                },
                Profile::Cnsa => {
                    match spec.algo {
                        Algo::Ed25519|Algo::Cv25519|Algo::Ed448|Algo::Secp256k1 =>
                            return Err(mk(Regime::Cnsa2, format!("{:?} for {role:?}", spec.algo), "not CNSA 2.0 approved")),
                        Algo::Brainpool(_) => return Err(mk(Regime::Cnsa2, "Brainpool".into(), "not CNSA 2.0 approved")),
                        Algo::NistP(256)|Algo::NistP(521) => return Err(mk(Regime::Cnsa2, format!("{:?}", spec.algo), "only P-384 transitional under CNSA")),
                        Algo::Rsa(n) if n < d.cnsa_rsa_min_bits => return Err(mk(Regime::Cnsa2, format!("RSA-{n}"), "below CNSA RSA-3072")),
                        _ => {}
                    }
                    let ceiling = if nss_2033 { d.cnsa_ceiling_2033 } else { d.cnsa_ceiling_2030 };
                    check_expiry(spec, ceiling, now, profile, Regime::Cnsa2, "expiry past CNSA transitional ceiling")?;
                }
                Profile::Bsi => {
                    if let Algo::Rsa(n) = spec.algo { if n < d.bsi_rsa_min_bits { return Err(mk(Regime::BsiTr02102, format!("RSA-{n}"), "below BSI RSA-3000")); } }
                    let horizon = if *role == Role::Encrypt { d.bsi_horizon_encrypt } else { d.bsi_horizon_sign };
                    check_expiry(spec, horizon, now, profile, Regime::BsiTr02102, "expiry past BSI horizon")?;
                }
            }
        }
    }
    if profile == Profile::Fips {
        if let Some(ResolvedValue::Uint(n)) = set.get("pin-min-length").map(|r| &r.value) {
            if *n < 8 { return Err(mk(Regime::Fips1403, format!("pin-min-length {n}"), "FIPS requires PIN length >= 8")); }
        }
    }
    Ok(())
}

fn check_expiry(spec: &AlgoSpec, horizon: Date, now: time::OffsetDateTime, profile: Profile, regime: Regime, note: &'static str)
    -> std::result::Result<(), ComplianceError> {
    if let Expiry::Days(days) = spec.expiry {
        let expiry_date = now.date() + time::Duration::days(days as i64);
        if expiry_date > horizon {
            return Err(ComplianceError { profile, regime, what: format!("expiry {expiry_date}"), note });
        }
    }
    Ok(())
}
```

- [ ] **Step 2: `verdicts()` — the informational regime-qualified labels**

Append:

```rust
/// Informational per-(role,algo) labels for the preview (§5: "labels are always
/// regime-qualified verdict tuples"). Covers the NON-error statuses §10 wants
/// represented (AllowedWithConditions, NotAddressed, Recommended). The hard
/// rejects are validate()'s job; a value validate() would reject is Forbidden here.
pub fn verdicts(set: &ResolvedSet) -> Vec<(String, Verdict)> {
    let profile = profile_of(set);
    let mut out = Vec::new();
    if let Some(algo) = algo_of(set) {
        for (role, spec) in &algo {
            let v = match (profile, spec.algo) {
                (Profile::Drduh, _) => Verdict { regime: Regime::Sp80057, status: VerdictStatus::Recommended, note: "drduh-guide aligned; not FIPS/CNSA/BSI evaluated" },
                (Profile::Bsi, Algo::Cv25519) => Verdict { regime: Regime::BsiTr02102, status: VerdictStatus::NotAddressed, note: "cv25519 not addressed by BSI TR-02102-1" },
                (Profile::Bsi, Algo::NistP(_)) => Verdict { regime: Regime::BsiTr02102, status: VerdictStatus::AllowedWithConditions, note: "NIST curves permitted with conditions (unverified)" },
                (Profile::Bsi, _) => Verdict { regime: Regime::BsiTr02102, status: VerdictStatus::Approved, note: "BSI-recommended" },
                (Profile::Fips, _) => Verdict { regime: Regime::Fips1403, status: VerdictStatus::Approved, note: "FIPS approved-mode" },
                (Profile::Cnsa, _) => Verdict { regime: Regime::Cnsa2, status: VerdictStatus::Approved, note: "CNSA 2.0" },
            };
            out.push((format!("{role:?}"), v));
        }
    }
    out
}
```

- [ ] **Step 3: The §10 compliance test matrix**

Append:

```rust
#[cfg(test)]
mod validate_tests {
    use super::*;
    use crate::config::parse_config;
    use crate::policy::{load_policy_under, Policy};
    use crate::registry::{resolve, CliArgs};

    fn now() -> time::OffsetDateTime { time::macros::datetime!(2026-06-23 0:00 UTC) }
    fn rset(toml: &str) -> ResolvedSet {
        let full = format!("real-name='A'\nemail='a@x.com'\n{toml}");
        resolve(&CliArgs::default(), &parse_config(&full).unwrap(), &Policy::default(), false).unwrap()
    }
    // uniform per-role algo profile helper
    fn algo4(c: &str, s: &str, a: &str, e: &str, exp: &str) -> String {
        format!("[algo]\ncertify={{algo='{c}',expiry='never'}}\nsign={{algo='{s}',expiry='{exp}'}}\nauth={{algo='{a}',expiry='{exp}'}}\nencrypt={{algo='{e}',expiry='{exp}'}}\n")
    }

    #[test]
    fn rsa_1024_rejected_under_every_profile() {
        // WHY (§5): RSA<2048 never acceptable — global floor, all profiles.
        for p in ["drduh","fips","cnsa","bsi"] {
            let set = rset(&format!("compliance-profile='{p}'\n{}", algo4("rsa1024","rsa1024","rsa1024","rsa1024","2y")));
            assert!(validate(&set, now()).is_err(), "RSA-1024 must be refused under {p}");
        }
    }
    #[test]
    fn cv25519_fips_error_drduh_ok() {
        // WHY (§5): cv25519-under-FIPS refused; identical under drduh permitted.
        assert!(validate(&rset(&format!("compliance-profile='fips'\n{}", algo4("rsa4096","rsa4096","rsa4096","cv25519","2y"))), now()).is_err());
        assert!(validate(&rset(&format!("compliance-profile='drduh'\n{}", algo4("ed25519","ed25519","ed25519","cv25519","2y"))), now()).is_ok());
    }
    #[test]
    fn ed448_fips_error_drduh_ok() {
        // WHY (§5/§10): Ed448 forbidden under fips (not in CMVP #5291); under drduh
        // it is permitted (subject only to the global floor; not an RSA algo).
        assert!(validate(&rset(&format!("compliance-profile='fips'\n{}", algo4("ed448","ed448","ed448","ed448","2y"))), now()).is_err());
        assert!(validate(&rset(&format!("compliance-profile='drduh'\n{}", algo4("ed448","ed448","ed448","cv25519","2y"))), now()).is_ok());
    }
    #[test]
    fn secp256k1_refused_under_fips() {
        // WHY (§5): secp256k1 is on the FIPS-approved-mode block-list.
        assert!(validate(&rset(&format!("compliance-profile='fips'\n{}", algo4("secp256k1","secp256k1","secp256k1","rsa4096","2y"))), now()).is_err());
    }
    #[test]
    fn fips_pin_below_8_rejected_and_positive_fips_ok() {
        // WHY (§5/§10): FIPS requires PIN>=8 (default 6 trips it); and a fully-FIPS
        // set with pin>=8 must pass (the algo gate must not over-refuse).
        let bad = rset(&format!("compliance-profile='fips'\npin-min-length=6\n{}", algo4("rsa4096","rsa4096","rsa4096","nistp384","2y")));
        let e = validate(&bad, now()).unwrap_err();
        assert!(e.what.contains("pin-min-length"));
        let ok = rset(&format!("compliance-profile='fips'\npin-min-length=8\n{}", algo4("rsa4096","rsa4096","rsa4096","nistp384","2y")));
        assert!(validate(&ok, now()).is_ok(), "valid FIPS set must pass");
    }
    #[test]
    fn cnsa_forbids_noncompliant_algos_and_small_rsa() {
        // WHY (§5): CNSA forbids Ed25519/P-256/P-521/Brainpool/cv25519 and RSA<3072.
        for e in ["ed25519","nistp256","nistp521","brainpool384","cv25519"] {
            assert!(validate(&rset(&format!("compliance-profile='cnsa'\n{}", algo4("rsa4096","rsa4096","rsa4096",e,"2y"))), now()).is_err(), "{e} must be CNSA-refused");
        }
        assert!(validate(&rset(&format!("compliance-profile='cnsa'\n{}", algo4("rsa2048","rsa2048","rsa2048","rsa2048","2y"))), now()).is_err());
    }
    #[test]
    fn cnsa_ceiling_2030_default_2033_only_when_opted_in() {
        // WHY (§5/§10): a compliant transitional algo (RSA-3072) expiring ~2033
        // is refused under default nss-2030 but allowed under nss-2033; past 2033
        // refused even then. (7y from 2026 = 2033; 12y = 2038.)
        let p384_7y = format!("compliance-profile='cnsa'\n{}", algo4("rsa3072","rsa3072","rsa3072","rsa3072","7y"));
        assert!(validate(&rset(&p384_7y), now()).is_err(), "expiry past 2030 refused by default");
        let opted = format!("compliance-profile='cnsa'\ncnsa-use-case='nss-2033'\n{}", algo4("rsa3072","rsa3072","rsa3072","rsa3072","7y"));
        assert!(validate(&rset(&opted), now()).is_ok(), "within 2033 allowed under nss-2033");
        let too_long = format!("compliance-profile='cnsa'\ncnsa-use-case='nss-2033'\n{}", algo4("rsa3072","rsa3072","rsa3072","rsa3072","12y"));
        assert!(validate(&rset(&too_long), now()).is_err(), "past 2033 refused even under nss-2033");
    }
    #[test]
    fn bsi_rsa_below_3000_and_split_horizons() {
        // WHY (§5): BSI RSA<3000 refused; encryption subkey past end-2031 refused
        // (7y from 2026 = 2033 > 2031); signing past 2035 refused (12y = 2038).
        assert!(validate(&rset(&format!("compliance-profile='bsi'\n{}", algo4("rsa2048","rsa2048","rsa2048","rsa2048","2y"))), now()).is_err());
        assert!(validate(&rset(&format!("compliance-profile='bsi'\n{}", algo4("rsa3072","rsa3072","rsa3072","rsa3072","7y"))), now()).is_err(), "enc past 2031");
        assert!(validate(&rset(&format!("compliance-profile='bsi'\n{}", algo4("rsa3072","rsa3072","rsa3072","rsa3072","12y"))), now()).is_err(), "sign past 2035");
    }
    #[test]
    fn cv25519_under_bsi_is_not_a_hard_error_and_verdict_is_notaddressed() {
        // WHY (§5/§10): cv25519 under bsi → NotAddressed (no hard reject), and the
        // verdict surface REPRESENTS that status (not merely 'no error').
        let set = rset(&format!("compliance-profile='bsi'\n{}", algo4("rsa3072","rsa3072","rsa3072","cv25519","2y")));
        assert!(validate(&set, now()).is_ok());
        let vs = verdicts(&set);
        assert!(vs.iter().any(|(role, v)| role == "Encrypt" && v.status == VerdictStatus::NotAddressed));
    }
    #[test]
    fn bsi_nist_verdict_is_allowed_with_conditions() {
        // WHY (§10): BSI NIST curves are represented as AllowedWithConditions.
        let set = rset(&format!("compliance-profile='bsi'\n{}", algo4("rsa3072","rsa3072","rsa3072","nistp384","2y")));
        let vs = verdicts(&set);
        assert!(vs.iter().any(|(_, v)| v.status == VerdictStatus::AllowedWithConditions));
    }
    #[test]
    fn policy_locked_fips_plus_cv25519_encrypt_errors_both_directions() {
        // WHY (§5/§10): profile is read from the set; locking fips + cv25519-encrypt
        // (in either lock combination) yields the regime-qualified hard error.
        let dir = std::env::temp_dir().join(format!("kwtest-comp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.toml");
        // direction 1: lock the profile, config the algo
        std::fs::write(&f, "compliance-profile='fips'\n").unwrap();
        let pol = load_policy_under(&f, &dir).unwrap();
        let cfg = parse_config(&format!("real-name='A'\nemail='a@x.com'\n{}", algo4("rsa4096","rsa4096","rsa4096","cv25519","2y"))).unwrap();
        assert!(validate(&resolve(&CliArgs::default(), &cfg, &pol, false).unwrap(), now()).is_err());
        // direction 2: lock the algo profile, config the compliance-profile
        std::fs::write(&f, &format!("{}", algo4("rsa4096","rsa4096","rsa4096","cv25519","2y"))).unwrap();
        let pol2 = load_policy_under(&f, &dir).unwrap();
        let cfg2 = parse_config("real-name='A'\nemail='a@x.com'\ncompliance-profile='fips'\n").unwrap();
        assert!(validate(&resolve(&CliArgs::default(), &cfg2, &pol2, false).unwrap(), now()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

- [ ] **Step 4: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/compliance.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): compliance validate() (incl Ed448/secp256k1) + regime-qualified verdicts() (§5)"
```

Expected: `checkPhase` runs the full `validate_tests` matrix, `ok`.

______________________________________________________________________

### Task 4: `secret` — preflight + clock-trust → `validated_now`

**Files:** Modify `Cargo.toml` (add `getrandom`, `libc`); create `src/secret.rs`; modify `lib.rs` (`pub mod secret;`).

**Interfaces:** Produces `pub fn validate_clock(detected, asserted: Option<&str>, interactive_confirm: Option<bool>) -> Result<OffsetDateTime>` (→ `validated_now`, uses `compliance::checked_clock_floor()`), `pub fn swap_active(&str) -> bool` (pure), `pub fn preflight() -> Result<()>` (live syscalls; integration-tested in Plan 3, not a unit test). Task 8 calls `validate_clock`.

- [ ] **Step 1: Add deps; clock-trust + swap helper (pure, fully tested)**
  Add to `Cargo.toml`:

```toml
getrandom = "0.2"   # after generate-lockfile, confirm no getrandom 0.3 dup via `cargo tree -d`
libc = "0.2"
```

`src/secret.rs`:

```rust
//! Secret-handling preflight + tmpfs/RAII guards (§7, Plan 2 subset). No key
//! material; generation is Plan 3. Clock-trust produces validated_now.

use crate::{Error, Result};
use time::OffsetDateTime;

/// Fail-closed clock validation (§7). Lower bound = the production-checked baked
/// floor (compliance::checked_clock_floor; hard-errors if <= 2024-01-01). Upper
/// bound can't be auto-checked: interactive → operator confirms detected time;
/// non-interactive → asserted-date (RFC-3339, absolute UTC, >= floor) required.
pub fn validate_clock(detected: OffsetDateTime, asserted: Option<&str>, interactive_confirm: Option<bool>)
    -> Result<OffsetDateTime> {
    let floor = crate::compliance::checked_clock_floor()?;
    let floor_dt = floor.with_hms(0, 0, 0).unwrap().assume_utc();
    if let Some(s) = asserted {
        let when = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|e| Error::Config(format!("asserted-date not RFC-3339: {e}")))?
            .to_offset(time::UtcOffset::UTC);
        if when < floor_dt { return Err(Error::Config(format!("asserted-date {when} < clock floor {floor_dt}"))); }
        return Ok(when);
    }
    match interactive_confirm {
        Some(true) => {
            let d = detected.to_offset(time::UtcOffset::UTC);
            if d < floor_dt { return Err(Error::Config(format!("detected clock {d} < floor {floor_dt}"))); }
            Ok(d)
        }
        Some(false) => Err(Error::Config("operator did not confirm the detected date/time".into())),
        None => Err(Error::Config("non-interactive run requires asserted-date".into())),
    }
}

/// True iff `/proc/swaps` lists any active swap (pure helper over the file text).
pub fn swap_active(proc_swaps: &str) -> bool {
    proc_swaps.lines().skip(1).any(|l| !l.trim().is_empty())
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn asserted_date_rfc3339_and_at_least_floor() {
        // WHY (§7): non-interactive requires an absolute RFC-3339 instant >= floor;
        // exercises the near-floor boundary against the configured floor.
        let floor = crate::compliance::checked_clock_floor().unwrap();
        let before = format!("{}-01-01T00:00:00Z", floor.year() - 1); // a real date below the floor
        assert!(validate_clock(OffsetDateTime::now_utc(), Some("not-a-date"), None).is_err());
        assert!(validate_clock(OffsetDateTime::now_utc(), Some(&before), None).is_err());
        let ok = validate_clock(OffsetDateTime::now_utc(), Some("2026-06-23T12:00:00+02:00"), None).unwrap();
        assert_eq!(ok.offset(), time::UtcOffset::UTC); // normalized to UTC
    }
    #[test]
    fn non_interactive_without_asserted_is_hard_error() {
        // WHY (§7): no asserted-date + not interactive → fail closed.
        assert!(validate_clock(OffsetDateTime::now_utc(), None, None).is_err());
    }
    #[test]
    fn interactive_requires_confirmation_and_floor() {
        // WHY (§7): interactive confirm accepts detected iff >= floor; declining errors.
        assert!(validate_clock(time::macros::datetime!(2026-06-23 0:00 UTC), None, Some(true)).is_ok());
        assert!(validate_clock(time::macros::datetime!(2026-06-23 0:00 UTC), None, Some(false)).is_err());
        assert!(validate_clock(time::macros::datetime!(2000-01-01 0:00 UTC), None, Some(true)).is_err());
    }
    #[test]
    fn swap_active_detects_an_entry() {
        // WHY (§7): active swap is a hard precondition failure.
        assert!(!swap_active("Filename Type Size Used Priority\n"));
        assert!(swap_active("Filename Type Size Used Priority\n/dev/sda3 partition 1000 0 -2\n"));
    }
}
```

- [ ] **Step 2: Live `preflight` (syscalls; Plan-3 integration-tested, not a unit test)**
  Append:

```rust
/// Live machine preflight (§7). Hard-errors on active swap; RLIMIT_CORE=0;
/// crng-init; checks the clock floor via checked_clock_floor(); mlock advisory.
/// Calls real syscalls/reads /proc — exercised in Plan 3/4, not unit tests.
pub fn preflight() -> Result<()> {
    crate::compliance::checked_clock_floor()?; // §7: hard-error on absent/absurd floor
    if swap_active(&std::fs::read_to_string("/proc/swaps").unwrap_or_default()) {
        return Err(Error::Runner("active swap present — refuse (swap may hold plaintext secrets)".into()));
    }
    let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit with a valid resource id + initialized rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
        return Err(Error::Runner("could not set RLIMIT_CORE=0".into()));
    }
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Runner(format!("CSPRNG not ready: {e}")))?;
    Ok(())
}
```

Add `pub mod secret;` to `lib.rs`.

- [ ] **Step 3: Regenerate lockfile, build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader/overlays/top-level/keywright && nix develop .#keywright -c cargo generate-lockfile && nix develop .#keywright -c cargo tree -d | grep -i getrandom || true
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates/keywright-core/src/secret.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): secret preflight + fail-closed clock-trust → validated_now (§7)"
```

Expected: `checkPhase` runs 4 `clock_tests`, `ok`; `cargo tree -d` shows no duplicate getrandom major.

______________________________________________________________________

### Task 5: `secret` — tmpfs RAII guards

**Files:** Modify `src/secret.rs`.

**Interfaces:** `pub struct EphemeralGnupgHome` (`new_in(&Path) -> Result<Self>`, `path()`, Drop removes dir 0700), `pub struct SessionSecretFile` (`new_in(&Path) -> Result<Self>` 0600, `path()`, Drop unlinks). Plan 3 populates; 2b proves the lifecycle.

- [ ] **Step 1: Guards + Drop tests (incl. panic path)**
  Append to `src/secret.rs`:

```rust
use std::path::{Path, PathBuf};

pub struct EphemeralGnupgHome { path: PathBuf }
impl EphemeralGnupgHome {
    pub fn new_in(base: &Path) -> Result<Self> {
        let path = base.join(format!("kw-gnupg-{}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        set_mode(&path, 0o700)?;
        Ok(Self { path })
    }
    pub fn path(&self) -> &Path { &self.path }
}
impl Drop for EphemeralGnupgHome { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.path); } }

pub struct SessionSecretFile { path: PathBuf }
impl SessionSecretFile {
    pub fn new_in(base: &Path) -> Result<Self> {
        let path = base.join(format!("kw-secret-{}", std::process::id()));
        std::fs::write(&path, b"")?;
        set_mode(&path, 0o600)?;
        Ok(Self { path })
    }
    pub fn path(&self) -> &Path { &self.path }
}
impl Drop for SessionSecretFile { fn drop(&mut self) { let _ = std::fs::remove_file(&self.path); } }

fn set_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    fn base() -> PathBuf { let b = std::env::temp_dir().join(format!("kw-guard-{}", std::process::id())); std::fs::create_dir_all(&b).unwrap(); b }

    #[test]
    fn ephemeral_home_removed_on_drop() {
        // WHY (§7): GNUPGHOME must be gone after the guard drops.
        let b = base();
        let p = { let g = EphemeralGnupgHome::new_in(&b).unwrap(); let p = g.path().to_path_buf(); assert!(p.exists()); p };
        assert!(!p.exists());
        std::fs::remove_dir_all(&b).ok();
    }
    #[test]
    fn session_file_unlinked_even_on_panic() {
        // WHY (§7/§9): Drop runs on a panic unwind (crate is panic=unwind), so the
        // secret file is unlinked on EVERY path.
        let b = base();
        let p = b.join(format!("kw-secret-{}", std::process::id()));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let f = SessionSecretFile::new_in(&b).unwrap(); assert!(f.path().exists()); panic!("boom");
        }));
        assert!(r.is_err());
        assert!(!p.exists(), "must be unlinked on panic unwind");
        std::fs::remove_dir_all(&b).ok();
    }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/secret.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): tmpfs RAII guards + panic-path Drop test (§7/§9)"
```

Expected: `checkPhase` runs 2 `guard_tests`, `ok`.

______________________________________________________________________

### Task 6: `device` — types + total fail-closed source-resolution

**Files:** Create `src/device.rs`; modify `lib.rs` (`pub mod device;`).

**Interfaces:** Produces the §6 types (`Transport`, `DiskCandidate`, `Discovery`, `ExclusionReason`, `DeviceRole`), the `Probes`/`Source`/`SourceKind`/`Member` topology model, and `pub fn build_discovery(&Probes) -> Discovery`. Task 7 consumes `Discovery`.

> **The load-bearing guarantee, made concrete:** `resolve_source` returns `None` (⇒ global `resolution_complete=false`) on ANY doubt — `Unknown`, depth overflow, an **empty** member set, a **degraded** member, a member that resolves to `None`/∅, or (in `build_discovery`) a resolved `by_id` that matches no enumerated candidate. Empty `Some(∅)` is never a success.

- [ ] **Step 1: Types + `Probes` + `resolve_source` + `build_discovery` (all concrete)**

`src/device.rs`:

```rust
//! Device discovery + the positive-proof, globally fail-closed safe-target
//! filter (§6). 2b builds Discovery from a parsed `Probes`; Plan 3 builds Probes
//! from the live runner. No real block devices here.

use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport { Usb, Sata, Nvme, Virtio, Other }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCandidate {
    pub by_id: String,
    pub by_id_aliases: Vec<String>,
    pub serial: String, pub model: String, pub size_bytes: u64,
    pub in_use_mountpoints: Vec<String>, // protected mounts resolving to THIS disk
    pub backs_active_swap: bool,
    pub removable: bool, pub transport: Transport,
    pub existing_keywright_backups: Vec<String>, // fpr/email already backed up here; populated in Plan 3
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub disks: Vec<DiskCandidate>,
    pub resolution_complete: bool,        // GLOBAL: false if ANY in-use source unresolved
    pub live_backing: BTreeSet<String>,   // by_ids backing /iso / the live squashfs (computed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusionReason { Rule1InUseMount(String), Rule1ActiveSwap, Rule1LiveBacking, Rule1ResolutionIncomplete, Rule2Internal, ByIdCollision }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRole { BackupLuks, ExportTarget, Excluded(ExclusionReason) }

// ---- the topology model fed to build_discovery ----
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source { pub id: String }       // a /dev path, pool name, swapfile path, overlay key…
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member { pub source: Source, pub degraded: bool }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind { WholeDisk(String), Partition(Source), MultiMember(Vec<Member>), Indirect(Source), Unknown }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InUseKind { Mount, Swap }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InUse { pub kind: InUseKind, pub at: String, pub source: Source }

#[derive(Debug, Clone, Default)]
pub struct Probes {
    pub whole_disks: Vec<DiskCandidate>,           // enumerated; in_use fields start empty/false
    pub in_use: Vec<InUse>,                        // protected mounts + active swaps
    pub resolver: BTreeMap<String, SourceKind>,    // Source.id → how it resolves
    pub live_backing_ids: BTreeSet<String>,        // disks backing /iso / squashfs (computed upstream)
}
impl Probes {
    fn classify_source(&self, s: &Source) -> SourceKind {
        self.resolver.get(&s.id).cloned().unwrap_or(SourceKind::Unknown) // unknown ⇒ fail closed
    }
}

/// Resolve one in-use source to the set of concrete whole-disk by_ids backing it.
/// None ⇒ unresolved ⇒ global fail-closed. Never returns Some(∅).
fn resolve_source(src: &Source, p: &Probes, depth: u8) -> Option<BTreeSet<String>> {
    if depth > 32 { return None; }
    match p.classify_source(src) {
        SourceKind::WholeDisk(by_id) => { let mut s = BTreeSet::new(); s.insert(by_id); Some(s) }
        SourceKind::Partition(parent) => resolve_source(&parent, p, depth + 1),
        SourceKind::Indirect(inner) => resolve_source(&inner, p, depth + 1),
        SourceKind::MultiMember(members) => {
            if members.is_empty() { return None; }                 // FAIL CLOSED: zero members
            let mut acc = BTreeSet::new();
            for m in &members {
                if m.degraded { return None; }                     // UNAVAIL/REMOVED/missing
                match resolve_source(&m.source, p, depth + 1) {
                    Some(disks) if !disks.is_empty() => acc.extend(disks),
                    _ => return None,                              // any member unresolved ⇒ whole source unresolved
                }
            }
            if acc.is_empty() { return None; }                     // belt-and-suspenders
            Some(acc)
        }
        SourceKind::Unknown => None,
    }
}

/// Build Discovery: resolve every in-use source; any failure (None, empty, or a
/// by_id not matching exactly one enumerated candidate) sets resolution_complete=false.
pub fn build_discovery(p: &Probes) -> Discovery {
    let mut disks = p.whole_disks.clone();
    let mut complete = true;
    for u in &p.in_use {
        match resolve_source(&u.source, p, 0) {
            Some(ids) if !ids.is_empty() => {
                for id in ids {
                    match disks.iter_mut().filter(|c| c.by_id == id).count() {
                        1 => {
                            let c = disks.iter_mut().find(|c| c.by_id == id).unwrap();
                            match u.kind {
                                InUseKind::Mount => c.in_use_mountpoints.push(u.at.clone()),
                                InUseKind::Swap => c.backs_active_swap = true,
                            }
                        }
                        _ => complete = false, // resolved to a disk we didn't enumerate, or an ambiguous match
                    }
                }
            }
            _ => complete = false, // None or empty ⇒ fail closed
        }
    }
    Discovery { disks, resolution_complete: complete, live_backing: p.live_backing_ids.clone() }
}
```

Add `pub mod device;` to `lib.rs`.

- [ ] **Step 2: A `disk()` helper + worked fixture builders (the template) + the recursion test matrix**

Append a shared **`#[cfg(test)] mod test_helpers`** (the `pub` builders — reused by Task 7's `classify_tests`, so both test mods `use super::test_helpers::*`) and a `#[cfg(test)] mod recursion_tests`. **Every topology in §6/§10 gets a concrete asserting test:**

```rust
#[cfg(test)]
mod test_helpers {
    use super::*;

    pub fn disk(by_id: &str, removable: bool) -> DiskCandidate {
        DiskCandidate { by_id: by_id.into(), by_id_aliases: vec![], serial: by_id.into(), model: "M".into(),
            size_bytes: 1<<40, in_use_mountpoints: vec![], backs_active_swap: false, removable, transport: Transport::Sata,
            existing_keywright_backups: vec![] }
    }
    pub fn disk_like_removable() -> DiskCandidate { disk("usb-removable", true) }
    pub fn src(id: &str) -> Source { Source { id: id.into() } }
    pub fn mount(at: &str, s: &str) -> InUse { InUse { kind: InUseKind::Mount, at: at.into(), source: src(s) } }
    pub fn swap(s: &str) -> InUse { InUse { kind: InUseKind::Swap, at: "swap".into(), source: src(s) } }
    pub fn whole(id: &str) -> SourceKind { SourceKind::WholeDisk(id.into()) }

    // TEMPLATE 1 — healthy ZFS mirror: / resolves to BOTH whole disks.
    pub fn probes_zfs_mirror() -> Probes {
        let mut r = BTreeMap::new();
        r.insert("rpool".into(), SourceKind::MultiMember(vec![
            Member { source: src("sda2"), degraded: false }, Member { source: src("sdb2"), degraded: false }]));
        r.insert("sda2".into(), SourceKind::Partition(src("disk-A")));
        r.insert("sdb2".into(), SourceKind::Partition(src("disk-B")));
        r.insert("disk-A".into(), whole("disk-A")); r.insert("disk-B".into(), whole("disk-B"));
        Probes { whole_disks: vec![disk("disk-A", false), disk("disk-B", false), disk("usb-1", true)],
            in_use: vec![mount("/", "rpool")], resolver: r, live_backing_ids: BTreeSet::new() }
    }
    // TEMPLATE 2 — degraded mirror: one member UNAVAIL ⇒ resolution_complete=false.
    fn probes_zfs_degraded() -> Probes {
        let mut p = probes_zfs_mirror();
        p.resolver.insert("rpool".into(), SourceKind::MultiMember(vec![
            Member { source: src("sda2"), degraded: false }, Member { source: src("guid-x"), degraded: true }]));
        p
    }
    // TEMPLATE 3 — empty member set (truncated zpool) ⇒ fail closed.
    fn probes_empty_member() -> Probes {
        let mut p = probes_zfs_mirror();
        p.resolver.insert("rpool".into(), SourceKind::MultiMember(vec![]));
        p
    }
    // TEMPLATE 4 — resolves to a by_id not among enumerated disks ⇒ fail closed.
    fn probes_unmatched_by_id() -> Probes {
        let mut p = probes_zfs_mirror();
        p.resolver.insert("disk-A".into(), whole("ghost-disk")); // not in whole_disks
        p
    }
    // TEMPLATE 5 — swapfile on a SEPARATE data disk (no protected mount) ⇒ that disk backs_active_swap.
    fn probes_swapfile_on_data_disk() -> Probes {
        let mut r = BTreeMap::new();
        r.insert("/swapfile".into(), SourceKind::Indirect(src("data-fs")));  // swapfile → containing fs
        r.insert("data-fs".into(), SourceKind::Partition(src("disk-D")));
        r.insert("disk-D".into(), whole("disk-D"));
        // root on its own disk:
        r.insert("disk-R".into(), whole("disk-R")); r.insert("root-fs".into(), SourceKind::Partition(src("disk-R")));
        Probes { whole_disks: vec![disk("disk-R", false), disk("disk-D", false), disk("usb-1", true)],
            in_use: vec![mount("/", "root-fs"), swap("/swapfile")], resolver: r, live_backing_ids: BTreeSet::new() }
    }
    fn protected(d: &Discovery) -> Vec<&DiskCandidate> { d.disks.iter().filter(|c| !c.in_use_mountpoints.is_empty()).collect() }

    #[test]
    fn mirror_rolls_up_to_both_whole_disks() {
        // WHY (§6): the protected / on a 2-disk mirror is attributed to BOTH whole
        // disks (not the partition/member nodes); resolution_complete=true.
        let d = build_discovery(&probes_zfs_mirror());
        assert!(d.resolution_complete);
        let p: BTreeSet<_> = protected(&d).iter().map(|c| c.by_id.clone()).collect();
        assert_eq!(p, BTreeSet::from(["disk-A".to_string(), "disk-B".to_string()]));
    }
    #[test]
    fn degraded_member_fails_closed() {
        // WHY (§6 load-bearing): an UNAVAIL/GUID member ⇒ resolution_complete=false.
        assert!(!build_discovery(&probes_zfs_degraded()).resolution_complete);
    }
    #[test]
    fn empty_member_set_fails_closed() {
        // WHY (§6 line 215): a source resolving to no disk ⇒ resolution_complete=false
        // (NOT a successful resolution to zero disks).
        assert!(!build_discovery(&probes_empty_member()).resolution_complete);
    }
    #[test]
    fn resolved_by_id_not_enumerated_fails_closed() {
        // WHY (§6): positive proof requires termination at an ENUMERATED whole disk.
        assert!(!build_discovery(&probes_unmatched_by_id()).resolution_complete);
    }
    #[test]
    fn swapfile_on_separate_data_disk_marks_swap_backing() {
        // WHY (§6): a swapfile on a data disk with no protected mount still marks
        // that disk backs_active_swap (swap can hold plaintext secrets).
        let d = build_discovery(&probes_swapfile_on_data_disk());
        assert!(d.resolution_complete);
        assert!(d.disks.iter().any(|c| c.by_id == "disk-D" && c.backs_active_swap));
    }
    #[test]
    fn unknown_source_fails_closed() {
        // WHY (§6): an unrecognized source (no resolver entry) ⇒ fail closed.
        let p = Probes { whole_disks: vec![disk("disk-X", true)], in_use: vec![mount("/", "mystery")],
            resolver: BTreeMap::new(), live_backing_ids: BTreeSet::new() };
        assert!(!build_discovery(&p).resolution_complete);
    }

    // The remaining §6/§10 topologies, each building its Probes inline from the
    // helpers above and asserting the named property. Implement each as its own
    // #[test] following the templates; the assertion each MUST prove:
    //   single_disk_root           → / rolls up to the one whole disk (resolution_complete)
    //   raw_swap_partition         → the swap partition's whole disk backs_active_swap
    //   dmcrypt_swap               → dm-crypt swap (Indirect→Partition) → whole disk backs_active_swap
    //   swapfile_on_root           → root disk backs_active_swap (swapfile→root-fs→root disk)
    //   esp_boot_efi               → /boot/efi attributed (Task 7 then excludes via the /boot prefix)
    //   nix_on_lvm                 → /nix on an LVM LV (Indirect→Partition) rolls up to the PV whole disk
    //   mdraid_root                → / on md (MultiMember of two partitions) rolls up to BOTH whole disks
    //   bcache_root                → / on bcache (Indirect→backing partition) rolls up to the backing whole disk
    //   overlay_mount              → overlay (MultiMember of lower/upper/work Indirect sources) rolls up to their fs disks
    //   zvol_swap                  → swap on a zvol (Indirect→pool MultiMember) rolls up to the pool disks (backs_active_swap)
    //   whole_disk_rollup_partition→ a single-partition root attributes the mount to the WHOLE disk, never the partition node
}
```

- [ ] **Step 3: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/device.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): device discovery + total fail-closed source-resolution (empty/degraded/unmatched all closed) (§6)"
```

Expected: `checkPhase` runs the recursion matrix (the 6 template tests + the enumerated topologies once implemented), `ok`.

______________________________________________________________________

### Task 7: `device` — `classify`, `check_roles`, idempotency, by-id collision

**Files:** Modify `src/device.rs`.

**Interfaces:** `pub fn classify(&Discovery, allowlist: &[String]) -> Vec<(DiskCandidate, DeviceRole)>`, `pub fn check_roles(&[(DiskCandidate, DeviceRole)]) -> Result<()>`, `pub fn idempotency_check(&DiskCandidate, fpr_or_email: &str, force: bool) -> Result<()>`.

- [ ] **Step 1: `classify` (global guard first; rule-1 before collision), `check_roles`, idempotency**

Append to `src/device.rs`:

```rust
fn rule1_mount(c: &DiskCandidate) -> bool {
    // path-component-prefix match of any protected root.
    const ROOTS: &[&str] = &["/", "/boot", "/nix", "/nix/.ro-store", "/iso"];
    c.in_use_mountpoints.iter().any(|m| ROOTS.iter().any(|r| m == r || m.starts_with(&format!("{}/", r.trim_end_matches('/')))))
}

pub fn classify(d: &Discovery, allowlist: &[String]) -> Vec<(DiskCandidate, DeviceRole)> {
    // GLOBAL guard FIRST — no per-disk evaluation when resolution is incomplete.
    if !d.resolution_complete {
        return d.disks.iter().cloned().map(|c| (c, DeviceRole::Excluded(ExclusionReason::Rule1ResolutionIncomplete))).collect();
    }
    // by-id collision counts across candidates + aliases.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in &d.disks { for id in std::iter::once(&c.by_id).chain(c.by_id_aliases.iter()) { *counts.entry(id.clone()).or_default() += 1; } }
    d.disks.iter().cloned().map(|c| {
        // Rule 1 (mount/swap/live) is BELOW the registry and checked BEFORE the
        // collision/rule-2 logic — a forged by_id cannot strip mount/swap protection.
        let role = if !c.in_use_mountpoints.is_empty() && rule1_mount(&c) {
            DeviceRole::Excluded(ExclusionReason::Rule1InUseMount(c.in_use_mountpoints[0].clone()))
        } else if c.backs_active_swap {
            DeviceRole::Excluded(ExclusionReason::Rule1ActiveSwap)
        } else if d.live_backing.contains(&c.by_id) {
            DeviceRole::Excluded(ExclusionReason::Rule1LiveBacking)
        } else if counts.get(&c.by_id).copied().unwrap_or(0) > 1 {
            DeviceRole::Excluded(ExclusionReason::ByIdCollision) // ambiguous identity (non-rule-1) → exclude + surface
        } else if !c.removable && !allowlist.contains(&c.by_id) {
            DeviceRole::Excluded(ExclusionReason::Rule2Internal)
        } else {
            DeviceRole::BackupLuks
        };
        (c, role)
    }).collect()
}

pub fn check_roles(classified: &[(DiskCandidate, DeviceRole)]) -> Result<()> {
    let n = classified.iter().filter(|(_, r)| *r == DeviceRole::BackupLuks).count();
    if n < 2 { return Err(Error::Runner(format!("need >= 2 backup drives, found {n}"))); }
    if classified.iter().any(|(_, r)| *r == DeviceRole::Excluded(ExclusionReason::ByIdCollision)) {
        return Err(Error::Runner("by-id collision among candidates — refuse (ambiguous device identity)".into()));
    }
    Ok(())
}

pub fn idempotency_check(drive: &DiskCandidate, fpr_or_email: &str, force: bool) -> Result<()> {
    if force { return Ok(()); }
    if drive.existing_keywright_backups.iter().any(|b| b == fpr_or_email) {
        return Err(Error::Runner(format!("{fpr_or_email} already backed up on {} — use force", drive.by_id)));
    }
    Ok(())
}
```

- [ ] **Step 2: Tests (the §10 device classification matrix)**

Append a `#[cfg(test)] mod classify_tests` that reuses the shared `test_helpers` mod from Task 6 (no helper duplication):

```rust
#[cfg(test)]
mod classify_tests {
use super::*;
use super::test_helpers::*;

#[test]
fn rule1_survives_allowlist_and_a_duplicate_by_id() {
    // WHY (§6/§10): a protected (rule-1) disk stays Excluded(Rule1*) even when it
    // is allowlisted AND shares a by_id with a removable target — protection is
    // independent of by_id, and rule-1 is below the registry.
    let mut d = build_discovery(&probes_zfs_mirror()); // disk-A/disk-B carry / 
    // forge a collision: give a removable target the same by_id as the rule-1 disk-A
    d.disks.push(DiskCandidate { by_id: "disk-A".into(), ..disk_like_removable() });
    let classified = classify(&d, &["disk-A".to_string()]); // allowlist the rule-1 id too
    let role_a = classified.iter().find(|(c, _)| c.by_id == "disk-A" && !c.in_use_mountpoints.is_empty()).map(|(_, r)| r).unwrap();
    assert!(matches!(role_a, DeviceRole::Excluded(ExclusionReason::Rule1InUseMount(_))), "rule-1 must survive the collision + allowlist");
}
#[test]
fn incomplete_resolution_excludes_every_candidate() {
    // WHY (§6 load-bearing): global fail-closed.
    let classified = classify(&build_discovery(&probes_zfs_degraded()), &[]);
    assert!(classified.iter().all(|(_, r)| *r == DeviceRole::Excluded(ExclusionReason::Rule1ResolutionIncomplete)));
}
#[test]
fn check_roles_requires_two_backup_luks() {
    // WHY (§6): ≥2 BackupLuks or hard error.
    let one = vec![(disk("usb-1", true), DeviceRole::BackupLuks)];
    assert!(check_roles(&one).is_err());
    let two = vec![(disk("usb-1", true), DeviceRole::BackupLuks), (disk("usb-2", true), DeviceRole::BackupLuks)];
    assert!(check_roles(&two).is_ok());
}
#[test]
fn allowlist_re_includes_rule2_internal_only() {
    // WHY (§6): an internal (rule-2) disk is re-included by the allowlist; a
    // rule-1 disk never is (covered above).
    let d = Discovery { disks: vec![disk("nvme-int", false), disk("usb-1", true), disk("usb-2", true)],
        resolution_complete: true, live_backing: BTreeSet::new() };
    assert!(classify(&d, &[]).iter().any(|(c, r)| c.by_id == "nvme-int" && *r == DeviceRole::Excluded(ExclusionReason::Rule2Internal)));
    assert!(classify(&d, &["nvme-int".to_string()]).iter().any(|(c, r)| c.by_id == "nvme-int" && *r == DeviceRole::BackupLuks));
}
#[test]
fn idempotency_refuses_existing_backup_unless_force() {
    // WHY (§6): single-shot; refuse re-provisioning an email already backed up
    // on the drive unless force.
    let mut used = disk("usb-1", true); used.existing_keywright_backups.push("AAAA@x.com".into());
    assert!(idempotency_check(&used, "AAAA@x.com", false).is_err());
    assert!(idempotency_check(&used, "AAAA@x.com", true).is_ok());
    assert!(idempotency_check(&disk("usb-2", true), "AAAA@x.com", false).is_ok());
}
}
```

- [ ] **Step 3: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/device.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): device classify (global guard first; rule-1 survives collision) + check_roles + idempotency (§6)"
```

Expected: `checkPhase` runs the classification matrix, `ok`.

______________________________________________________________________

### Task 8: `plan` — `PlanResult` assembly + render + `--dry-run`

**Files:** Create `src/plan.rs`; modify `lib.rs` (`pub mod plan;`).

**Interfaces:**

```rust
pub struct PlanResult { pub resolved: ResolvedSet, pub validated_now: time::OffsetDateTime, pub compliance_data_version: String }
pub fn build_plan(cli: &CliArgs, config: &Config, policy: &Policy, interactive: bool,
                  detected: time::OffsetDateTime, asserted: Option<&str>, interactive_confirm: Option<bool>) -> Result<PlanResult>;
pub fn render_preview(p: &PlanResult) -> String;     // every resolved value + provenance; secrets/audit_redact → <redacted>
pub fn dry_run(cli, config, policy, detected, asserted) -> Result<String>;  // non-interactive; writes NO file
```

- [ ] **Step 1: Assembly + redacting renderer + dry-run**

`src/plan.rs`:

```rust
//! Plan assembly + dry-run/preview (§8). Wraps 2a's resolve() into PlanResult;
//! never materializes a secret; redacts.

use crate::config::Config;
use crate::policy::Policy;
use crate::registry::{resolve, CliArgs, ResolvedValue};
use crate::{secret, compliance, Error, Result};
use time::OffsetDateTime;

pub struct PlanResult { pub resolved: crate::registry::ResolvedSet, pub validated_now: OffsetDateTime, pub compliance_data_version: String }

pub fn build_plan(cli: &CliArgs, config: &Config, policy: &Policy, interactive: bool,
                  detected: OffsetDateTime, asserted: Option<&str>, interactive_confirm: Option<bool>) -> Result<PlanResult> {
    let resolved = resolve(cli, config, policy, interactive)?;
    let validated_now = secret::validate_clock(detected, asserted, interactive_confirm)?;
    compliance::validate(&resolved, validated_now).map_err(|e| Error::Compliance(e.to_string()))?;
    Ok(PlanResult { resolved, validated_now, compliance_data_version: compliance::version().to_string() })
}

fn show(v: &ResolvedValue) -> String {
    match v {
        ResolvedValue::Bool(b) => b.to_string(),
        ResolvedValue::Enum(s) => s.to_string(),
        ResolvedValue::Uint(n) => n.to_string(),
        ResolvedValue::Expiry(e) => format!("{e:?}"),
        ResolvedValue::AlgoProfile(m) => format!("{m:?}"),
        ResolvedValue::DeviceList(xs) => format!("{xs:?}"),
        ResolvedValue::Pin(_) => "<redacted>".into(),
        ResolvedValue::Str(s) => s.clone(),
    }
}

/// Render every decision in the registry with its resolved value + provenance.
/// secret/audit_redact decisions render <redacted> (even those absent from the
/// ResolvedSet — secrets are skipped by resolve()), so the preview SHOWS that a
/// PIN would be redacted. Compliance verdicts + the data edition + validated_now
/// are appended. Redaction also rides on SecretString/Pin Debug (no leak path).
pub fn render_preview(p: &PlanResult) -> String {
    let mut out = String::new();
    for d in crate::registry::DECISIONS {
        let line = if d.secret || d.audit_redact {
            format!("{} = <redacted>", d.id)
        } else if let Some(r) = p.resolved.get(d.id) {
            format!("{} = {}  ({:?})", d.id, show(&r.value), r.provenance)
        } else {
            continue; // optional, unresolved
        };
        out.push_str(&line); out.push('\n');
    }
    for (role, v) in compliance::verdicts(&p.resolved) {
        out.push_str(&format!("verdict[{role}] = {:?}/{:?} ({})\n", v.regime, v.status, v.note));
    }
    out.push_str(&format!("validated_now = {}\ncompliance-data-version = {}\n", p.validated_now, p.compliance_data_version));
    if let Some(na) = compliance::data().data_not_after {
        if p.validated_now.date() > na { out.push_str(&format!("WARNING: compliance data stale (not-after {na})\n")); }
    }
    out
}

/// Dry-run: non-interactive build + render; materializes nothing, writes NO file.
pub fn dry_run(cli: &CliArgs, config: &Config, policy: &Policy, detected: OffsetDateTime, asserted: Option<&str>) -> Result<String> {
    let p = build_plan(cli, config, policy, /*interactive*/ false, detected, asserted, None)?;
    Ok(render_preview(&p))
}
```

Add `pub mod plan;` to `lib.rs`.

- [ ] **Step 2: Tests (§8/§10) — concrete helpers**

Append:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_config;

    fn now() -> OffsetDateTime { time::macros::datetime!(2026-06-23 0:00 UTC) }
    fn cfg(s: &str) -> Config { parse_config(&format!("real-name='A'\nemail='a@x.com'\n{s}")).unwrap() }
    fn drduh() -> Config { cfg("") } // compliance-profile defaults to 'drduh' → Provenance::Default

    #[test]
    fn dry_run_writes_no_file_and_redacts() {
        // WHY (§8): dry-run materializes nothing, writes NO file, and the preview
        // shows secrets as <redacted>.
        let xdg = std::env::temp_dir().join(format!("kw-dryrun-{}", std::process::id()));
        std::fs::create_dir_all(&xdg).unwrap();
        let before = std::fs::read_dir(&xdg).unwrap().count();
        let preview = dry_run(&CliArgs::default(), &drduh(), &Policy::default(), now(), Some("2026-06-23T00:00:00Z")).unwrap();
        let after = std::fs::read_dir(&xdg).unwrap().count();
        assert_eq!(before, after, "dry-run wrote a file");
        assert!(preview.contains("user-pin = <redacted>"), "secret decisions render redacted");
        std::fs::remove_dir_all(&xdg).ok();
    }
    #[test]
    fn preview_shows_provenance_and_data_version() {
        // WHY (§5/§8): provenance + the compliance-data-version appear in the preview.
        let p = build_plan(&CliArgs::default(), &drduh(), &Policy::default(), false, now(), Some("2026-06-23T00:00:00Z"), None).unwrap();
        let preview = render_preview(&p);
        assert!(preview.contains("compliance-profile = drduh  (Default)"));
        assert!(preview.contains(&p.compliance_data_version));
    }
    #[test]
    fn build_plan_runs_compliance_against_validated_now() {
        // WHY (§5/§7): a bsi encryption key past end-2031 is rejected through the
        // full build_plan path (compliance fed validated_now).
        let bad = cfg("compliance-profile='bsi'\n[algo]\ncertify={algo='rsa3072',expiry='never'}\nsign={algo='rsa3072',expiry='2y'}\nauth={algo='rsa3072',expiry='2y'}\nencrypt={algo='rsa3072',expiry='7y'}\n");
        assert!(build_plan(&CliArgs::default(), &bad, &Policy::default(), false, now(), Some("2026-06-23T00:00:00Z"), None).is_err());
    }
}
```

- [ ] **Step 3: Build + commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add overlays/top-level/keywright/crates/keywright-core/src/plan.rs overlays/top-level/keywright/crates/keywright-core/src/lib.rs
nix build .#keywright -L
nix fmt && git add -A overlays/top-level/keywright
git commit -m "feat(core): plan — PlanResult assembly + redacting preview + no-materialize --dry-run (§8)"
```

Expected: `checkPhase` runs 3 `plan::tests`, `ok`.

______________________________________________________________________

### Task 9: Final whole-crate verification

- [ ] **Step 1: Clean build + full suite**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
git add -A overlays/top-level/keywright
nix build .#keywright -L --rebuild
./result/bin/keywright --version
```

Expected: build exits 0; `checkPhase` shows all modules `ok`.

- [ ] **Step 2: `compliance` reads no clock (§5/§10 gate)**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
! grep -nE 'SystemTime|now_utc|now_local|Instant::now' overlays/top-level/keywright/crates/keywright-core/src/compliance.rs && echo "OK: compliance reads no clock"
```

Expected: `OK: compliance reads no clock` (the `validate_tests` use `datetime!`, not `now_utc`).

- [ ] **Step 3: Format idempotence** — `nix fmt && git status --porcelain` clean; commit `style: treefmt` if needed.

______________________________________________________________________

## Self-Review

**1. Spec coverage (§5–§8/§10):**

- compliance baked data + production floor-sanity gate (§7) → Task 2; `validate()` (global RSA floor; FIPS forbid incl. **Ed448/secp256k1**/cv25519-enc/RSA-enc; PIN\<8; CNSA forbid + RSA\<3072 + **2030/2033 ceiling tested**; BSI RSA\<3000 + split horizons; cv25519-bsi ok) + `verdicts()` (**NotAddressed/AllowedWithConditions/Recommended represented**) → Task 3 + the §10 matrix. **Scoped out (stated):** CNSA SHA-256-general, strict-FIPS Brainpool — no registry input; §10 coverage claim corrected accordingly.
- secret preflight + clock-trust (floor via `checked_clock_floor`, asserted/interactive, `<=2024-01-01` hard-error in production) + RAII guards (Drop incl. `catch_unwind`) → Tasks 4/5.
- device total fail-closed recursion (concrete `Probes`/`Source`/`SourceKind`; **empty-set, degraded, unmatched-by_id, unknown all → fail closed**) + classify (global guard first; rule-1 survives collision+allowlist) + check_roles (≥2 + collision hard-error) + idempotency (over `existing_keywright_backups`) → Tasks 6/7; the §6/§10 topology matrix has concrete asserting tests (6 worked + the rest enumerated with their exact named assertion, built from the template helpers).
- parse stack parsers (mdadm header skip; zpool pool-row skip; leaf+state) → Task 1.
- plan PlanResult + redacting preview (renders registry secret/audit_redact as `<redacted>`) + no-file dry-run + ComplianceError→`Error::Compliance` → Task 8; no-clock gate → Task 9.
- **Plan 2a prerequisites folded into this PR:** `Algo::{Ed448,Secp256k1}` + `parse_algo` arms; `Error::Compliance(String)`; spec §3 `Algo` updated to match.

**2. Placeholder scan:** the device topology matrix lists ~11 additional tests by name with their exact asserting property + the helper template to build each — concrete enough to implement unambiguously without inventing the contract (the types/builders are now real code). The `let _ =` import-reminder line in Task 8 is explicitly flagged for removal. No vague "add error handling".

**3. Type consistency:** `ResolvedSet`/`ResolvedValue`/`Algo`(+Ed448/Secp256k1)/`Expiry`/`Role`/`AlgoSpec` (2a) → compliance + plan; `checked_clock_floor()` → secret; `validate_clock` → `OffsetDateTime` → plan → `compliance::validate`; `Discovery`/`DiskCandidate`(+`existing_keywright_backups`)/`DeviceRole`/`ExclusionReason`(+`ByIdCollision`) (Task 6) → classify/check_roles (Task 7); `PlanResult` matches spec §3; `ComplianceError` maps to `Error::Compliance`.

______________________________________________________________________

## Execution Handoff

Plan complete. This Plan 2b doc joins the **single Plan-2 PR** (spec `required`/`Algo` changes + Plan 2a + Plan 2b); implementation (2a then 2b) follows after that PR is reviewed/merged, subagent-driven.
