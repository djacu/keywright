# Keywright Core Engine — Decision & Safety Layer (Plan 2) Design

**Status:** Draft for review (rev 9 — PIN policy: unique-per-card Admin/User PINs (fleet-shared Admin = explicit opt-in), Reset Code default-on; rev 8 decoupled the clock-floor from the flake; folds in four rounds of adversarial review + the deployment decision)
**Date:** 2026-06-22
**Builds on:** `docs/superpowers/specs/2026-06-20-keywright-foundation-design.md` (the foundation design; this spec references its locked decisions rather than repeating them).
**Resolves:** the implementation-plan document for foundation §18 open items **S3, S4, S5, N1** (resolutions in §§3–7) and the L0–L3 portions of S13.
**Scope:** the **L0–L3 "decision & safety" layer** of `keywright-core` — everything the engine does **before any secret key material exists**: typed errors, the decision registry, config/policy resolution, compliance gating, device discovery + safety filtering, the tmpfs/RAII secret-handling primitives that don't require keys, and the dry-run/plan preview.
**Deployment assumption (decided):** Keywright runs from the dedicated air-gapped ISO (OS in RAM, no on-disk OS, swap forbidden by §7) **and must remain safe if run on a general-purpose host with a normal on-disk OS** (devs, testing, a security engineer's workstation). §6 is therefore designed to be safe on arbitrary real-world storage, not just the appliance.

## 1. Scope & Plan Map

| Plan | Scope | Status |
|---|---|---|
| **Plan 1** | Build/test/CI harness: Rust workspace, `opcard-rs` virtual card, keytocard VM tests, jobset, GitHub Actions | **Done** (on `main`) |
| **Plan 2** | **This spec** — `keywright-core` L0–L3: decision registry, config/policy, compliance gate, device discovery + safety, tmpfs/RAII primitives, dry-run. **No secret key material.** | This document |
| **Plan 3** | `keywright-core` L4–L5: gpg/scdaemon OpenPGP orchestration **(incl. the gpg `--with-colons`/`--status-fd` parsers)**, gpg/ykman seam, LUKS backup + verified round-trip, JCS audit chain + signing, public export bundle. opcard-VM-tested. | Future |
| **Plan 4** | Provisioning state machine + full vertical-slice VM test + the §15 acceptance criteria from the foundation spec. | Future |

**Why split here:** L0–L3 is pure logic + read-only device discovery + dry-run, fully unit-testable with **no card, no LUKS, and no secret key material**. L4–L5 is the key-touching, secret-bearing, opcard-integration-tested part.

**Card-driving strategy (locked, implemented in Plan 3):** gpg subprocess + scdaemon (PC/SC) (`--command-fd`/`--status-fd`/`--with-colons`), matching foundation §2.3/§10 and the only path proven in Plan 1's VM tests. No Rust OpenPGP library, no direct PC/SC crate.

## 2. Architecture & Modules (L0–L3)

`keywright-core` is the UI-agnostic engine library (foundation §2.1): no UI, **no `process::exit`**, every fallible operation returns `Result`, so RAII `Drop` guards unwind on every exit path including panic (§9 — `panic=unwind` is mandatory). `keywright-cli` and the later `keywright-tui` layer over the same core.

```
L0  error                          (no deps)
L1  registry → error               runner → error               parse → error
L2  config → {error, registry}     policy → {error, registry}   compliance → {error, registry}
    secret → {error, runner}
L3  device → {error, runner, parse, registry}     plan → {error, registry, config, compliance, device}
```

| Module | Responsibility | Does NOT do (deferred) |
|---|---|---|
| `error` | Crate-wide typed `Error` enum(s) (`thiserror`); every fallible op returns `Result`; no `process::exit`. | — |
| `registry` | Declare each decision once with per-surface controls; data-driven slice + provenance + the clap/TOML/audit/dry-run derivation surface. | — |
| `runner` | Typed subprocess wrapper: build argv, pin paths to `/nix/store`, feed **secrets only via a `Secret` fd/stdin type the argv builder cannot accept**, capture structured output. Plan 2: read-only storage probes (`lsblk`, `findmnt`, `/proc/self/mountinfo`, `/proc/swaps`, `zpool`, `mdadm`/sysfs, `bcache`). | gpg/cryptsetup orchestration (Plan 3). |
| `parse` | Pure parsers for the storage probes → a device + in-use-source topology. | The gpg `--with-colons`/`--status-fd` parsers — **Plan 3** (validated against real opcard-rs output). |
| `config` | Parse operator TOML; resolve TOML+CLI+policy+default by the registry precedence chain → resolved values with provenance; determine interactive vs non-interactive; parse + validate + NFC-normalize identity input. | — |
| `policy` | Load the policy file from the `/nix/store` path (**canonicalized**, refuse anything not under the real store); expose the lockable-field set + locked values. | — |
| `compliance` | Fail-closed validator (`drduh`/`fips`/`cnsa`/`bsi`) over the **full resolved set**; per-(option, regime) verdict tuples; the global minimum-RSA floor, the FIPS/CNSA forbid-lists, the BSI horizons, the FIPS-approved-mode hardware block-list. The **single cross-field constraint surface over resolved decisions**. | actual keygen (Plan 3); aggregate device constraints (those are `device`). |
| `secret` | tmpfs working-state setup; `EphemeralGnupgHome` + `SessionSecretFile` RAII guards; process hardening (`RLIMIT_CORE=0`, advisory `mlock`, active-swap precondition, crng-init preflight, tmpfs presence); the `SessionSecretFile` *contract*; `SecretString`. | `LuksMount` + the backup round-trip (Plan 3); secret *generation* for keys (Plan 3). |
| `device` | Enumerate disks + the in-use-source topology; apply the **positive-proof, fail-closed** safe-target filter (absolute rule-1 below the registry, rule-2 + allowlist); classify roles + `check_roles` aggregate constraints; the idempotency guard; the by-id canonical-identity contract. | actually formatting/mounting LUKS (Plan 3). |
| `plan` | Resolve the full decision set and render every value + provenance for the mandatory preview and `--dry-run` (forces non-interactive; **never materializes secrets**; redacts; exits 0 touching nothing). | executing the plan (Plan 3/4). |

## 3. The Decision Registry (the spine)

Each decision is declared once in a **data-driven static slice**, with **per-surface controls** so the uniform derivation cannot generate forbidden surfaces (no `--pin` argv flag, no config-settable destructive token):

```rust
pub enum ValueType { Bool, Enum(&'static [&'static str]), Uint, Expiry, AlgoProfile, DeviceList, Pin, Str }

pub enum Algo { Ed25519, Cv25519, Rsa(u16), NistP(u16), Brainpool(u16) }   // const-initializable
pub enum Expiry { Never, Days(u32) }                                       // const-initializable
pub enum Role  { Certify, Sign, Auth, Encrypt }
pub struct AlgoSpec { pub algo: Algo, pub expiry: Expiry }

pub enum DefaultVal { None, Bool(bool), Enum(&'static str), Uint(u64),
                      Expiry(Expiry), Str(&'static str), Algo(&'static [(Role, AlgoSpec)]) }

pub struct Decision {
    pub id: &'static str,        // canonical id → flag/key/field name
    pub value_type: ValueType,
    pub default: DefaultVal,
    pub lockable: bool,          // may a policy lock this field?
    pub cli: bool,               // exposed as a CLI flag?
    pub config: bool,            // accepted from TOML?
    pub secret: bool,            // value is a secret → entry via fd/stdin only; forces cli=false, config=false
    pub audit_redact: bool,      // redact in audit + dry-run preview (implied by secret; may also be set alone)
}
pub static DECISIONS: &[Decision] = &[ /* see the draft table below */ ];
```

**Invariant (type/test-enforced):** the flag-builder skips `cli=false`; the TOML mapper skips `config=false`; the audit/preview renderer redacts `audit_redact`. `secret=true` ⇒ `cli=false ∧ config=false ∧ audit_redact=true` (asserted by a registry-consistency unit test; `audit_redact=true` is also allowed on a non-secret field). Secret *values* are never carried as `String` in argv: `runner` accepts them only via a distinct `Secret` type (fd/stdin payload) the argv builder's signature cannot take, so "secret in argv" is a **compile error**. `SecretString` and `ResolvedValue::Pin` implement a **redacting `Debug`/`Display` (`[REDACTED]`)**, so they cannot leak through logs, panics, or error formatting.

**Resolution & provenance** (foundation §3):

```rust
pub enum Provenance { PolicyLocked, Cli, Config, Default, Interactive, SessionFile }
pub enum ResolvedValue { Bool(bool), Enum(&'static str), Uint(u64), Expiry(Expiry),
                         AlgoProfile(BTreeMap<Role, AlgoSpec>), DeviceList(Vec<String>),
                         Pin(SecretString), Str(String) }   // SecretString = zeroize-on-drop, redacting Debug
pub struct Resolved { pub value: ResolvedValue, pub provenance: Provenance }
pub struct ResolvedSet(BTreeMap<&'static str, Resolved>);   // keyed by Decision id

// The resolution entry point returns the resolved decisions PLUS the two
// non-Decision context values the engine must carry so nothing downstream
// re-reads a raw clock or data file: the validated wall-clock (§7) and the
// baked compliance-data edition (§5). compliance::validate + the plan preview
// consume these as inputs — never SystemTime::now() or an unchecked clock.
pub struct PlanResult {
    pub resolved: ResolvedSet,
    pub validated_now: OffsetDateTime,    // §7 clock step (confirmed | asserted), absolute UTC
    pub compliance_data_version: String,  // baked compliance-data edition (§5)
}

pub fn resolve(cli: &CliArgs, config: &Config, policy: &Policy, interactive: bool)
    -> Result<PlanResult, Error>;
```

Precedence per decision: **policy-locked > CLI > config > default > (interactive prompt | non-interactive hard error)**. A policy-locked field rejects any lower-precedence override with a named error. Per-value range/format validation happens during resolution; **a resolution-time validation error carries the decision `id` + a non-secret reason (e.g. "pin too short: len < 8") and never embeds the secret value.** **All cross-field constraints over resolved decisions live in `compliance::validate` (§5)** (full `ResolvedSet`); there is no per-decision `policy_hook`. (Aggregate constraints over *discovered devices* — e.g. ≥2 backup drives — are not decisions and live in `device::check_roles`, §6.)

**`AlgoProfile`** is a single `Decision` (`id = "algo"`, `value_type = AlgoProfile`) resolving to `BTreeMap<Role, AlgoSpec>`. TOML — a nested `[algo]` table (the only nested decision; the mapper special-cases it):

```toml
[algo]
certify = { algo = "ed25519", expiry = "never" }
sign    = { algo = "ed25519", expiry = "2y" }
auth    = { algo = "ed25519", expiry = "2y" }
encrypt = { algo = "cv25519", expiry = "2y" }
```

CLI for `AlgoProfile`: per-role flags `--algo-<role> <algo>[:<expiry>]`.

**Draft decision table** (non-exhaustive; the implementation plan enumerates the full slice):

| id | value_type | default | lockable | cli | config | secret | audit_redact |
|---|---|---|---|---|---|---|---|
| `compliance-profile` | Enum[drduh,fips,cnsa,bsi] | `drduh` | yes | y | y | n | n |
| `cnsa-use-case` | Enum[nss-2030,nss-2033] | `nss-2030` | yes | y | y | n | n |
| `algo` | AlgoProfile | ed25519 C/S/A · cv25519 E | yes | y | y | n | n |
| `subkey-expiry` | Expiry | `Days(730)` | yes | y | y | n | n |
| `pin-min-length` | Uint | `6` (fips ⇒ ≥8) | yes | y | y | n | n |
| `pin-source` | Enum[generated,chosen] | `generated` | yes | y | y | n | n |
| `admin-pin-scope` | Enum[per-card,fleet-shared] | `per-card` | yes | y | y | n | n |
| `reset-code` | Bool | `true` | yes | y | y | n | n |
| `factory-reset-required` | Bool | `true` | yes | y | y | n | n |
| `audit-required` | Bool | `true` | yes | y | y | n | n |
| `allow-bootstrap` | Bool | `true` | yes | y | y | n | n |
| `device-allowlist` | DeviceList | `[]` | yes | y | y | n | n |
| `on-failure` | Enum[abort-leave-clean,factory-reset-and-abort] | `abort-leave-clean` | yes | y | y | n | n |
| `target-card-serial` | Str | `None` | no | y | y | n | n |
| `asserted-date` | Str (RFC-3339) | `None` | no | y | y | n | n |
| `real-name` | Str | `None` | no | y | y | n | n |
| `email` | Str | `None` | no | y | y | n | n |
| `user-pin` / `admin-pin` / `certify-passphrase` | Pin | `None` | no | **n** | **n** | **y** | **y** |
| `confirm-format` / `confirm-keytocard` / `force` | Bool (token) | `false` | no | y | **n** | n | n |

`compliance_tags` are **not** a `Decision` field — per-(option, regime) verdicts are computed in `compliance` keyed by the resolved option (foundation §3 places verdicts per-option).

## 4. Config, Policy & Identity Resolution

- **Config format:** TOML. The NixOS module exposes `keywright.config` (attrset → TOML) **XOR** `keywright.configFile` (a path), mutually exclusive via a module assertion (foundation §4). Tool reads TOML at a known path or `--config <path>`.
- **Policy trust root (canonicalized):** `policy` **canonicalizes** the supplied path (`realpath`, resolving every symlink) **before** the prefix check, rejects if the canonical path is not under the canonical `/nix/store`, and rejects any symlink in the resolved chain that leaves the store. The operator's `--config`/`--policy` override **cannot redirect the policy path** (it comes from the NixOS module only). TOCTOU: open the file, then verify the open fd's path is under the store (read-only store). Loading policy from a writable path is the one thing that collapses the locked-precedence model (foundation §9), so this is load-bearing.
- **Lockable fields:** compliance profile, cnsa-use-case, algorithm/curve set, key expiry, PIN min-length + source, factory-reset-required, audit-required, `allow-bootstrap`, device allowlist (foundation §9).
- **Non-interactive determination:** non-interactive iff `--batch <file>` / `--non-interactive` **or** stdin is not a TTY. A required decision unmet in non-interactive mode is a hard error.
- **Destructive tokens — distinct, CLI-only:** three separate tokens, **satisfying one never satisfies another**: `confirm-format`, `confirm-keytocard`, `force`. All `cli=true, config=false`. `target-card-serial`, if supplied, must match the discovered serial or hard-error.
- **Identity input schema** (foundation §13/§B9 — L0–L3 input parsing/validation/normalization, no key material): exactly one UID = `real-name` + `email` (Comment omitted). `email` validated against an RFC-5322 subset; both **NFC-normalized at input**. Batch input is a `[[identity]]` TOML array of `{ real_name, email }` in **file order = audit order**; duplicate emails rejected. The single-run interactive prompt and the one-element batch share one code path.

## 5. Compliance Gate

A fail-closed validator run **after** resolution and **before** any key generation. The **single cross-field constraint surface over resolved decisions**; it reads the full `ResolvedSet` and **extracts `compliance-profile`/`cnsa-use-case` from the set itself — there is no separate `profile` argument** (one source of truth):

```rust
pub enum Profile { Drduh, Fips, Cnsa, Bsi }
pub enum Regime  { Fips1403, Fips1865, Sp80057, Cnsa2, BsiTr02102 }
pub enum VerdictStatus { Recommended, Approved, AllowedWithConditions, Forbidden, NotAddressed }
pub struct Verdict { pub regime: Regime, pub status: VerdictStatus, pub note: &'static str }
pub fn validate(resolved: &ResolvedSet, now: OffsetDateTime) -> Result<(), ComplianceError>; // takes the validated UTC `now`; reads no clock itself
```

- **Global minimum-RSA floor (every profile, incl. drduh):** reject any `Algo::Rsa(n)` with **`n < 2048`**, named error. RSA-1024 (~80-bit) is never acceptable.
- **Labels are always regime-qualified verdict tuples** — never bare "FIPS"/"approved" (foundation §9; compliance.md §2). Five regimes: FIPS 140-3 (#5291), FIPS 186-5/SP 800-186, SP 800-57 Pt.1 r5, CNSA 2.0, BSI TR-02102-1. Per-(option, regime) verdicts live in `compliance` tables keyed by the resolved option.
- **`drduh` profile:** standalone, non-regulatory; ed25519 C+S+A, cv25519 E, permissive expiry; **no** FIPS/CNSA/BSI claims ("drduh-guide aligned; not FIPS/CNSA/BSI evaluated"). Subject only to the global minimum-RSA floor. **cv25519 permitted.**
- **`fips` forbid-list:** cv25519/X25519, RSA-encryption subkey, secp256k1, **Ed448**, PIN `< 8`. (cv25519-under-FIPS is the most likely operator mistake — clear named error.)
- **Ed448 (disambiguated):** blocked under the `fips` profile (it is in the fips forbid-list, enforced by `validate`). It is **not** added to the universal/approved-mode *hardware* block-list — i.e. not gated under `drduh`/`cnsa`/`bsi` as a hardware rule; its absence from CMVP #5291 means it is simply unsupported on a FIPS device, surfaced as "unsupported," not a cross-profile compliance error. (Error under `fips`; permitted-or-unsupported under the others.)
- **FIPS-approved-mode hardware block-list (scoped):** RSA decipher, X25519/cv25519, secp256k1, RSA-1024, 3DES are blocked **when the active profile is `fips` and/or the target is a FIPS YubiKey in OpenPGP Approved Mode** (compliance.md §4/§5 — an approved-mode property, not universal). Does **not** fire under `drduh`/non-FIPS. *(Plan 2 activates this only via the `profile == fips` branch; the FIPS-device-in-Approved-Mode branch needs card-status detection, wired in Plan 3.)*
- **`cnsa` forbid-list (compliance.md §5):** forbids Ed25519, P-256, P-521, all Brainpool, X25519/cv25519, SHA-256 for general use (SHA-384/512 floor), and **RSA `< 3072`** (a size bound, not the literal "2048"). P-384/RSA-3072/4096 are **transitional-only**; expiry ceiling **end-2030** when `cnsa-use-case = nss-2030` (default), **end-2033** only when `nss-2033`.
- **`bsi` profile:** NIST curves → `AllowedWithConditions` (permit-with-condition / unverified); **cv25519 under `bsi` → `NotAddressed`** (no hard reject, matching compliance.md); Brainpool BSI-recommended; **RSA `< 3000` rejected**. Expiry horizons split per compliance.md §3: an **encryption** subkey expiring after **end-2031** is hard-rejected; a **signing/auth** subkey after **end-2035** is hard-rejected.
- **strict-FIPS:** excludes Brainpool by default (policy flag).
- **Per-role profiles + expiry (foundation §10):** non-FIPS default ed25519 C+S+A / cv25519 E; FIPS RSA-4096 C+S/A / NIST P-curve ECDH E. Certify never expires; subkeys default 2-year, policy-configurable incl. never.
- **Absolute compliance horizons are versioned, refreshable data — never frozen Rust constants:** the dated values in this section (BSI end-2031 / end-2035, CNSA end-2030 / end-2033, the SP 800-57 algorithm-sunset years, the firmware 5.7.4 / CMVP #5291 references) are time-sensitive published values the standards bodies revise. They live in **compliance-data tables baked into the ISO's read-only `/nix/store` at build time** (same trust model as the policy, §4) and are stamped with a **`compliance-data-version`** (the editions/dates transcribed, e.g. `BSI TR-02102-1:2024-01; SP 800-57 r5; CNSA 2.0 v2.1`) — **not** hard-coded in Rust source. A rebuild refreshes them; the `compliance-data-version` is carried in **`PlanResult`** and the plan preview, and recorded in every audit record (the audit chain itself is Plan 3), so the edition that gated a provisioning is auditable. Staleness is made **visible** (the version string in preview/audit, plus an optional baked `compliance-data-not-after` advisory date that surfaces a preview warning) but is **not** guaranteed to fail in the safe direction: if a standard later *tightens* (shorter horizon, higher floor, new forbid), a stale ISO would *under*-refuse — the unsafe direction — which an air-gapped box cannot detect. The obligation is therefore to **rebuild when a standard republishes** (§14). The §7 clock-floor sanity constant lives in this same baked, versioned, flake-decoupled data (a project-maintained date rather than a standards-derived horizon).
- **The expiry-ceiling comparison takes a validated clock as a parameter:** these horizons are absolute calendar dates, so the check (`key-expiry-date ≤ horizon`) depends on a trustworthy "now". `compliance::validate(&resolved, now)` receives the **`validated_now`** (from `PlanResult`, produced by the §7 clock step) and **reads no clock itself** — never `SystemTime::now()` or an unchecked system clock. A §10 test asserts `compliance` has no access to the system clock.

**Acceptance (added to §15):** under `fips`, a cv25519 encryption subkey is refused before keygen with a regime-qualified error; under `drduh`, the same cv25519 is permitted; **RSA < 2048 refused under every profile; RSA < 3072 refused under `cnsa`; RSA < 3000 refused under `bsi`.**

## 6. Device Discovery & Safety — positive-proof, fail-closed

The absolute safety requirement (foundation §6.1): **never offer, as a backup/export target, any disk that is part of the running system** — a disk backing a live mount (`/`, `/boot`, `/nix`, `/iso`, the live squashfs) or backing active swap (swap can hold plaintext key material). Formatting such a disk in Plan 3 would destroy a running system or secrets. Because mapping "which physical disk backs this filesystem/swap?" is hard across Linux storage stacks (an enumerate-every-stack approach repeatedly failed open — see the review history), the rule is stated as **positive-proof and fail-closed**:

> A disk may be classified as a valid target **only if discovery positively proves that no in-use mount and no active swap resolves to it, and resolution of the entire in-use inventory was complete**. If discovery cannot fully resolve every in-use source to concrete backing disks, it enters a **global fail-closed state and excludes every candidate disk**.

```rust
pub enum Transport { Usb, Sata, Nvme, Virtio, Other }
pub struct DiskCandidate {
    pub by_id: String,              // authoritative stable id (wwn- preferred)
    pub by_id_aliases: Vec<String>, // all /dev/disk/by-id links (collision detection)
    pub serial: String, pub model: String, pub size_bytes: u64,
    pub in_use_mountpoints: Vec<String>, // every protected mount resolving to THIS disk
    pub backs_active_swap: bool,         // an active swap resolves to THIS disk
    pub removable: bool, pub transport: Transport,
}
pub struct Discovery {
    pub disks: Vec<DiskCandidate>,
    pub resolution_complete: bool,  // GLOBAL: false if ANY in-use source could not be resolved to disks
}
pub enum ExclusionReason { Rule1InUseMount(String), Rule1ActiveSwap, Rule1LiveBacking, Rule1ResolutionIncomplete, Rule2Internal }
pub enum DeviceRole { BackupLuks, ExportTarget, Excluded(ExclusionReason) }
pub fn classify(d: &Discovery, allowlist: &[String]) -> Vec<(DiskCandidate, DeviceRole)>;
pub fn check_roles(classified: &[(DiskCandidate, DeviceRole)]) -> Result<(), Error>; // aggregate constraints
pub fn idempotency_check(drive: &DiskCandidate, fpr_or_email: &str, force: bool) -> Result<(), Error>;
```

- **The in-use inventory (sources):** every mountpoint from `lsblk` + `findmnt`/`/proc/self/mountinfo`, and every active-swap entry from `/proc/swaps` (foundation §6.1.1 source set). The lsblk block-tree alone is insufficient — filesystems whose mounts are not lsblk block-tree children (ZFS datasets especially) are invisible to it — so `findmnt`/`mountinfo` is the authoritative mount source.
- **Total recursive source-resolution:** each in-use source is resolved to a **set of concrete backing whole-disks** by a recursion that follows every layering construct until it terminates at physical disks:
  - a source that is a block device/partition → walk up the device-mapper / MD / loop tree to the physical disk(s);
  - **a swapfile** (`/proc/swaps` `Type=file`, listed as a *path* not a device) → map the path to its containing filesystem (`findmnt -T <path>` / longest-prefix `mountinfo`) → resolve **that filesystem's** source (recurse);
  - a **ZFS** dataset/zvol → pool → vdev member devices (`zpool status`; a member may render only as a bare GUID or as a *partition* — resolve each member up the partition/dm/MD/loop tree to its **whole disk**, and attribute the mount/swap to that whole-disk `by_id`);
  - **mdraid / bcache** → member set, each member walked up to its **whole disk** the same way;
  - an **overlay** (source `overlay`, backing in mount options) → its `lowerdir`/`upperdir`/`workdir` → map each to its containing filesystem → recurse;
  - in general, recurse until every branch terminates at a concrete whole physical disk.
  - Resolution is **total and all-or-nothing per source**: a source resolves successfully only if it terminates at a concrete set of **whole disks**. For a **multi-member source** (ZFS vdev, mdraid, bcache, dm-stripe) this requires **every member** to resolve to a concrete whole disk; if any member is unparseable, shown only as a GUID, in a degraded/UNAVAIL/REMOVED/missing state, or otherwise not confirmable to a concrete disk, the **entire source is unresolved**. Generally, **a resolver that cannot be *sure* it found ALL backing disks for a source MUST mark resolution incomplete — never return a partial set.** Any unresolved source (unrecognized type, dangling reference, a source resolving to no disk, **or a partial multi-member result**) → discovery sets `resolution_complete = false` (global).
- **Global fail-closed (the load-bearing guarantee):** `resolution_complete` is a **discovery-level (global) flag, not per-disk** — when any in-use source is unresolved, you do not know which disk it belongs to, so `classify` excludes **every** candidate with `Rule1ResolutionIncomplete`. (`check_roles` then sees 0 `BackupLuks` and hard-errors → the tool safely refuses to proceed rather than risk a wrong target. Over-refusal on an exotic host is the *intended* failure direction.)
- **Rule 1 (absolute exclusion):** **global guard first** — if `!d.resolution_complete`, `classify` returns **every** candidate as `Excluded(Rule1ResolutionIncomplete)` without evaluating any per-disk condition (`resolution_complete` exists only on `Discovery`, never on `DiskCandidate`, and `classify` takes `&Discovery`, so this cannot be mis-coded as a per-disk check). Otherwise a disk is excluded if `in_use_mountpoints` is non-empty (path-component-prefix-matching `/`, `/boot`, `/nix`, `/nix/.ro-store`, `/iso`, the live squashfs — so a separate `/boot/efi` ESP is caught by `/boot`), **or** `backs_active_swap`, **or** it backs the live/ISO media (`Rule1LiveBacking`). Rule 1 is **hard-coded in `device` below the registry**: no `device-allowlist` and no `force` can re-include a rule-1 disk. **Rule-1 protection is independent of `by_id`** — a forged/duplicate serial cannot strip a disk's mount/swap-based protection.
- **`Rule1LiveBacking` derivation:** the disk backing `/iso` (via the block-device walk-up) ∪ the disk backing the loop device whose file resides on `/iso` (via the loop→backing-file→containing-fs recursion). It is redundant-but-defense-in-depth with the `/iso` and `/nix/.ro-store` mount-prefix exclusions above; it must be computed (not stubbed `false`), so a future change to the live-media chain cannot silently remove protection.
- **Rule 2 (default-deny internal):** internal disks (`removable=false` / transport-internal) are denied unless their `by_id` is in the policy-lockable `device-allowlist`; the allowlist may re-include a rule-2 disk, **never** a rule-1 disk.
- **by-id canonical identity (Plan 3 trusts this contract):** authoritative id = `wwn-`/stable hardware id; `by_id` must be **unique**. **`classify` performs cross-candidate by-id collision detection** so a duplicate/forged by-id surfaces in the preview (not only at the Plan-3 destructive path); an allowlist match or destructive target resolving to >1 physical disk is a **hard error**. Destructive ops address by `by_id`, never `/dev/sdX`. **Re-validation:** immediately before any destructive use (Plan 3), device identity (`by_id` + serial + size) is re-confirmed and the op aborts on drift (closes the discover→use TOCTOU).
- **Device roles + aggregate constraints:** `BackupLuks` (LUKS, holds secrets), `ExportTarget` (non-encrypted, public bundle), `Excluded`. **`device::check_roles` owns aggregate constraints** (not `compliance`, which sees only resolved decisions; not rule-1): requires **`len(BackupLuks) >= 2`**, hard-error otherwise, run after `classify` and before any irreversible op.
- **Idempotency guard:** single-shot; refuse to re-format a drive already holding a recognizable Keywright backup, or re-provision a fingerprint/email already backed up on a selected drive, unless the explicit `force` token (CLI-only) is supplied.
- **Plan 2 testing (fixtures):** all logic is unit-tested against captured probe fixtures covering every topology the review rounds surfaced: simple boot disk; **LVM-on-LUKS root**; **raw-swap partition**; **encrypted (dm-crypt) swap**; **swapfile on the root fs**; **swapfile on a SEPARATE data disk with no protected mount** (asserts the data disk is `Rule1ActiveSwap`-excluded); separate **`/boot/efi` ESP**; **`/nix` on LVM**; **ZFS-on-root (single-disk AND mirror/raidz)**; **mdraid root**; **bcache root**; **zvol-backed swap**; **overlay** mount; a **degraded multi-member fixture** (ZFS mirror / mdraid root with one member shown only as a GUID or UNAVAIL) asserting `resolution_complete=false` ⇒ **every** candidate excluded (`Rule1ResolutionIncomplete`); a **whole-disk roll-up assertion** (on the healthy multi-member + partition fixtures, the protected mount is attributed to the **whole-disk** candidate, never the partition/member node); and a generic **unresolvable-source** case asserting **every** candidate is excluded, not just one. Plus removable backup/export drives. No real block devices are touched.

## 7. Secret Handling & RAII (Plan 2 subset)

```rust
pub fn preflight() -> Result<(), Error>; // active-swap → hard error; RLIMIT_CORE=0; crng-init (getrandom) ready
                                         // or fail-closed; tmpfs working dir present; mlock advisory (ENOMEM non-fatal);
                                         // HWRNG absence → advisory log (crng-init is the hard gate);
                                         // clock floor: HARD-ERROR if baked data floor constant absent/unparseable/<= 2024-01-01
                                         //   (never skipped); else require now >= floor;
                                         // upper bound: interactive-confirm | asserted-date, else fail-closed (see Clock trust)
pub struct EphemeralGnupgHome;           // tmpfs GNUPGHOME; Drop wipes the dir on every path incl. panic
pub struct SessionSecretFile;            // $XDG_RUNTIME_DIR/keywright, 0600; Drop-unlinks at session end
pub struct SecretString;                 // zeroize-on-drop in-memory secret; redacting Debug
```

- **Transport invariant:** secrets via fd/stdin only — never argv, env, log, history; enforced at the type level (§3). `SecretString`/`ResolvedValue::Pin` redact in `Debug`/`Display`.
- **tmpfs residency:** GNUPGHOME + all working state + `TMPDIR` + child scratch on tmpfs; active swap a hard precondition failure; `RLIMIT_CORE=0`; **`mlock` attempted as advisory** (ENOMEM logged, not fatal — tmpfs + no-swap are the primary controls); no secrets in the ISO.
- **In-memory zeroing:** PIN/passphrase values use `SecretString`. **`SessionSecretFile` Drop-*unlinks*** (tmpfs — RAM-backed, pages zeroed on reclaim — so byte-overwrite adds nothing and a fallible `shred` in `Drop` is avoided).
- **Entropy preflight:** require crng-init (`getrandom`) before any future secret/key generation; fail closed. **HWRNG (N1):** advisory-log default; crng-init is the hard gate.
- **Clock trust:** the §5 expiry-ceiling comparison and gpg's key creation/expiry stamping both depend on the system wall-clock, which on an air-gapped box (no NTP, possibly a dead RTC) may be wrong. `preflight` enforces a **fail-closed lower bound** — a coarse *sanity gate* that rejects an absurdly-early clock, **not** a precise build date. The floor is a **stable, deliberately-maintained date constant carried in the baked compliance/clock reference data** (§5 — the same versioned, refreshable data, baked read-only into `/nix/store`), **decoupled from the flake**: it is **not** derived from `self.lastModified` or any per-build timestamp (which would rebuild the ISO on unrelated dependency/commit changes and isn't reproducible), and it changes only when that data file is intentionally bumped. `preflight` **hard-errors (never skips)** if the floor is absent, unparseable, or `<=` a fixed minimum sanity epoch (`2024-01-01`, guarding against a missing/zeroed value); only with a valid floor does it require `now >= floor` (the wall clock should never read earlier than the declared floor). The **upper bound cannot be auto-checked**, so the validated `now` is **operator-confirmed**: interactive mode shows the detected date/time and requires confirmation (provenance `Interactive`); non-interactive/batch mode requires `asserted-date` (registry — parsed to an **absolute UTC instant**, rejecting naive/ambiguous forms, and `>=` the floor, provenance `Cli`/`Config`) or it is a hard error. `asserted-date` is intentionally **non-lockable** (the provisioning date is unknowable at build time; its only bound is `>= floor`). The resulting **`validated_now`** rides in `PlanResult`, is what §5 compares against, and is recorded in the audit with provenance (Plan 3). Pre-key-material (Plan 2). Residual (§14): a clock the operator deliberately sets *forward* and also confirms/asserts is accepted.
- **`SessionSecretFile` contract (S13 schema — Plan 2 owns the contract; Plan 3 owns generation/injection):** may hold, per identity/batch, the **certify-key passphrase**, the **YubiKey PINs**, and (batch-scoped) the **LUKS passphrase** persisting across identities. Each is `pin-source = generated|chosen` (registry): `generated` ⇒ tool-makes-it; `chosen` ⇒ operator-supplied via fd/stdin (a fd referenced in the `--batch` payload, never argv/env). `Provenance::SessionFile` marks a cache-served value. **The LUKS-passphrase slot is defined here for Plan 3 to populate** — Plan 2 does not populate it and its tests do not exercise it (a `None` field is valid in Plan 2), but the struct must accommodate it so **Plan 3 extends this schema rather than inventing a parallel cache.** Generation + per-batch injection are Plan 3.
- **PIN uniqueness & custody:** the **User PIN is always uniquely generated per card** (no fleet option). The **Admin PIN is uniquely generated per card by default** (`admin-pin-scope = per-card`); a **fleet-shared Admin PIN** (one value across the batch/fleet) is reachable only via the explicit `admin-pin-scope = fleet-shared` opt-in — a documented, weaker posture (single point of compromise; not rotatable without re-touching every card), carried as a named residual (§14). A **Reset Code is generated by default** (`reset-code = true`) so a user can reset their own User PIN without the Admin PIN. The Admin PIN's durable copy is the LUKS escrow (security team); the User PIN + Reset Code are delivered out-of-band to the user. (Generation, card-write, and backup of all three are Plan 3.)
- **Deferred to Plan 3:** `LuksMount`, the verification-scratch `EphemeralGnupgHome`, the bootstrap-ephemeral-key guard, and any key/PIN/LUKS-passphrase *generation*.

## 8. Dry-Run / Plan Preview

`plan` resolves the full decision set and renders **every value with its provenance**, with two hard rules:

1. **Dry-run never materializes a secret** — a property of dry-run *mode*, not a side effect of non-interactivity. Secrets are kept in-memory only / not materialized, so **no `SessionSecretFile` (or any file) is ever written**, covering *both* the interactive-prompt path *and* the non-interactive `--dry-run --batch <chosen-secret-fd>` path. "Exits 0 touching nothing (no devices, no card, no files)" holds for every invocation.
1. **The renderer redacts every `audit_redact`/`secret` value** (`<redacted>`); and because redaction is enforced in `SecretString`/`ResolvedValue::Pin` `Debug`/`Display` and **no `Error` variant embeds a secret value**, the **resolution-error channel** cannot disclose a secret either.

The interactive-confirm / non-interactive-log-and-proceed gate before execution is wired in Plan 3/4; Plan 2 delivers the resolve-and-render + standalone `--dry-run`.

## 9. Error Model & Panic Discipline

A typed `Error` enum (`thiserror`) per module boundary; **no `Error` variant embeds a secret value** (decision id + non-secret reason only). No `process::exit`; everything returns `Result`. RAII `Drop` guards must run on **every** exit path including panic unwinding, so **the crate is compiled with `panic = "unwind"` in all profiles; `panic = "abort"` is forbidden** (it would skip `Drop` and void every secret-safety guarantee) — enforced by a `Cargo.toml` profile comment + a cfg/`compile_error!` guard. Panic-path tests use `std::panic::catch_unwind`; guard types satisfy `UnwindSafe` (or `AssertUnwindSafe` with a justifying comment).

## 10. Testing Strategy (Plan 2)

All Plan 2 tests are **unit tests requiring no hardware, no card, and no real block devices** — they run on a dev machine and in CI without KVM. Every assertion carries a WHY-comment tying it to the requirement it guards (`tests-document-why`). Read-back/observable-state assertions, not exit codes.

- **registry:** precedence, provenance, id→flag/key/field derivation, locked-field override rejection. **Surface invariants:** no `Pin`/`secret` decision generates a CLI flag or TOML key; no destructive token generates a TOML key; `secret ⇒ audit_redact`; `SecretString`/`Pin` `Debug` renders `[REDACTED]`. AlgoProfile `[algo]` TOML round-trips.
- **config/policy:** TOML parse + resolution; **policy-path canonicalization** rejects a symlink leaving `/nix/store` and a `..`-traversal path; XOR config/configFile; non-interactive determination; required-field-missing hard error; **identity** RFC-5322-subset validation, **NFC-normalization-at-input**, `[[identity]]` file-order, duplicate-email rejection; a too-short *chosen* PIN error contains **no PIN bytes**.
- **compliance:** **RSA-1024 rejected under every profile incl. drduh**; **RSA\<3072 rejected under cnsa**; **RSA\<3000 rejected under bsi**; FIPS forbid-list (**cv25519-under-FIPS refused, cv25519-under-drduh permitted**); **Ed448 under fips → error, under drduh → permitted/unsupported**; FIPS-approved-mode block-list scoping; PIN `<8`; CNSA forbid-list (Ed25519/P-256/P-521/Brainpool/SHA-256-general); **CNSA ceiling 2030 default, 2033 only when `cnsa-use-case=nss-2033`**; BSI split horizons (enc >2031 reject; sign/auth >2035 reject); **cv25519 under bsi → `NotAddressed`**; Brainpool excluded under strict-FIPS; `drduh` standalone verdict. **Cross-field via policy-locked inputs:** policy locks `algo.encrypt=cv25519` + `compliance-profile=fips` → named regime-qualified hard error; symmetric case → same. `validate` reads the profile from the `ResolvedSet` (no separate arg).
- **device:** rule-1 absolute exclusion holds across **all** §6 fixtures — LVM-on-LUKS, raw/encrypted swap, **swapfile on root AND on a separate data disk**, ESP, /nix-on-LVM, **ZFS (single + mirror/raidz), mdraid, bcache, zvol-swap, overlay**, a **degraded multi-member fixture (one member as GUID/UNAVAIL → `resolution_complete=false` → EVERY candidate excluded)**, the **whole-disk roll-up assertion (protected mount attributed to the whole disk, not the partition/member)**, and the generic **unresolvable-source case (EVERY candidate excluded)** — a protected disk is excluded **even if allowlisted/forced**; allowlist re-includes a rule-2 disk but never rule-1; **`check_roles` enforces ≥2 BackupLuks**; idempotency + `force`; **by-id collision surfaces in `classify`/preview**; rule-1 holds under a forged/duplicate serial.
- **parse:** source-resolution recursion (every fixture's protected mount/swap rolls up to the correct backing disk(s); ZFS vdev members, swapfile→containing-fs, overlay→backing-dirs) against captured fixtures.
- **secret:** `preflight` (swap-active → error; crng; mlock advisory), `EphemeralGnupgHome`/`SessionSecretFile` `Drop` removes the path (assert gone after drop) **incl. a `catch_unwind` panic-path test**, `SecretString` zeroizes.
- **dry-run:** `--dry-run` and **`--dry-run --batch <chosen-secret-fd>`** each create **no** file under `$XDG_RUNTIME_DIR`; a chosen PIN renders **redacted**.
- **tokens:** satisfying `confirm-format` does **not** unlock `confirm-keytocard` or `force`.
- **clock + compliance-data:** `preflight` hard-fails when the baked floor **constant** is **absent / unparseable / `<= 2024-01-01`** (not merely when `now < floor`) and when `now < floor`; a non-interactive run hard-fails when `asserted-date` is **absent**, `< floor`, or not RFC-3339; `asserted-date` is normalized to an absolute UTC instant before the compare; **`compliance::validate` takes `now` as a parameter and a test asserts it has no access to the system clock**; the §5 ceiling consumes that `validated_now`; the `validated_now` + `compliance-data-version` ride in `PlanResult` and appear in the dry-run/plan preview with provenance (audit recording is Plan 3).

**Not in Plan 2 tests:** VM/opcard integration, card ops, LUKS, audit signing, end-to-end slice (Plans 3–4). The gpg `--with-colons` parsers are Plan 3.

## 11. Crate / Dependency Policy

Standard, well-known crates, **vendored + hash-pinned** via the existing `buildRustPackage` `cargoLock` (same as `opcard-rs`); `Cargo.lock` regenerated + committed; air-gapped build needs no network. Plan 2 set: `serde`, `toml`, `thiserror`, `clap` (present), **`getrandom`**, **`libc` or `nix`** (`setrlimit`, `mlock`), **`zeroize`**, **`time`** (UTC `OffsetDateTime` + RFC-3339 parsing for the clock-trust `validated_now`/`asserted-date`). Largely already transitive under `clap`/`serde`. **No** `sequoia`/`rpgp`/`pcsc` (gpg-subprocess decision). The §6 source-resolution shells out to **read-only** probes (`zpool status`, `lsblk`, `findmnt`, `mdadm --detail`/sysfs, bcache sysfs) via `runner` — no new key/storage crate.

## 12. Resolved Decisions & Deferrals

This spec is the implementation-plan document for foundation §18 items **S3, S4, S5, N1**.

| Decision | Resolution |
|---|---|
| Card-driving | gpg subprocess + scdaemon (PC/SC) |
| Registry shape (**S4**) | data-driven `static &[Decision]` with per-surface controls; `ResolvedValue`/`DefaultVal`/`Algo`/`Expiry` enums; `AlgoProfile` = one entry, `[algo]` nested TOML; **no `policy_hook`** — cross-field over decisions in `compliance::validate(&ResolvedSet, now)` (no profile arg; takes the validated clock), aggregate over devices in `device::check_roles`; `compliance_tags` per-option in `compliance` |
| Plan 2 scope | L0–L3 only; gpg `--with-colons` parsers → Plan 3 |
| `drduh` profile | standalone, non-regulatory; cv25519 permitted; still subject to the global min-RSA floor |
| Compliance floors/lists | **global min-RSA `<2048` reject (all profiles)**; FIPS-mode block-list scoped; Ed448 in fips forbid-list only; **CNSA RSA `<3072`**; **BSI RSA `<3000`**, split 2031(enc)/2035(sign), cv25519 `NotAddressed`; CNSA 2033 ceiling gated by `cnsa-use-case`; strict-FIPS excludes Brainpool |
| Device safety (**S3**) | **positive-proof, fail-closed**: a disk is a valid target only if discovery proves no in-use mount/swap resolves to it AND resolution was complete; any unresolved in-use source → global exclude-all. Total recursive source-resolution across dm/LVM/btrfs/loop/ZFS/mdraid/bcache/zvol/**swapfile**/**overlay**. allowlist = policy-lockable by-id list; `force`/`confirm-*` = distinct CLI-only tokens; rule-1 below the registry, by-id-independent; by-id uniqueness in `classify`; ≥2 BackupLuks in `device::check_roles`. **Designed safe on general-purpose hosts, not just the appliance.** |
| `on-failure` values (**S5**) | `abort-leave-clean` (default — renamed from the foundation's illustrative `abort`), `factory-reset-and-abort`; retry interactive-only; behavior in Plan 3 |
| HWRNG (**N1**) | advisory-log; crng-init hard gate; `mlock` advisory |
| Compliance-data freshness + clock trust | absolute horizons (BSI/CNSA dates, SP 800-57 sunsets, firmware/cert refs) are **versioned refreshable data baked in `/nix/store`** + a `compliance-data-version` (staleness made *visible*, **not** guaranteed safe-direction — standards can tighten), never frozen constants; **clock-trust preflight** — floor is a **stable maintained date constant in the baked compliance/clock data** (decoupled from the flake — *not* `self.lastModified`/per-build, so no unrelated ISO rebuilds; preflight HARD-ERRORS if absent/unparseable/`<= 2024-01-01`), then `now >= floor`; upper bound operator-confirmed or `asserted-date` (absolute UTC, `>= floor`, non-lockable); the **`validated_now` + `compliance-data-version` ride in `PlanResult`**, passed to `compliance::validate(&resolved, now)` (reads no clock) |
| Secret safety | type-level fd/stdin transport; `SecretString` zeroize + redacting Debug; no secret in any Error/log; dry-run never materializes a secret; `panic=abort` forbidden |
| PIN uniqueness & reset code | User PIN **always** per-card; Admin PIN per-card by default (`admin-pin-scope`; `fleet-shared` = explicit documented opt-in, §14 residual); **Reset Code generated by default** (`reset-code=true`); generation/card-write/backup are Plan 3 |
| Crate policy | serde/toml/thiserror/clap/getrandom/libc(or nix)/zeroize, vendored |
| Version / edition | stays `0.0.1`; edition 2024 (confirmed by the committed `Cargo.toml`) |

**Explicitly deferred to Plan 3/4:** the gpg-subprocess *implementation* + the gpg parsers; per-batch secret *generation/injection code* (S13 generation half); the opcard-rs capability spike (B8); the export-manifest format + ownertrust annotation; the `on-failure` *behavior*; `LuksMount` + backup round-trip; the JCS audit chain + signing; the public export bundle; the provisioning state machine; any `ykman`/hardware path; echo-for-confirmation UX; the FIPS-device-in-Approved-Mode card-detection branch.

## 13. Non-Goals (Plan 2)

No secret key material, no key generation, no card operations, no LUKS format/mount, no backup, no audit-record signing, no public export, no provisioning state machine, no `ykman`, no TUI, **no gpg subprocess invocation or gpg-output parsing**. The only operator-visible Plan 2 behavior is `--dry-run`/plan-preview output and resolution/validation/discovery errors.

## 14. Residual Risks / Carry-Over

- The "operator who controls the ISO" threat is out of scope (policy authenticity == ISO build integrity); named, not mitigated.
- §6 is **fail-closed by construction**: a storage stack the source-resolution doesn't yet recognize degrades to "resolution incomplete → exclude all candidates → tool refuses to proceed" (safe), never to a wrong target. The cost is **over-refusal** on exotic hosts (an operational annoyance, not data loss); the recognized-stack set + the fixture matrix grow over time to reduce over-refusal. This is the deliberate bias given the "safe on a normal machine" requirement.
- Discovery is a **best-effort read-only snapshot** assembled from several probes (`findmnt`/`mountinfo`, `/proc/swaps`, `zpool status`, `lsblk`, by-id symlinks) and is **not atomic**. The fail-closed bias makes a mid-scan change that adds an unresolvable source safe (`resolution_complete=false` → exclude-all), and the load-bearing discover→use race is closed by the immediate pre-destructive re-validation of `by_id`+serial+size (Plan 3). No atomicity is assumed.
- §6 source-resolution is **fail-closed against non-resolution by construction** but relies on each per-stack resolver being **conservative against mis-resolution** (a resolver unsure it found all backing disks marks the source incomplete rather than returning a partial set). That conservatism is an implementation-correctness obligation guarded by the §6/§10 fixture matrix (incl. the degraded-member and whole-disk roll-up fixtures); a new storage stack must ship its resolver + fixtures together.
- `mlock` is advisory (ENOMEM non-fatal); tmpfs + no-swap are the primary anti-swap controls.
- The compliance forbid-lists/horizons (§5) are transcribed from `compliance.md` and are **time-sensitive**: they are carried as versioned, refreshable compliance-data baked into the ISO (stamped `compliance-data-version`, with an optional `compliance-data-not-after` advisory date), not frozen constants, so a rebuild refreshes them. Staleness is made **visible** (the version string + advisory date surface in preview/audit) but is **not** guaranteed to fail in the safe direction: if a standard later *relaxes*, a stale ISO over-refuses (safe); if it *tightens* (shorter horizon, higher floor, new forbid), a stale ISO *under*-refuses (the unsafe direction) — and an air-gapped box cannot tell which. The obligation is therefore to **rebuild when a standard republishes**; any horizon load-bearing for a deployment should be re-confirmed against the primary source before relying on it.
- **Clock trust on air-gapped hosts:** the baked **maintained floor constant** (§5/§7 data, decoupled from the flake) is a coarse sanity bound that catches a *grossly* backwards clock automatically (fail-closed) — a floor left un-bumped weakens detection of a *mildly* backwards clock, but the operator-confirm / `asserted-date` upper bound is the real date check; the floor is refreshed alongside the compliance-data on rebuild. The *upper* bound relies on operator confirmation (interactive) or `asserted-date` (non-interactive). A clock deliberately set **forward** and confirmed/asserted by the operator is accepted — defending against a colluding operator who controls both the box and the asserted date is out of scope (named, not mitigated; consistent with the "operator who controls the ISO" residual above). A wrong clock also mis-stamps gpg key creation/expiry (Plan 3); the same validated `now` is the mitigation.
- **Fleet-shared Admin PIN (opt-in only):** with `admin-pin-scope = fleet-shared`, one Admin PIN governs every card — a single point of compromise (physical possession of any card + the shared PIN = takeover of that card's key use) that cannot be rotated without re-touching every card. Off by default (`per-card`); named, not mitigated, when explicitly opted into. (The User PIN is never fleet-shared.)
- The `runner` secret-type + gpg-parser contracts are designed in Plan 2 around the gpg-subprocess decision but exercised against gpg only in Plan 3; a mismatch surfaced there is a Plan 3 finding.
