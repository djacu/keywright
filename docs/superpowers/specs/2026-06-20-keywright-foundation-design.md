# Keywright — Foundation + First Vertical Slice (Design Spec)

**Status:** Draft for review · **Date:** 2026-06-20
**Scope:** The first sub-project of Keywright — the cross-cutting *foundation contracts* proven by one end-to-end *vertical slice* of YubiKey/OpenPGP provisioning, CI-tested against a virtual smartcard.

Related artifacts in this repo:
- `docs/design/open-questions.md` — the adversarial gap-check (B1–B13, S1–S12, M1–M3) this spec resolves.
- Feasibility was proven by a throwaway spike (`opcard-rs` virtual card + `keytocard` in a NixOS VM test, ECC **and** RSA-4096); its packaging + test migrate into this spec (see §13).

---

## 1. What Keywright is, and what this spec delivers

**Keywright** automates the [drduh YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) provisioning procedure into a tested, audited tool that runs in an air-gapped NixOS live environment — built "corporate from day one."

This spec is **not** the whole product. It delivers the **foundation** (the contracts every later sub-project depends on) **proven by a single vertical slice**:

> **discover** connected YubiKeys + drives → operator **selects** 1 card + ≥2 backup drives + 1 export target → **generate** an offline master (certify) key + subkeys → **back up** the master to all selected drives (encrypted, round-trip-verified) → set **card config** (PINs/KDF/attributes) → **`keytocard`** the subkeys → **export** the public bundle → emit a **signed, hash-chained audit entry**. Plus a **2-identity batch** path proving per-identity isolation.

The entire slice is **CI-tested in a NixOS VM against a virtual OpenPGP card** (no hardware), for both an ECC and an RSA-4096 algorithm profile.

### 1.1 Non-goals (deferred sub-projects — designed-for, not built here)

Renew / rotate / revoke lifecycle ops; key **escrow**; same-identity **multi-card duplication**; the **TUI**; compliance/attestation **reporting**; the **`mkHost`** host-builder refactor + the `nixos-configs` build matrix; the **ISO build** itself; **batch renew** + **batch export**; YubiKey-as-LUKS-unlock; and **all real-hardware validation** (ykman ops, touch policy, FIPS-mode device behaviour, multi-reader scdaemon). These are bounded in §16–§17.

---

## 2. Architecture & repository layout

### 2.1 Language & shape — Rust, UI-agnostic core + CLI

- `crates/keywright-core` — the **UI-agnostic engine library**: discovery, gpg orchestration, the card/ykman seam, backup, audit, policy/config, the decision registry. No UI, **no `process::exit`** (returns typed errors so cleanup guards unwind). All logic and the bulk of tests live here.
- `crates/keywright-cli` — a thin `clap` binary over the core (the "guided" flow = interactive prompts; config-driven = non-interactive).
- *(later)* `crates/keywright-tui` — a `ratatui` layer over the same core (testable via `TestBackend` + MVU + VM-console driving).

### 2.2 Where it lives in the flake

Source is **colocated with its `package.nix`** (no repo-root `Cargo.toml`):

```
overlays/top-level/keywright/        package.nix · Cargo.toml · Cargo.lock · crates/…
overlays/top-level/opcard-rs/        package.nix · Cargo.lock   (third-party, fetchFromGitHub)
overlays/nixos-tests/                <test>.nix   (runNixOSTest definitions, auto-discovered)
hydra-jobs/vm-tests.nix              VM-test jobset (mapTestOn over pkgs.keywrightTests)
hydra-jobs/nixos-configs.nix         system-agnostic config matrix (genAttrs supportedSystems loop)
checks/                              formatting / light checks ONLY
```

- `keywright/package.nix` uses `rustPlatform.buildRustPackage` with a **committed `Cargo.lock`** and a `lib.fileset` `src` (only `Cargo.toml`/`Cargo.lock`/`crates`, excluding `package.nix` so editing it doesn't bust the build cache).
- The VM-tests overlay (`overlays.nixosTests`, exposing `pkgs.keywrightTests`) is added to `hydra-jobs/common.nix`'s overlay list — **not** to `overlays.default` (avoids the default-overlay ↔ nixosConfigurations cycle and keeps `nix flake show`/`checks` fast).

### 2.3 Orchestration model

The core never shells out ad-hoc. Each external tool (`gpg`, `gpg-connect-agent`/`scdaemon`, `ykman`, `cryptsetup`, `lsblk`/`blkid`, `findmnt`) sits behind a **typed command runner** that builds argv, **feeds secrets via file descriptors/stdin (never argv or environment)**, parses **structured output** (`gpg --with-colons`/`--status-fd`, `lsblk --json`), and returns typed results or typed errors. **Binary paths are pinned to `/nix/store`** (no `$PATH` reliance — reproducibility + air-gap integrity).

### 2.4 Control & error model — one irreversible state machine

Provisioning is an **explicit ordered state machine with guards**. The canonical order (per resolution of gap-check **B6**):

```
discover → generate (master+subkeys, off-card) → backup (to all drives) →
VERIFY backup (round-trip) → set PINs/KDF/attributes → keytocard →
readback-verify on-card fingerprints → write+sign audit → export public bundle
```

- **Guards** encode the drduh irreversibility hazards as typed preconditions: `keytocard` is gated on a *verified, usable* backup (§7); KDF before PIN-change; backup before keytocard.
- **`factory-reset` is pre-provisioning hygiene / failure-recovery — never a post-keytocard wipe.**
- **Deterministic cleanup via RAII (`Drop`):** guard values (`EphemeralGnupgHome`, `LuksMount`, `SessionSecretFile`) run cleanup on *every* exit path (return, `?`, panic-unwind) — wipe the tmpfs `GNUPGHOME`, shred session secret files, `luksClose`/unmount. Hard-kill (`SIGKILL`) is backstopped by the ephemeral reboot.
- **Errors** are typed: recoverable (re-prompt) vs fatal (abort + cleanup).

---

## 3. The decision registry (config ↔ prompt ↔ CLI ↔ audit parity)

Every user decision is **declared once** as a registry entry: `{ id, type, options (each with compliance tags), default, policy-hook }`. The **CLI flags, TOML config keys, TUI prompts, and audit fields all derive from that one declaration** — so they cannot drift; "every question has a config option" holds by construction.

- Each resolved value carries **provenance**: `policy | cli | config | default | interactive | session-file`.
- **Precedence:** `policy-locked > CLI flag > config file > built-in default >` (interactive: prompt | non-interactive: **hard error** "missing required setting X"). A complete config = the fully-automatable path.
- **Mandatory plan preview (S11):** before any irreversible action, the tool prints every resolved decision with its provenance and requires confirmation (interactive) or logs-and-proceeds (non-interactive). A `--plan`/`--dry-run` resolves + prints the full plan and exits `0` without touching card or drives.

---

## 4. Configuration format & sources

- **Format: TOML** (Rust-native via `serde`+`toml`; supports comments for human review; avoids YAML's ambiguity; renders cleanly from Nix).
- **Sources are mutually exclusive (NixOS module assertion):** `keywright.config` (a Nix attrset rendered to TOML via `pkgs.formats.toml`) **XOR** `keywright.configFile` (a path to an operator-authored TOML). Whichever is set lands at the canonical path the tool reads (or `--config <path>`). The tool is agnostic to how the file got there.
- **Non-interactive trigger (B11):** non-interactive iff `--batch <file>`/`--non-interactive` is passed **or** stdin is not a TTY; an unmet required decision is a hard error. Destructive actions require an explicit token (`confirm_destructive=true`/`--yes`), never silently skipped.

---

## 5. Secret-handling contract

1. Secrets flow via **file descriptors/stdin** — never argv or environment; never logged; never in shell history.
2. `GNUPGHOME` and all working state live on **tmpfs**; `TMPDIR` and child-process scratch are forced under the tmpfs root; **active swap is a hard precondition failure** (B5 — `shred` is unreliable on SSD, so confidentiality rests on tmpfs + no-swap, not shredding); `RLIMIT_CORE=0`.
3. **Certify-secret invariant (B5):** after `keytocard` (which only stubs the *subkeys*), the **primary certify secret remains fully present** in tmpfs. It exists *only* (a) transiently in tmpfs `GNUPGHOME` and (b) inside the LUKS backups via `--export-secret-keys`; **never** on any non-tmpfs, non-LUKS path. The VM test asserts no plaintext secret material outside tmpfs/LUKS at any point, including after teardown.
4. **No secrets are ever persisted into the ISO image.** `sops-nix`-via-the-ISO-host-key is unsound for a distributable image (baked key = public; no key = can't decrypt). Corporate secret custody is the **escrow** sub-project (deferred). `sops`-to-an-operator-YubiKey is acceptable at most for *non-master* config.
5. **Three independent secrets (S3):** the GPG certify passphrase, the LUKS backup-volume passphrase, and the YubiKey PINs are **distinct** (if LUKS pass = GPG pass, one leak + a stolen drive = the master).
6. **Session passphrase reuse:** to avoid re-typing across multi-drive backup / batch flows, a passphrase may be cached in a **transient tmpfs file** (`$XDG_RUNTIME_DIR/keywright/…`, `0600`), session-scoped, **shredded at session end**, never persisted/logged — either written by the tool after one prompt or placed by the operator (config-driven automation). Provenance `session-file`. *Granularity:* key material (`GNUPGHOME`) is wiped **per identity** (isolation); the session passphrase persists for the batch.
7. **Entropy preflight (S4):** before any key/secret generation, require kernel CSPRNG readiness (`getrandom`/"crng init done"; prefer a hardware RNG); **fail closed** otherwise (a cold-booted air-gapped box can be poorly seeded → guessable keys).

---

## 6. Device model & safety

Devices are **lists**; selection is **multi-select**. Three device **roles**:

- **Backup drives** (LUKS, hold secrets) — back up the master to **≥2 in one operation** (drduh: ≥2 backups).
- **Export target** (non-encrypted; holds the public bundle — §11). The tool **owns** the export (audited; writes *only* non-secret outputs), rather than leaving the operator to mount-and-copy.
- **Boot/live media** — **excluded** (see below).

### 6.1 Safe-target filter — default-deny

A drive is offered **only if** it survives all exclusions:

1. **Not backing the running system** — exclude any whole-disk with a partition mounted at `/`, `/boot`, `/nix` (or `/nix/.ro-store`), `/iso`/the live squashfs source, or active swap (`lsblk` MOUNTPOINTS + `findmnt` + `/proc/swaps`). This single rule excludes **both** the live-ISO USB and a future internal OS drive.
2. **Default-deny internal disks** — exclude non-removable/internal (`rm:false` / `tran ∈ {nvme,sata,…}`) unless explicitly allowlisted.
3. **Identify/confirm/address by stable handles** — `by-id` + serial + model + size; destructive ops (`luksFormat`/wipe) address devices by **by-id**, never `/dev/sdX`.
4. **Explicit per-device confirmation** (typed gesture; CI supplies `confirm_destructive`).

### 6.2 Idempotency guard (S12)

Refuse to `luksFormat` a drive already holding a recognizable Keywright backup, or to re-provision a fingerprint/email that already has a backup directory on a selected drive, unless explicitly forced.

---

## 7. Backup & verification

- Per identity, write the encrypted backup to **each** selected drive under a **per-fingerprint directory** (§11 layout). Shared org backup media (one LUKS passphrase) hold many identities; format designed to be cleanly archivable for the future off-site/cloud export (encrypted-archive — a backup/escrow concern, deferred).
- **"Verified usable backup" = full round-trip (B4)**, entirely in tmpfs: `luksOpen` on a separate handle → import the secret key(s) into a scratch tmpfs `GNUPGHOME` → assert the fingerprint matches and a decrypt/sign test succeeds → close. Only after this passes is `keytocard` permitted. The VM test **injects a truncated/corrupt backup and asserts `keytocard` is blocked**.

---

## 8. Audit & operator identity (Option A)

- **Append-only, hash-chained log** (each entry carries the previous entry's hash → tamper-evident), **signed by the operator's provisioned YubiKey**, whose fingerprint/UID **is** the operator identity. The log is **backed up alongside the keys** and exported (public) in the bundle.
- **Bootstrap exception (S7):** the very first provisioning (no operator key yet) is `identity_assurance=self-asserted`, signed by an ephemeral key whose public half is embedded as the genesis record. `allow_bootstrap` is a **policy-lockable** field the security team sets `false` once an operator key exists; the tool never silently prefers bootstrap when an operator key is present.
- **Record schema (B7):** versioned **canonical JSON-lines** (sorted keys, UTF-8, no floats), one object per line. Fields: `schema_version, chain_id (random per chain), seq, prev_hash, timestamp, event_type, operator_fpr, subject_fpr/UID, decisions{key→value+provenance}, outcome, signature` (over the canonical bytes minus `signature`). Genesis: `seq=0, prev_hash=0…0, event_type=genesis`; the first real-key entry hash-commits to the genesis fingerprint; the genesis root is surfaced for out-of-band recording. Each run = one `chain_id` (corporate reconciliation tooling deferred, but `chain_id` exists now).
- **Aborted runs are recorded:** every non-success exit emits a signed `aborted` record (by the card if it became a usable signer, else the bootstrap key).

---

## 9. Policy & compliance enforcement

- **Policy trust root (B1):** the security-team policy is **baked into the read-only `/nix/store` at ISO build time** (resolved by the NixOS module to a store path, not runtime-editable). *Policy authenticity == ISO build integrity.* Operator-editable config supplies only non-locked values. Runtime signature-verification of externally-supplied policy is deferred.
- **Lockable fields (B2):** compliance profile, algorithm/curve set, key expiration, PIN min-length + generated-vs-chosen, factory-reset-required, audit-required, `allow_bootstrap`.
- **Compliance is a fail-closed gate, not a tag (B2):** compliance constraints are a **hard floor evaluated after policy resolution**; a policy-locked value that violates the active profile makes the tool **refuse to start with a named error**, before any key generation — never a silent downgrade. The VM test asserts a *FIPS-profile + locked-RSA-encryption-subkey* config **fails closed**.
- **Compliance profiles** (sourced + verified against primary specs — full matrix to be persisted as `docs/design/compliance.md`):
  - **FIPS** (YubiKey 5 FIPS, CMVP #5291): RSA-2048/3072/4096 sign/auth, ECDSA P-256/384/521, Ed25519, **ECDH on NIST P-curves for encryption**, SHA-2; **forbid** cv25519/X25519, RSA-encryption subkey (blocked on-card), secp256k1, Ed448; **≥8-char PINs**.
  - **CNSA 2.0:** transitional classical only — RSA-3072/4096, **P-384 only**, SHA-384/512 (flag "retire by 2030/2033"); no YubiKey is fully CNSA-2.0-conformant (needs ML-KEM/ML-DSA).
  - **BSI TR-02102-1:** Brainpool curves recommended; NIST P-curves *not* on its recommended list; RSA-3072+.
  - **drduh:** rsa4096 + ed25519-auth.

---

## 10. Key parameters (algorithms, PINs, KDF, attributes, expiry, revocation)

- **Per-role algorithm profile (S1)**, selected by the active policy (not one uniform `KEY_TYPE`):
  - **Default (non-FIPS):** ed25519 certify + ed25519 sign + **cv25519 encrypt** + ed25519 auth.
  - **FIPS profile:** RSA-4096 sign/auth + **NIST P-curve ECDH encrypt** (cv25519/X25519 are forbidden/blocked under FIPS).
  - **Certify key never expires** (offline + self-renewing). **Subkeys default to 2-year expiry**, policy-configurable (including `never`).
- **Card config in-slice (B3):** after `keytocard`, run `kdf-setup` → set **Admin PIN** → set **User PIN** → set **card attributes** (name + login from the identity; `url`/`lang` deferred). **PINs generated** (high-entropy) by default, length per active policy (**FIPS forces ≥8**). **KDF defaults on** (PIN hashed before transmission), policy-settable off for legacy-client orgs. Each of these card ops is contingent on opcard-rs support — see open item §16/B8.
- **Admin-PIN custody (policy):** default corporate posture — the **security team retains the Admin PIN** (escrowed); the **user holds the User PIN**; optionally a **Reset Code** lets the user self-unblock. A policy + escrow concern.
- **Revocation certificate (S2):** generated **in-slice** while the certify key is in tmpfs (`gpg --gen-revoke`, reason "unspecified"), stored **secret-equivalent — only in the LUKS backups, never the public export**. VM test asserts present-in-backup, absent-from-public-export.
- **Touch policy (S8):** the decision (default touch=on for sig/dec/aut) is recorded in the registry/audit **now**, but **application via `ykman` is deferred/HITL** (opcard can't take the ykman call).
- **Tool-generated `GNUPGHOME` config (S6):** dirmngr/keyserver/network fully disabled (air-gap), cross-certification required, AES256/SHA512 preferences per policy. Treated as a baked, hash-pinned asset, not operator-editable.

---

## 11. Public export bundle

The **only** artifact not reconstructable from a YubiKey is the **public key `.asc`** — the card carries only the three subkeys' public parts + fingerprints + serial, *not* the primary public key, UIDs, bindings, expiry, or ownertrust. (Verified: from the `.asc` alone, with no card, the fingerprint, Key ID, all subkey **keygrips** — including the `[A]` auth keygrip — and the SSH public key all derive.) The bundle, written to the **export target** (non-secret, no LUKS), contains *only* public-derivable data:

1. **`<keyid>-<date>.asc`** — full public certificate.
2. **A machine-readable manifest (TOML/JSON)** for declarative configs: primary fingerprint + Key ID (0xlong), UID(s), per-subkey `{capability, algorithm, fingerprint, keygrip, expiry}` with the **`[A]` keygrip called out** (for `gpg-agent` `sshKeys`/`sshcontrol`), the **SSH public key** (`gpg --export-ssh-key`), creation date, and the **provisioned card serial(s)**.
3. **`ownertrust`** (`gpg --export-ownertrust`) for non-interactive ultimate trust.
4. *(optional)* `summary.txt`.

Goal: a downstream config (e.g. a Home-Manager module) **reads the manifest to populate `sshKeys = [<auth keygrip>]` and `signingkey = <keyid>` automatically** — no hand-transcribing hex, no grabbing the wrong subkey's keygrip. **Never** co-mingle secret-equivalent data (revocation cert, PINs, passphrases) into this bundle.

---

## 12. The gpg ↔ ykman seam

A first-class architectural boundary:
- **gpg-driven path** (CI-testable against the virtual card): key generation, `card-status`, PIN change, KDF, card attributes, `keytocard`, `factory-reset`.
- **ykman/hardware path** (human-in-the-loop, stubbed in CI behind the seam): touch policy (`set-touch`), retry counters (`set-retries`), `openpgp reset`, `config usb`, and anything requiring genuine-YubiKey/FIPS-mode behaviour. `ykman` binds only to readers named `"yubico yubikey"`, so it never attaches to the virtual card.

The CLI/core keep these cleanly separable so the gpg path is fully VM-tested while the ykman path is gated and documented as a manual checklist (the deferred hardware spec).

---

## 13. Failure handling, batch, and multi-user

- **Abort-only, no resume (B6).** On any failure: report the card/drive state; **interactively prompt** the operator — *(r)etry from backup / (f)actory-reset and retry / (a)bort and leave for inspection*; **non-interactively** follow a config-driven `on_failure` policy. Never auto-reset a card without consent. On final failure, leave the card **clean** (factory-reset), never half-provisioned, and emit a signed `aborted` record.
- **Card binding (S5):** with N cards inserted, the operator confirms the target by **reader name + card serial**; that exact card identity is pinned for the whole flow; the post-`keytocard` readback must come from the same serial.
- **Multi-user batch** = iterate the single-identity flow with **per-identity `GNUPGHOME` wipe** (isolation); the session LUKS passphrase + opened drives persist for the batch. Config-driven batch (`[[identity]]` TOML array — name+email only, no device fields, processed in file order = audit order, duplicate emails rejected) is the automatable corporate path.

---

## 14. Test harness & CI

### 14.1 Structure

- **VM tests** ride the package set: `overlays.nixosTests` exposes `pkgs.keywrightTests` (auto-discovered `runNixOSTest`s); `hydra-jobs/vm-tests.nix` = `mapTestOn (packagePlatforms { keywrightTests = recurseIntoAttrs (getAttrs (getDirectoryNames …) pkgs.keywrightTests); })`. VM tests carry `meta.platforms` → correct per-system jobs.
- **NixOS configs** ride a `genAttrs supportedSystems` loop over **system-agnostic** config files (no hardcoded `hostPlatform`) — `hydra-jobs/nixos-configs.nix` — *not* `mapTestOn` (a `toplevel` lacks `meta.platforms` and self-pinned configs corrupt under `mapTestOn`; verified).
- `supportedSystems` gates everything (`["x86_64-linux"]` now; add arches as runners appear).
- `checks/` stays formatting-only (`nix flake check` is serial/slow). Everything is built by **`verify-hydra-jobset`** (`nix-eval-jobs` + `nom build`).

### 14.2 The migrated keystone test

`opcard-rs` → `overlays/top-level/opcard-rs` (`buildRustPackage`, features `vpicc,rsa4096-gen`). The keytocard `nixosTest` → `overlays/nixos-tests/`, with **rationale comments tying each assertion to the requirement it guards** (per project convention — the *why*, not just the *what*).

### 14.3 VM-test plumbing & assertions

- **Reader topology (B12):** `services.pcscd` + `vsmartcard-vpcd` present `opcard-rs` as a single PC/SC reader; `scdaemon` set `disable-ccid`; readiness is a poll-`gpg --card-status`-until-serial wait (not a sleep). *(Hardware uses the CCID path → HITL-divergent; documented.)*
- **Device-safety vs virtio (B12):** nixosTest disks are `/dev/vdX`/`tran=virtio` with no by-id — which the `rm:true`+`tran=usb` filter would exclude. Give the VM's backup disks **explicit qemu serials** so `/dev/disk/by-id/…` exists, drive selection through the **allowlist** path, and **assert the virtio boot disk is excluded** while ≥2 serial-bearing disks are selectable. (Real `rm`/`tran=usb` detection is HITL-divergent, stubbed via allowlist in VM.)
- **Read-back assertions, not exit codes (S9):** parse `gpg --card-status --with-colons` to assert the three subkey fingerprints present on-card post-`keytocard` and absent post-`factory-reset`; assert KDF + PIN-change took effect via an op that consumes the new PIN.
- **Coverage:** fast **ed25519/cv25519** path = per-PR gate; **RSA-4096 + the 2-identity batch** (provision A → reset → provision B; assert `GNUPGHOME` isolation + both backups present) = a separate (nightly) job (S10). Provision `rng-tools`/`haveged`; set explicit test timeouts.

### 14.4 GitHub Actions + cache (B13)

One `.github/workflows` file on `ubuntu-latest`: `DeterminateSystems/nix-installer-action` (KVM default-on; gate VM tests on `DETERMINATE_NIX_KVM`) + `wimpysworld/nothing-but-nix` (disk) → run `verify-hydra-jobset` against `hydra-jobs/vm-tests.nix`, with a **Cachix** push/pull so `opcard-rs` + the VM-test closure aren't rebuilt every run. Matrix/self-hosted deferred. (Feasibility proven by the deleted spike; KVM + ISO budget confirmed on a public runner.)

---

## 15. Acceptance criteria

The slice is "done" when, on `verify-hydra-jobset ./hydra-jobs/vm-tests.nix` (green in CI):

1. A single-identity provision **end-to-end** succeeds for **both** the ed25519/cv25519 and RSA-4096 profiles: discover → select (1 card, ≥2 serial-disks excluded-boot-disk) → keygen → backup-to-all-drives → **round-trip-verify** → PIN/KDF/attributes set → `keytocard` → readback-verify → signed hash-chained audit entry → public bundle exported.
2. **Safety guards proven:** the boot disk is **never offered**; `keytocard` is **blocked** when the backup is corrupt; a **FIPS-profile + locked-RSA-encryption** config **fails closed**; no plaintext secret exists outside tmpfs/LUKS at any point or after teardown.
3. The **2-identity batch** provisions A then B on one (reset-between) virtual card with **`GNUPGHOME` isolation** asserted and **both** backups present.
4. The **audit chain** verifies (signatures + `prev_hash` links); the **revocation cert** is in the backup and **absent** from the public export.
5. `--dry-run` prints the full resolved plan + provenance and exits `0` touching nothing.
6. Unit tests for the core (decision registry, device-safety filter, audit canonicalization, parsers) pass; `nix flake check` (formatting) passes.

---

## 16. Open verification items (tracked, non-blocking)

- **B8 — opcard-rs capability coverage:** keygen/`keytocard`/`factory-reset`/`card-status` are proven; **PIN-change, KDF-via-gpg, set-attributes** are **not yet** verified on the virtual card. Closed by extending the migrated keystone test during implementation; any unsupported op is annotated **HITL-only, stubbed in VM**.
- **Hardware (pending a YubiKey 5 FIPS — not currently available):** FIPS-mode device behaviour, all `ykman` ops, touch policy, multi-reader `scdaemon` disambiguation, real `rm`/`tran=usb` detection, RSA-on-real-card. A documented human-in-the-loop checklist (hardware spec).
- **Freshness:** NIST SP 800-57 Rev.6 / SP 800-131A Rev.3 are drafts (bind to Rev.5 / r2); CNSA deadlines; CMVP cert #3907 → Historical (~Sept 2026); cite CNSA v2.1 (`PP-24-4014`).

---

## 17. Deferred sub-projects (roadmap)

Lifecycle (**renew** — extend expiry from the offline master, batchable; **rotate** — new subkeys, same master, the non-FIPS→FIPS migration path; **revoke**); **escrow** (corporate custody of certify/LUKS passphrases + Admin PINs; off-site/cloud **encrypted-archive** export; **batch renew/export**); same-identity **multi-card duplication**; the **TUI**; compliance/attestation **reporting**; the **air-gapped ISO build**; the **`mkHost`** refactor + `nixos-configs` matrix; **YubiKey-as-LUKS-unlock**. Each gets its own spec → plan → build cycle; the foundation here is designed so they slot in without rework (escrowed master + central provisioning + per-fingerprint backups + the seam + compliance profiles).
