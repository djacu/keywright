# Keywright — Foundation + First Vertical Slice (Design Spec)

**Status:** Draft for review (rev 2 — adversarial-review fixes folded in; see §18) · **Date:** 2026-06-20
**Scope:** The first sub-project of Keywright — the cross-cutting *foundation contracts* proven by one end-to-end *vertical slice* of YubiKey/OpenPGP provisioning, CI-tested against a virtual smartcard.

Related artifacts in this repo:

- `docs/design/open-questions.md` — the adversarial gap-check (B1–B13, S1–S12, M1–M3) this spec resolves.
- `docs/design/compliance.md` — the sourced + verified FIPS/CNSA/BSI/NIST compliance matrix.
- Feasibility was proven by a throwaway spike (`opcard-rs` virtual card + `keytocard` in a NixOS VM test, ECC **and** RSA-4096); its packaging + test migrate into this spec (see §14).
- §18 records the disposition of the adversarial spec-review findings.

______________________________________________________________________

## 1. What Keywright is, and what this spec delivers

**Keywright** automates the [drduh YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) provisioning procedure into a tested, audited tool that runs in an air-gapped NixOS live environment — built "corporate from day one."

This spec delivers the **foundation** (the contracts every later sub-project depends on) **proven by a single vertical slice**:

> **discover** connected YubiKeys + drives → operator **selects** 1 card + ≥2 backup drives + 1 export target → **generate** an offline master (certify) key + subkeys → **back up** the master to all selected drives (encrypted, round-trip-verified) → set **card config** (KDF/PINs/attributes, *before* keytocard) → **`keytocard`** the subkeys → **export** the public bundle → emit a **signed, hash-chained audit entry**. Plus a **2-identity batch** path proving per-identity isolation.

The entire slice is **CI-tested in a NixOS VM against a virtual OpenPGP card** (no hardware), for both an ECC and an RSA-4096 algorithm profile.

### 1.1 Non-goals (deferred sub-projects — designed-for, not built here)

Renew / rotate / revoke lifecycle ops; key **escrow**; same-identity **multi-card duplication**; the **TUI**; compliance/attestation **reporting**; the **`mkHost`** host-builder refactor + the `nixos-configs` build matrix; the **ISO build** itself (incl. measured/Secure-Boot image integrity); **batch renew** + **batch export**; YubiKey-as-LUKS-unlock; and **all real-hardware validation** (ykman ops, touch policy, FIPS-mode device behaviour, multi-reader scdaemon). Bounded in §16–§18.

______________________________________________________________________

## 2. Architecture & repository layout

### 2.1 Language & shape — Rust, UI-agnostic core + CLI

- `crates/keywright-core` — the **UI-agnostic engine library**: discovery, gpg orchestration, the card/ykman seam, backup, audit, policy/config, the decision registry. No UI, **no `process::exit`** (returns typed errors so cleanup guards unwind). All logic and the bulk of tests live here.
- `crates/keywright-cli` — a thin `clap` binary over the core.
- *(later)* `crates/keywright-tui` — a `ratatui` layer over the same core.

### 2.2 Where it lives in the flake

Source is **colocated with its `package.nix`** (no repo-root `Cargo.toml`):

```
overlays/top-level/keywright/        package.nix · Cargo.toml · Cargo.lock · crates/…
overlays/top-level/opcard-rs/        package.nix · Cargo.lock   (third-party, fetchFromGitHub)
overlays/nixos-tests/<name>/         package.nix   (each test is a DIRECTORY returning runNixOSTest {…})
hydra-jobs/vm-tests.nix              VM-test jobset (mapTestOn over pkgs.keywrightTests)
hydra-jobs/nixos-configs.nix         DEFERRED (rides the mkHost matrix, §1.1/§17) — not in this slice
checks/                              formatting / light checks ONLY
```

- `keywright/package.nix` uses `rustPlatform.buildRustPackage` with a **committed `Cargo.lock`** and a `lib.fileset` `src` (only `Cargo.toml`/`Cargo.lock`/`crates`, excluding `package.nix`).
- **Test discovery (fixed per review B3/S8):** each VM test is a **directory** `overlays/nixos-tests/<name>/package.nix` returning `pkgs.testers.runNixOSTest {…}`. An `overlays.nixosTests` overlay wraps the discovered set under one attribute — `keywrightTests = recurseIntoAttrs (packagesFromDirectoryRecursive { inherit (final) callPackage; directory = ./nixos-tests; })` — so the jobset's `getDirectoryNames` (directories-only) selects them and the nested `pkgs.keywrightTests.<name>` namespace exists. The overlay is injected **only into `vm-tests.nix` via `extraOverlays`** (not baked into shared `common.nix`, which would apply the heavyweight test overlay — and its `nixos/lib` eval cost — to the packages jobset too).

### 2.3 Orchestration model

The core never shells out ad-hoc. Each external tool sits behind a **typed command runner** that builds argv, **feeds secrets via file descriptors/stdin (never argv or environment)**, parses **structured output** (`gpg --with-colons`/`--status-fd`, `lsblk --json`), and returns typed results/errors. **Binary paths are pinned to `/nix/store`**. Interactive gpg subcommands (`--gen-revoke`, `--edit-key … keytocard`, `--card-edit`) are driven via `--command-fd`+`--status-fd` parsing `GET_BOOL`/`GET_LINE` status lines with a pty / pinentry-loopback (they require a controlling tty / refuse `--batch`) — not blind heredocs (review S6).

### 2.4 Control & error model — one irreversible state machine

The canonical order (guards in brackets):

```
discover → generate (master+subkeys, off-card) → backup (to all drives) →
VERIFY backup (round-trip, §7) → [fresh/reset card] kdf-setup → change Admin PIN →
change User PIN → set attributes (name + login; login REQUIRED before keytocard) →
keytocard ×3 (authenticates with the CHANGED Admin PIN) → readback-verify (per-slot fpr) →
write + SIGN terminal audit record (BEFORE any reset) → export public bundle
```

- **Why card-config precedes keytocard (review B1):** KDF (`kdf-setup`) is only accepted on a *fresh* card before keys/PIN changes; `keytocard` fails without the login attribute and authenticates with the Admin PIN. This matches drduh's order.
- **Guards** encode the drduh irreversibility hazards as typed preconditions: `keytocard` is gated on a *verified, usable* backup (§7) read from the *same pinned LUKS handle* used at backup, with the target card serial fixed before keytocard (closes the verify→keytocard swap window, review S2).
- **`factory-reset` is never part of the success path of an already-provisioned card** (review S14). It is used only for (a) pre-provisioning hygiene of a fresh/dirty card and (b) **failure-recovery**, which *may* reset a card with partial `keytocard` state — gated on a verified backup (§13).
- **Deterministic cleanup via RAII (`Drop`):** guard values run cleanup on *every* exit path. **Two distinct `EphemeralGnupgHome` guards** — the provisioning home and the §7 verification scratch home — plus `LuksMount` and `SessionSecretFile` guards; all tmpfs-resident, each wiping on `Drop`. Hard-kill is backstopped by the ephemeral reboot.

______________________________________________________________________

## 3. The decision registry (config ↔ prompt ↔ CLI ↔ audit parity)

Every user decision is **declared once** as a registry entry: `{ id, type, options (each with compliance tags), default, policy-hook }`. The **CLI flags, TOML config keys, TUI prompts, and audit fields all derive from that one declaration**.

- Each resolved value carries **provenance**: `policy | cli | config | default | interactive | session-file`.
- **Precedence:** `policy-locked > CLI flag > config file > built-in default >` (interactive: prompt | non-interactive: **hard error**). A complete config = the fully-automatable path.
- **Mandatory plan preview (S11-orig):** before any irreversible action, the tool prints every resolved decision + provenance and requires confirmation (interactive) or logs-and-proceeds (non-interactive). `--dry-run` resolves + prints the plan and exits `0` touching nothing.
- The concrete Rust shape (value-type enum; algorithm-profile as one-or-per-role entries; `policy-hook` signature + invocation point; id→key→flag derivation; structured-value audit serialization) is pinned in the implementation plan (review S4).

______________________________________________________________________

## 4. Configuration format & sources

- **Format: TOML** (Rust-native; comments for review; renders cleanly from Nix; avoids YAML ambiguity).
- **Sources are mutually exclusive (NixOS module assertion):** `keywright.config` (Nix attrset → TOML via `pkgs.formats.toml`) **XOR** `keywright.configFile` (path to operator TOML).
- **Non-interactive trigger (B11-orig):** non-interactive iff `--batch <file>`/`--non-interactive` or stdin not a TTY; unmet required decision is a hard error. Destructive actions require an explicit token; the interactive "type the card serial" gate has a non-interactive analog (`target_card_serial` must match the discovered serial or hard-error) (review S5).

______________________________________________________________________

## 5. Secret-handling contract

1. Secrets flow via **file descriptors/stdin** — never argv/env; never logged; never in shell history.
1. `GNUPGHOME` and all working state live on **tmpfs**; `TMPDIR` and child-process scratch are forced under the tmpfs root; **active swap is a hard precondition failure** (`shred` is unreliable on SSD); `RLIMIT_CORE=0`.
1. **Certify-secret invariant (review S2):** after `keytocard` (which only stubs the *subkeys*), the **primary certify secret remains fully present** in tmpfs. It exists *only* in: **(a)** the transient provisioning tmpfs `GNUPGHOME`; **(b)** the LUKS backups via `--export-secret-keys`; and **(c)** the transient §7 verification scratch tmpfs `GNUPGHOME` (its own `Drop` guard, wiped immediately after verify — not only at teardown). **Never** on any non-tmpfs, non-LUKS path. *(Carve-out: the §11.1 encrypted-delivery `.age` on the export drive is **ciphertext**, not raw secret — the bootstrap User PIN it carries never leaves tmpfs/LUKS in cleartext — so it is out of scope of this plaintext-residency invariant.)* The VM test asserts **no plaintext secret outside tmpfs/LUKS at any point, and no escrow-decryptable ciphertext outside the LUKS backups and the intended `.age` artifact**, that the scratch home is wiped post-verify, and that nothing remains after teardown.
1. **No secrets are ever persisted into the ISO image.** `sops-nix`-via-the-ISO-host-key is unsound for a distributable image. Corporate secret custody is the **escrow** sub-project (deferred).
1. **Three independent secrets (S3-orig):** the GPG certify passphrase, the LUKS passphrase, and the YubiKey PINs are **distinct**.
1. **Session passphrase cache — security-relevant, not a UX nicety (review S2):** the round-trip verify (§7) *requires* the certify passphrase to be available to the scratch agent, so the cache is load-bearing for the safety gate. It is a **transient tmpfs file** (`$XDG_RUNTIME_DIR/keywright/…`, `0600`), session-scoped, **`Drop`-shredded at session end**, never persisted/logged (provenance `session-file`). Granularity: key material (`GNUPGHOME`) is wiped **per identity**; the cache persists for the batch. The per-secret non-interactive source for unattended batch (which secret the cache carries; operator-supplied vs tool-generated certify/PIN/LUKS) is pinned in the plan (review S13).
1. **Entropy preflight (S4-orig):** before any generation, require kernel CSPRNG readiness (`getrandom`/"crng init done"); **fail closed** otherwise. (HWRNG preference disposition — advisory-log vs policy-lockable-hard-fail — decided in the plan; crng-init is authoritative, review N1.)

______________________________________________________________________

## 6. Device model & safety

Devices are **lists**; selection is **multi-select**. Three device **roles**: **backup drives** (LUKS, secrets; back up to **≥2 in one operation**), an **export target** (non-encrypted, public bundle — §11; the tool *owns* the audited export), and the **excluded boot/live media**.

### 6.1 Safe-target filter — default-deny

Offer a drive **only if** it survives all exclusions:

1. **Not backing the running system** — exclude any whole-disk with a partition mounted at `/`, `/boot`, `/nix` (or `/nix/.ro-store`), `/iso`/the live squashfs source, or active swap (`lsblk` MOUNTPOINTS + `findmnt` + `/proc/swaps`). Covers **both** the live-ISO USB and a future internal OS drive. **This mountpoint rule — not `rm`/`tran` — is what excludes the boot disk** (a qemu boot disk can carry a serial/by-id and look removable; review S3/§14.3).
1. **Default-deny internal disks** — exclude non-removable/internal (`rm:false` / `tran ∈ {nvme,sata,…}`) unless explicitly allowlisted.
1. **Identify/confirm/address by stable handles** — `by-id` + serial + model + size; destructive ops address by **by-id**, never `/dev/sdX`.
1. **Explicit per-device confirmation.**

**Allowlist (review S3):** a decision-registry entry — a list of stable device identifiers — that **can re-include a rule-2 internal disk but can NEVER re-include a rule-1 running-system/boot/swap disk** (absolute). Its key/type/precedence + the idempotency-override token are pinned in the plan.

### 6.2 Idempotency guard (S12-orig)

Refuse to `luksFormat` a drive already holding a recognizable Keywright backup, or to re-provision a fingerprint/email already backed up on a selected drive, unless explicitly forced.

______________________________________________________________________

## 7. Backup & verification

- Per identity, write the encrypted backup to **each** selected drive under a **per-fingerprint directory** (§11). Shared org backup media (one LUKS passphrase) hold many identities; format designed to be cleanly archivable for future off-site/cloud export (deferred).
- **"Verified usable backup" = full round-trip (B4-orig)**, entirely in tmpfs: `luksOpen` on a separate handle → import the secret key(s) into the §5.3(c) scratch tmpfs `GNUPGHOME` → assert the fingerprint matches and a decrypt/sign test succeeds → wipe the scratch home. Only after this passes is `keytocard` permitted, operating on the **same pinned LUKS handle** with the **card serial fixed**. The VM test **injects a truncated/corrupt backup and asserts `keytocard` is blocked**.

______________________________________________________________________

## 8. Audit & operator identity (Option A)

- **Append-only, hash-chained log** signed by the operator's provisioned YubiKey, whose fingerprint/UID **is** the operator identity. Backed up alongside the keys; the public chain is exported in the bundle.
- **Canonicalization is pinned to RFC 8785 / JSON Canonicalization Scheme (review B2):** records are UTF-8 JSON objects; UIDs are NFC-normalized *at input* (before serialization). `entry_hash = SHA-256( JCS(record with signature="") )`; `prev_hash(N) = entry_hash(N-1)` (lower-hex); the `signature` is the signer's detached OpenPGP signature over `entry_hash`. One object per line. (Reconciles the previously-divergent constructions.) A round-trip unit test (canonicalize → sign → independent re-canonicalize → verify, with a non-ASCII UID) is an acceptance item.
- **Record fields:** `schema_version, chain_id (random per chain), seq, prev_hash, timestamp, event_type, operator_fpr, subject_fpr/UID, decisions{key→value+provenance}, outcome, signature`.
- **Signer rule — total (review S1):** in a **non-bootstrap** run the **operator's provisioned YubiKey signs ALL records, including aborts**; the **subject card signs only its own success record**; the **bootstrap-ephemeral key signs only genesis-run records**. The **terminal (success or abort) record is signed BEFORE any factory-reset**, and the bootstrap/ephemeral key's `Drop` lifetime extends until the terminal record is signed.
- **Bootstrap/genesis (review S11):** `seq=0, prev_hash=0…0, event_type=genesis`, signed by the ephemeral key whose public half is embedded **and committed into the public export bundle** (a second copy outside the operator's hands); the first real-key entry **counter-signs** the genesis fingerprint. **Out-of-band recording of the genesis root is a mandatory, gated step** for bootstrap runs (the operator must acknowledge having recorded it, logged as a decision with provenance). `allow_bootstrap` is policy-lockable (set `false` once an operator key exists); the tool never silently prefers bootstrap when an operator key is present.
- **Honest guarantee:** the chain provides **per-run, intra-chain tamper-evidence**; cross-run/fleet reconciliation (a durable corporate ledger) is **deferred** (each run mints its own `chain_id`). A bootstrap chain is *authenticatable* only to the extent its genesis root was recorded out-of-band.

______________________________________________________________________

## 9. Policy & compliance enforcement

- **Policy trust root (B1-orig):** the security-team policy is **baked into the read-only `/nix/store` at ISO build time** (resolved by the NixOS module to a store path). *Policy authenticity == ISO build integrity.* **Named residual risk (review S12):** nothing in this slice verifies the ISO's own integrity at boot, so policy enforcement is sound only against an operator who **cannot supply their own boot medium**; defending a malicious operator who controls the ISO is **out of scope for slice #1** and requires measured/Secure Boot + signed-image verification — owned by the deferred ISO sub-project.
- **Lockable fields (B2-orig):** compliance profile, algorithm/curve set, key expiration, PIN min-length + generated-vs-chosen, factory-reset-required, audit-required, `allow_bootstrap`, the device allowlist.
- **Compliance is a fail-closed gate (B2-orig + review S9):** compliance constraints are a **hard floor evaluated after policy resolution**; any policy/config/CLI value violating the active profile makes the tool **refuse to start with a named error, before any key generation**. The slice enforces the **full FIPS forbid-list** as the floor: **cv25519/X25519, RSA-encryption subkey, secp256k1, Ed448, \<8-char PIN** are all rejected under FIPS (cv25519-under-FIPS is the single most likely operator mistake, since cv25519 is the *non-FIPS default* — §10). §15 asserts at least the cv25519-under-FIPS, RSA-encryption-under-FIPS, and sub-8-char-PIN-under-FIPS conditions fail closed.
- **Compliance profiles** (verified — `docs/design/compliance.md`): **FIPS** (YubiKey 5 FIPS, CMVP #5291); **CNSA 2.0** (transitional classical: RSA-3072/4096, P-384 only, SHA-384/512); **BSI TR-02102-1** (Brainpool); **drduh**.

______________________________________________________________________

## 10. Key parameters (algorithms, PINs, KDF, attributes, expiry, revocation)

- **Per-role algorithm profile (S1-orig)**, selected by policy (not one uniform `KEY_TYPE`):
  - **Default (non-FIPS):** ed25519 certify + ed25519 sign + **cv25519 encrypt** + ed25519 auth.
  - **FIPS profile (review S15):** **RSA-4096 certify + RSA-4096 sign/auth + NIST P-curve ECDH encrypt** (cv25519/X25519 forbidden/blocked under FIPS; Ed25519 *is* FIPS-approved but RSA-4096 is used across roles for the FIPS profile).
  - **Certify key never expires.** **Subkeys default to 2-year expiry**, policy-configurable (incl. `never`).
- **Card config — runs BEFORE keytocard, on the fresh/reset card (review B1):** `kdf-setup` (KDF defaults **on**, policy-settable off; hashes the PIN before transmission) → set **Admin PIN** → set **User PIN** → set **attributes** (name + login from the identity; `url`/`lang` deferred). **PINs generated** high-entropy by default, length per active policy (**FIPS forces ≥8**). `keytocard` then authenticates with the **changed Admin PIN**. Each card op is contingent on opcard-rs support — see §16/B8 (incl. that KDF-after-key-present must be *rejected*).
- **PIN uniqueness & custody (policy):** the **User PIN is always unique per card**; the **Admin PIN is unique per card by default** (`admin-pin-scope = per-card`), with a **fleet-shared Admin PIN** available only as an explicit, documented opt-in (`admin-pin-scope = fleet-shared` — a single point of compromise: physical possession of any card + the shared PIN takes over that card's key use, and it can't be rotated without re-touching every card; named, not mitigated, opt-in only). The **security team retains the Admin PIN** (escrowed); the **user holds the User PIN**. A **Reset Code is generated by default** (`reset-code = true`; lets the user self-reset their User PIN without the Admin PIN) and is **escrow-only** — held in the LUKS backup, **never** placed in the emailable secret-delivery artifact (§11.1), handed to the user out-of-band only on an actual reset. (`admin-pin-scope` and `reset-code` are policy-lockable registry decisions — see the Plan-2 decision-layer spec.)
- **Revocation certificate (S2-orig):** generated **in-slice** while the certify key is in tmpfs (via `--command-fd`-driven `--gen-revoke`, reason "unspecified" — it cannot run under `--batch`, review S6), stored **secret-equivalent — only in the LUKS backups, never the public export**. The VM test asserts a parseable revocation packet is produced and present-in-backup/absent-from-public-export.
- **Touch policy (S8-orig):** recorded in the registry/audit **now** (default on for sig/dec/aut); **application via `ykman` is deferred/HITL**.
- **Tool-generated `GNUPGHOME` config (S6-orig):** dirmngr/keyserver/network fully disabled (air-gap), cross-certification required, AES256/SHA512 preferences per policy; **`scdaemon.conf` sets `disable-ccid` AND a store-pinned `pcsc-driver = …/libpcsclite.so`** (GnuPG ≥2.4 removed the automatic PC/SC fallback, review S7). Baked, hash-pinned, not operator-editable.

______________________________________________________________________

## 11. Public export bundle

The **only** artifact not reconstructable from a YubiKey is the **public key `.asc`** (the card lacks the primary public key, UIDs, bindings, expiry, ownertrust). *Verified:* from the `.asc` alone, with no card, the fingerprint, Key ID, all subkey **keygrips** (incl. the `[A]` auth keygrip), and the SSH public key all derive. The bundle (to the export target; **public-derivable data only** — never the revocation cert/PINs/passphrases **in plaintext**). **The export drive as a whole is NOT wholesale-public:** secret *delivery* rides the same drive as a **separate, encrypted, clearly-typed** artifact (§11.1), so the drive must not be published wholesale — only its public portion. The public bundle is:

1. **`<keyid>-<date>.asc`** — full public certificate.
1. **A machine-readable manifest (TOML/JSON)** for declarative configs: primary fingerprint + Key ID, UID(s), per-subkey `{capability, algorithm, fingerprint, keygrip, expiry}` with the **`[A]` keygrip called out** (for `gpg-agent` `sshKeys`/`sshcontrol`), the **SSH public key** (`gpg --export-ssh-key`), creation date, provisioned card serial(s), and the bootstrap genesis public key (§8).
1. **`ownertrust`** (`gpg --export-ownertrust`) — annotated/commented as **owner-machine-only**, not a blind `import-ownertrust` (trust-amplification footgun, review N2).
1. *(optional)* `summary.txt`.

Goal: a downstream config reads the manifest to populate `sshKeys = [<auth keygrip>]` + `signingkey = <keyid>` automatically.

### 11.1 Encrypted secret-delivery artifact (per user)

The public bundle above carries **no** secrets. Secret *delivery* to the user is a **separate, encrypted, clearly-typed** artifact co-located on the same export drive — so the pairing is unambiguous and so is the type:

- **`<keyid>-secrets.age`** sits beside that user's **`<keyid>-<date>.asc`**: same keyid → unambiguous which secret belongs to which public payload; `.age` → unambiguously the encrypted, email-to-user blob, **not** keyserver material.
- **Contents — scoped to the user's own card-access bootstrap secret:** the **(bootstrap) User PIN** + a short "how to use your YubiKey" note. **Excluded:** the Reset Code (escrow-only, §10), the master key, the Admin PIN, the LUKS passphrase, the certify passphrase — none ever leave the LUKS escrow.
- **Encryption:** `tar` → **`age` passphrase mode** (scrypt KDF) with a **tool-generated diceware passphrase**. Because the ciphertext is harvestable (emailed; the drive can be mis-copied), the passphrase is the load-bearing offline-attack control, so its strength is **pinned** (not left implicit): a **policy-lockable minimum entropy** — `secret-artifact-passphrase-min-bits`, default **≥ 90 bits (≈ 7 EFF-wordlist words)** — and a **minimum `age` scrypt work factor** (log2 N ≥ 19, verified against the vendored `age`). Relay-friendly out-of-band; stored in the LUKS escrow; delivered out-of-band. **The passphrase value is redacted from the audit (never logged, §5.1) — only the generation event and the `secret-artifact-key-scope` decision are recorded; the value lives only in the LUKS escrow.**
- **Key scope (policy):** **`secret-artifact-key-scope`** (policy-lockable registry decision) = **`per-user`** (default — each artifact its own passphrase; N out-of-band deliveries; per-user isolation) | **`fleet`** (one passphrase for the batch, delivered out-of-band **once** — lowest friction, but a **named single point of compromise**: harvesting the one out-of-band passphrase decrypts every batch artifact; not mitigated, opt-in only). *(The two fleet opt-ins — `admin-pin-scope = fleet-shared` (§10) and `secret-artifact-key-scope = fleet` — are independent and their compromises stay **separable** (the Admin PIN never enters the `.age`); enabling both compounds blast radius, so opt into each on its own merits.)*
- **Delivery model:** the user receives their YubiKey + the encrypted blob (any channel, including **email** — the blob is encrypted) + the passphrase (out-of-band). **Bootstrap-change norm:** the how-to instructs the user to **change the (bootstrap) User PIN on first use** (self-service, no Admin PIN), so the delivered secret is **ephemeral** — a later passphrase compromise + harvested ciphertext yields only a stale PIN.
- **Why emailing an encrypted PIN is acceptable — three independent layers:** the PIN is a *second factor* to the **physical card**; it is a *bootstrap* value **changed on first use**; and it is *encrypted* with a **generated passphrase + slow KDF**. Any one failing still leaves the others.
- **Export-drive semantics:** the drive carries **public certs + encrypted-secret artifacts** and is therefore **not wholesale-public**. To prevent an accidental bulk copy to a generic public share (the realistic mis-publish vector — a keyserver would reject non-OpenPGP `.age` data), the tool writes the two classes under **clearly-named subdirs** — `publish/` (the `.asc` + manifest + ownertrust) and `deliver/` (the per-user `<keyid>-secrets.age`) — and **prints a post-export warning enumerating which files are public vs per-user-only**. The operator publishes `publish/` and emails each user their `deliver/<keyid>-secrets.age`. A mis-publish's blast radius is bounded (still passphrase-protected + card-2nd-factor + ephemeral).
- **Regenerable:** both the public bundle and the `.age` artifacts are **regenerable from the LUKS backups** (`<fpr>.pub.asc` + `secrets.txt` + the delivery passphrase), so a failed export-drive write is recoverable without re-touching a card.

(Generation, encryption, and the export write are **Plan 3**; `secret-artifact-key-scope` is a policy-lockable registry decision declared via the Plan-2 registry. Adds the `age` tool — a small, vendored dependency.)

______________________________________________________________________

## 12. The gpg ↔ ykman seam

- **gpg-driven path** (CI-testable against the virtual card): key generation, `card-status`, KDF, PIN change, card attributes, `keytocard`, `factory-reset`, revocation cert.
- **ykman/hardware path** (human-in-the-loop, stubbed in CI behind the seam): touch policy, retry counters, `openpgp reset`, `config usb`, and anything requiring genuine-YubiKey/FIPS-mode behaviour. `ykman` binds only to readers named `"yubico yubikey"`.

______________________________________________________________________

## 13. Failure handling, batch, and multi-user

- **Abort-only, no resume (B6-orig).** Interactively prompt — *(r)etry from backup / (f)actory-reset and retry / (a)bort and leave for inspection*; non-interactively follow a config `on_failure` policy (enum + default pinned in the plan; non-interactive values e.g. `abort` | `factory-reset-and-abort`, retry-from-backup interactive-only — review S5). Never auto-reset without consent. **A signed terminal `aborted` record is written BEFORE any factory-reset** (signer per the §8 total rule — operator YubiKey in steady state, bootstrap key only in a genesis run); recovery may factory-reset a partially-`keytocard`'d card, gated on the verified backup, then re-import subkeys from backup and retry (bounded). On final failure the card is left **clean**, never half-provisioned.
- **Card binding (S5-orig):** with N cards inserted, the operator confirms by **reader name + card serial**; that identity is pinned for the whole flow; the post-`keytocard` readback is parsed **per slot** (OPENPGP.1/2/3 = sig/enc/auth, not by line order — review N3) and must come from the same serial.
- **Multi-user batch** = iterate the single-identity flow with **per-identity `GNUPGHOME` wipe**; session LUKS passphrase + opened drives persist for the batch. Config (`[[identity]]` TOML: name+email only, file order = audit order, duplicate emails rejected) is the automatable corporate path.
- **Batch is fail-fast with incremental per-card commit.** The per-card **commit boundary is the signed success-audit record, written BEFORE export** (matching the §2.4 canonical order and §8's sign-before-anything-irreversible rule). Order per card: verified LUKS backup (the §7 gate, before `keytocard`) → `keytocard` → per-slot readback-verify → **signed success audit (the commit point)** → export that user's public cert (`publish/`) + `.age` (`deliver/`). A **card failure aborts the batch** (a failure is often *systemic* — bad drive/reader/config — so stopping beats churning through every remaining card). **Failed-card disposition** (per §8 sign-before-reset): write the signed **terminal `aborted`** record first (capturing whether card N had been `keytocard`'d), then per `on_failure` factory-reset card N and leave it **clean** — the verified LUKS backup makes its key material recoverable for a redo; **if card N is factory-reset, its LUKS-escrowed Reset Code is now stale, and the aborted record flags it superseded** (a redo mints a fresh one). Because commit is incremental, cards 1…N-1 (each with a signed success-audit) are **fully provisioned, backed up, and distributable**; export is the **last, regenerable** step, so a card whose audit is signed but whose export *write* failed is recovered by **re-exporting from its LUKS backup — no card re-touch** (the only "regenerable without re-touching" case). There is **no resume** — the unprovisioned remainder is a **fresh batch run** (new `chain_id`) that **must reselect the same backup drives**, so the §6.2 idempotency guard sees the already-provisioned identities and refuses to re-mint a key for one already backed up there.

______________________________________________________________________

## 14. Test harness & CI

### 14.1 Structure

- **VM tests** ride the package set: `overlays.nixosTests` (directories, §2.2) → `pkgs.keywrightTests`; `hydra-jobs/vm-tests.nix` = `mapTestOn (packagePlatforms { keywrightTests = recurseIntoAttrs (getAttrs (getDirectoryNames …) pkgs.keywrightTests); })`, with the tests overlay injected via `extraOverlays`.
- `hydra-jobs/nixos-configs.nix` (the system-agnostic config matrix) is **DEFERRED** with the `mkHost` refactor (§1.1/§17) — *not* in this slice's harness (review N4). This slice's harness = `vm-tests.nix` + formatting `checks/`.
- `supportedSystems` gates everything (`["x86_64-linux"]` now). Built by **`verify-hydra-jobset`** (`nix-eval-jobs` + `nom build`).

### 14.2 The migrated keystone test

`opcard-rs` → `overlays/top-level/opcard-rs` (`buildRustPackage`, features `vpicc,rsa4096-gen`). The keytocard `nixosTest` → `overlays/nixos-tests/<name>/`, with **rationale comments tying each assertion to the requirement it guards** (the *why*, not just the *what*).

### 14.3 VM-test plumbing & assertions

- **Reader topology (B12-orig + review S7):** `services.pcscd` + `vsmartcard-vpcd` present `opcard-rs` as a single PC/SC reader; `scdaemon` set `disable-ccid` **and** a store-pinned `pcsc-driver`; readiness is a poll-`gpg --card-status`-until-serial wait (assert the vpcd serial returns within the timeout; distinguish "reader-not-found" from "card-not-ready"). Hardware uses the CCID path → HITL-divergent, documented.
- **Device-safety vs virtio (review S3):** nixosTest disks are `/dev/vdX`. Give the backup disks **explicit qemu serials** (so `/dev/disk/by-id/…` exists) and drive selection through the **allowlist** path; **assert the boot disk is excluded via the mountpoint rule (§6.1.1), not rm/tran**, while ≥2 serial-bearing disks are selectable.
- **Read-back assertions, not exit codes (S9-orig):** parse `gpg --card-status --with-colons` per slot to assert the three subkey fingerprints present post-`keytocard` and absent post-`factory-reset`; assert KDF + PIN-change took effect via an op consuming the new PIN; **assert `kdf-setup` is rejected if attempted after a key is present** (B1 ordering guard).
- **Coverage:** fast **ed25519/cv25519** path = per-PR gate; **RSA-4096 + the 2-identity batch** = a separate (nightly) job. Provision `rng-tools`/`haveged`; explicit test timeouts.

### 14.4 GitHub Actions + cache (B13-orig + review B4/S10)

**GitHub Actions is the acceptance gate** (matches the "CI-tested" headline); it invokes `verify-hydra-jobset` against `hydra-jobs/vm-tests.nix` (Hydra-jobs are the job *definitions*, `verify-hydra-jobset` the runner). One workflow on `ubuntu-latest`: `DeterminateSystems/nix-installer-action` + `wimpysworld/nothing-but-nix` + a **Cachix** push/pull. **KVM-unavailable is a visible non-success (review B4):** if `DETERMINATE_NIX_KVM != 1` the VM-test job **fails (or emits a required, merge-blocking "VM tests skipped: no KVM" status)** — "green" must never mean "VM tests didn't run." A guaranteed-KVM path (larger/self-hosted runner) is the fallback if free-runner KVM proves flaky. Matrix/self-hosted otherwise deferred.

______________________________________________________________________

## 15. Acceptance criteria

The slice is "done" when, with GitHub Actions green (VM tests actually executed, per §14.4):

1. Single-identity provision **end-to-end** for **both** the ed25519/cv25519 **and** the FIPS RSA-4096 profile (incl. **RSA-4096 certify**): discover → select (1 card; boot disk excluded by mountpoint rule; ≥2 serial-disks) → keygen → backup-to-all-drives → **round-trip-verify** → KDF/PINs/attributes (before keytocard) → `keytocard` (changed Admin PIN) → per-slot readback → signed JCS-canonical hash-chained audit record (before any reset) → public bundle exported.
1. **Safety guards proven (fail-closed):** boot disk **never offered**; `keytocard` **blocked** on a corrupt backup; **cv25519-under-FIPS**, **RSA-encryption-under-FIPS**, and **sub-8-char-PIN-under-FIPS** configs each **fail closed before keygen**; **`kdf-setup` after a key is present is rejected**; **entropy preflight** fails closed when crng is not ready; **idempotency guard** refuses to reformat an existing Keywright backup.
1. **Certify-secret disposal asserted:** no plaintext certify/secret material outside tmpfs/LUKS at any point, **and no escrow-decryptable ciphertext outside the LUKS backups and the intended §11.1 `.age`**; the §7 scratch home is wiped post-verify; nothing remains after teardown; the session cache is shredded at session end.
1. **2-identity batch** (provision A → reset → provision B on one virtual card) with **`GNUPGHOME` isolation** asserted and **both** backups present; runs to completion with **no interactive secret entry**.
1. **Audit verifies:** signatures + `prev_hash` links check; a JCS round-trip with a non-ASCII UID verifies; the genesis root is emitted and the bootstrap pubkey appears in the export bundle; a **signed, correctly-chained `aborted` record** is produced on an injected post-`keytocard` failure. The **revocation cert** is a parseable packet in the backup and **absent** from the public export.
1. **Config/registry:** `--dry-run` prints the full resolved plan + provenance and exits `0` touching nothing; the non-interactive plan-log path CI uses is exercised; advertised `GNUPGHOME` cipher/digest preferences match policy; the card-binding readback comes from the pinned serial.
1. **Unit tests** for the core (decision registry, device-safety filter, audit JCS canonicalization, parsers) pass; `nix flake check` (formatting) passes.
1. **Secret delivery (mostly Plan-3 acceptance — generation/export is Plan 3):** the per-user `.age` contains **only the bootstrap User PIN** (the Reset Code is **absent** from it and asserted present-in-LUKS); the generated delivery passphrase **meets the entropy floor** (§11.1); the `secret-artifact-key-scope` and `admin-pin-scope` policies are honored; the public bundle + `.age` are **regenerable from the LUKS backups**; the per-card commit is the **signed success-audit before export** (§13).

______________________________________________________________________

## 16. Open verification items (tracked, non-blocking)

- **B8 — opcard-rs capability coverage:** keygen/`keytocard`/`factory-reset`/`card-status` proven; **PIN-change, KDF-via-gpg (incl. the fresh-card ordering rejection), set-attributes** **not yet** verified on the virtual card. Closed by extending the migrated keystone test during implementation; any unsupported op is annotated **HITL-only, stubbed in VM**.
- **Hardware (pending a YubiKey 5 FIPS — not currently available):** FIPS-mode device behaviour, all `ykman` ops, touch policy, multi-reader `scdaemon` disambiguation, real `rm`/`tran=usb` detection, RSA-on-real-card, and the **B1 card-config ordering on real hardware** (opcard-rs may not enforce the fresh-card precondition). A documented human-in-the-loop checklist (hardware spec).
- **Freshness:** NIST SP 800-57 Rev.6 / SP 800-131A Rev.3 are drafts (bind to Rev.5 / r2); CNSA deadlines; CMVP #3907 → Historical (~Sept 2026); cite CNSA v2.1 (`PP-24-4014`).

______________________________________________________________________

## 17. Deferred sub-projects (roadmap)

Lifecycle (**renew** — extend expiry from the offline master; **rotate** — new subkeys, same master, the non-FIPS→FIPS migration; **revoke**), where `renew`/`rotate` take **selection filters** over the per-fingerprint backups — `--expiring-within <duration>`, fingerprint/email list, algorithm/non-compliant, or all — with a secret-free `--dry-run` "who's due" report (expiry is public metadata); an expiry-window filter on a quarterly cadence self-aligns renewals to quarter boundaries and spreads public-key redistribution to ~1/6 of the fleet per run; **escrow** (custody of certify/LUKS passphrases + Admin PINs via a pinned versioned `secrets.txt` schema — review N6; off-site/cloud **encrypted-archive** export; **batch renew/export**); same-identity **multi-card duplication**; the **TUI**; compliance/attestation **reporting**; the **air-gapped ISO build** (incl. measured/Secure-Boot image integrity — the owner of §9's residual risk); the **`mkHost`** refactor + `nixos-configs` matrix; **YubiKey-as-LUKS-unlock**.

______________________________________________________________________

## 18. Adversarial spec-review disposition

The adversarial review (6 lenses) returned **ready-with-fixes**: no strategy errors; load-bearing GPG/LUKS/keygrip/entropy mechanics independently verified.

**Folded into this revision (rev 2):** **B1** card-config ordering before `keytocard` (§2.4, §10); **B2** RFC-8785/JCS audit canonicalization + single hash construction (§8); **B3/S8** test-discovery via directories + `extraOverlays` (§2.2, §14.1); **B4** KVM-unavailable = visible non-success (§14.4, §15); **S1** total abort/terminal-record signer rule + sign-before-reset + bootstrap-key lifetime (§8, §13); **S2** the verification scratch `GNUPGHOME` as a named tmpfs/Drop-guarded third copy + verify→keytocard swap-window closure + session-cache reframed security-relevant (§5, §7); **S9** full FIPS forbid-list as the fail-closed floor (§9, §15); **S11** honest audit guarantee + mandatory gated genesis-root recording + bootstrap pubkey in the export bundle (§8); **S12** named ISO-integrity residual risk (§9); **S14** factory-reset wording (§2.4); **S15** FIPS certify algorithm (§10); **S6** pty/`--command-fd` driving of interactive gpg (§2.3, §10); **S7** store-pinned `pcsc-driver` (§10, §14.3); **N2** ownertrust annotation (§11); **N3** per-slot readback (§13); **N4** nixos-configs deferred (§14.1); **N6** escrow `secrets.txt` schema (§17). Acceptance gaps (S10) closed in §15.

**Carried into the implementation plan as explicit tasks (concrete shapes, not design questions):** **S3** allowlist registry-entry key/type/precedence + idempotency token; **S4** concrete decision-registry Rust types + policy-hook signature; **S5** non-interactive `on_failure` enum/default + `confirm_destructive` granularity + `target_card_serial` gate; **S13** per-secret non-interactive source for unattended batch; **N1** entropy HWRNG disposition.

**Accepted residual risks (named, owned by deferred specs):** policy authenticity == ISO build integrity (S12 → ISO spec); bootstrap-chain authenticity depends on out-of-band genesis recording, and there is no cross-run/fleet ledger yet (S11 → escrow/reporting specs).
