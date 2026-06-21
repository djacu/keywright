# Keywright First Spec — Consolidated Open Questions

Deduplicated across all five lenses (drduh-coverage, corporate-reqs, security-threat, test-ci-feasibility, ops-ux-config). Ranked by consequence within each section.

______________________________________________________________________

## 1. Blocks the spec

### B1. Policy trust root on the air-gapped ISO

*(corporate-reqs Q1, security-threat #7)*
**Question:** How does Keywright know the active policy is the security team's authentic policy and not operator-tampered? On an air-gapped box there is no network PKI. Options: (a) policy baked into read-only `/nix/store` at ISO build time (hash-pinned, not runtime-editable); (b) detached-signed TOML verified against a baked security-team key; (c) both.
**Why:** "policy-locked > CLI > config" precedence is only as strong as the integrity of the thing declaring a field locked. If the operator can edit the TOML, they can unlock RSA-decrypt on FIPS, lower the PIN floor, or disable the audit log. This is the single load-bearing decision for the entire corporate story and gates the config schema (where a "locked" marker can trustworthily live).
**Default:** Slice #1: policy baked into read-only Nix store (`keywright.policyFile` resolved to a `/nix/store` path by the NixOS module, not runtime-editable). Operator-editable config supplies only non-locked values. State explicitly: "policy authenticity == ISO build integrity"; this breaks if a policy is ever loaded from a writable path. Defer runtime signature verification of externally-supplied policy.

### B2. Lockable-field set + compliance-as-hard-floor conflict rule

*(corporate-reqs Q2 + Q3)*
**Question:** Which decision-registry fields are policy-lockable, and what happens when a locked value contradicts a compliance profile (e.g. policy locks RSA-4096 encryption subkey but device profile is FIPS, which forbids RSA-decrypt)? Is the compliance profile a fail-closed *gate* or only an audit *tag*?
**Why:** Without an enumerated lockable set and a conflict rule, "policy enforcement in the slice" is undefined behavior — either silent bypass (field assumed locked is actually overridable) or internally-contradictory configs whose resolution (refuse vs. compliance-wins vs. policy-wins) is unspecified. Tagging-only makes the FIPS/BSI labels decorative; the corporate value proposition is enforcement.
**Default:** Lockable fields for slice #1: compliance profile, algorithm/curve set, key expiration, PIN min length + generated-vs-chosen mode, factory-reset-required, audit-required. Rule: compliance constraints are a hard floor evaluated *after* policy resolution; a policy-locked value that violates the active profile makes the tool refuse to start with a named error (never silently downgrade). Compliance profile is a fail-closed gate that aborts before any key generation. VM test asserts a FIPS-profile + locked-RSA-encryption config fails closed.

### B3. Card configuration (PIN change, KDF, attributes) in-slice or deferred?

*(drduh Q2, corporate-reqs Q2, security-threat #2, test-ci Q2)*
**Question:** The written flow jumps generate → backup → keytocard → factory-reset and never mentions the five drduh card-mutation steps: KDF-setup, Admin PIN change, User PIN change, card attributes (login/name/url/lang), Reset Code. The DECIDED list pins only their *ordering* (KDF-before-PIN-change), not their *inclusion*.
**Why:** A card left with default PINs (123456 / 12345678) and no KDF is not a provisioned corporate credential — it is wide open, and the audit-signing identity is trivially usable by anyone holding the key. This is a fork that materially changes the state machine. If included, the FIPS profile must gate User-PIN length too (drduh's default 6-char User PIN is below the FIPS 8-char floor).
**Default:** INCLUDE: kdf-setup → set Admin PIN → set User PIN → set card attributes (login=UID). PINs generated (not chosen) by default; length derived from active policy (FIPS forces ≥8 for User PIN). Reset Code and on-card URL deferred unless policy requires. **Must verify opcard-rs supports kdf-setup and change-pin** (see B8) or mark unsupported sub-steps HITL-only/stubbed in CI.

### B4. "Verified usable backup" guard — what "verified" means

*(drduh Q4, security-threat #4, test-ci Q4)*
**Question:** factory-reset is irreversible and gated *only* on this guard. Does "verified" mean (a) LUKS container opens, (b) master key file present inside, or (c) a full round-trip: luksOpen → import secret key into a scratch tmpfs GNUPGHOME → decrypt/sign test → fingerprint matches? Which of drduh's three artifacts (Certify.key, Subkeys.key, public .asc) is round-trip-verified, against what?
**Why:** The single most safety-critical guard. If verification is merely "file written + luksClose succeeded," it passes on a corrupt/truncated/wrong-passphrase backup and the operator loses the master key permanently at factory-reset. Verification semantics also determine what must be in the backup and the exact VM test assertion + failure-injection.
**Default:** Full round-trip entirely within tmpfs: luksOpen on a separate handle → import secret key(s) into scratch tmpfs GNUPGHOME → assert fingerprint matches and a decrypt/sign test succeeds → close. Never decrypt to persistent storage. VM test injects a truncated/corrupt backup and asserts keytocard is blocked.

### B5. Disposition of the certify (master) secret key + secret/tmpfs leak boundary

*(drduh new-Q "where does certify secret end up", security-threat #6-leak)*
**Question:** After keytocard on subkeys only, the primary certify secret remains *fully present* (not a stub) in tmpfs GNUPGHOME. Is its disposal asserted as an invariant? Separately: is *any* plaintext secret guaranteed never to touch a non-tmpfs path — including gpg/cryptsetup scratch files, `TMPDIR`, swap, core dumps, and the backup-verification round-trip?
**Why:** The crown-jewel secret. drduh writes Certify.key/Subkeys.key/public.asc into the *same* GNUPGHOME dir, so a sloppy public-export step or a `TMPDIR` on disk silently leaks it. On SSD `shred` is unreliable, so confidentiality must rest on tmpfs + no-swap, not shredding. DECIDED covers tmpfs-wipe and "no secrets in ISO" but does not name the certify secret as a tracked artifact with a positive disposal assertion, nor close the scratch/swap/coredump escape paths. The whole confidentiality claim depends on this.
**Default:** Invariant: certify secret exists only (1) transiently in tmpfs `$GNUPGHOME` and (2) inside LUKS backups via `--export-secret-keys`; never on any non-tmpfs, non-LUKS path. Force `TMPDIR` and all child-process scratch under the tmpfs root; require swap disabled/absent (assert no active swap as a precondition); `RLIMIT_CORE=0` and mlock where feasible. Public-key export uses a separate explicit destination. VM test asserts no plaintext certify/secret material outside LUKS or tmpfs at any point, and none after Drop-based teardown.

### B6. Irreversible-step ordering + partial-failure recovery (single irreversible state machine)

*(drduh new-Q failure-semantics, corporate-reqs Q5, security-threat #partial, ops-ux Q-failure, test-ci Q9)*
**Question:** keytocard is destructive per-subkey (transferred subkey becomes an on-disk stub) and factory-reset is destructive on the same physical card. Define the canonical order of {verified-backup, PIN/KDF set, keytocard ×3, audit-write, factory-reset} and the documented recovery for *each* partial-failure window — e.g. crash after subkey 1 but before 2/3; crash after keytocard but before the signed audit entry; abort after master backup. Is a signed "aborted" audit record emitted on every non-success exit? Who signs it when the card never became a usable signer?
**Why:** Every gap between irreversible steps is a window leaving the system either insecure (live key, default PIN, no audit) or unrecoverable (wiped card, GNUPGHOME of stubs). RAII Drop wipes tmpfs on every exit, so an abort is genuinely unrecoverable unless recovery explicitly uses the backup. Corporate auditability also requires that "a card was touched then provisioning failed" is itself a signed, recorded event, or the append-only chain develops undetectable gaps. There is no negative-path test to write until this is decided.
**Default:** Canonical order: discover → generate → backup → **verify backup (round-trip)** → set PINs/KDF → keytocard → readback-verify on-card subkey fingerprints → write+sign audit entry → (factory-reset is only the *pre-provisioning hygiene* reset of a fresh card, per drduh — never a post-keytocard wipe). Slice #1 is **abort-only, no resume**. On any keytocard failure: treat card as dirty → factory-reset → re-import subkeys from the verified LUKS backup into a fresh tmpfs GNUPGHOME → retry the full sequence (bounded retries); on final failure leave card factory-reset (clean), never half-provisioned, and emit a signed "aborted" audit record. The card signs the abort record if it became a usable signer; otherwise the ephemeral bootstrap key signs it (bootstrap key therefore lives until success-or-recorded-abort). In batch: fail-fast (abort the batch), completed identities' backups + audit left intact and reported.

### B7. Audit record schema + canonical signing input + genesis/bootstrap + multi-chain identity

*(corporate-reqs Q4, security-threat #6+bootstrap, test-ci Q6, ops-ux minor)*
**Question:** Option A decides the *scheme* (YubiKey-signed, hash-chained, append-only, self-asserted bootstrap) but leaves unspecified: serialized record fields, the exact bytes hashed/signed (canonicalization), the genesis record format, the embedded ephemeral public key, whether the first real-key entry counter-signs the genesis anchor, the clock source on an air-gapped box, and whether N per-operator/per-box chains reconcile into one corporate ledger.
**Why:** A hash chain is only verifiable if the signed bytes are pinned; any canonicalization ambiguity makes independent verification impossible and breaks the VM signature/chain assertions. The genesis is the trust root — if it is purely self-asserted with a discarded ephemeral key and no external anchor, anyone who runs the tool once can fabricate a consistent history. The format is written into backups and is effectively immutable once any real key is provisioned, so it must be nailed now.
**Default:** Versioned line-delimited canonical JSON (sorted keys, UTF-8, no floats), one object per line. Fields: `schema_version, chain_id (random per chain), seq, prev_hash, timestamp, event_type, operator_fpr, subject_fpr/UID, decisions{key→value+provenance}, outcome, signature` (over canonical bytes minus the signature field). Genesis: `seq=0, prev_hash=all-zero, event_type=genesis`, signed by the ephemeral bootstrap key with its public half embedded; the first real-key entry hash-commits to the genesis fingerprint; surface the genesis root to the operator for out-of-band recording. Each box/run = one `chain_id`; corporate merge = concatenation keyed by `chain_id` (reconciliation tooling deferred, but `chain_id` MUST exist now). Audit-signing happens *before* factory-reset, signed by the just-created signing key via scdaemon.

### B8. opcard-rs capability coverage for in-slice card ops

*(test-ci Q1, drduh Q2 dependency)*
**Question:** The only DECIDED "proven against opcard-rs" claim is ed25519/cv25519 + RSA-4096 keytocard. Which remaining in-slice card ops — PIN change, Admin-PIN change, KDF-DO enable, set-key-attributes for non-default curves (RSA-4096/Brainpool switch), factory-reset — are actually verified on the virtual card vs. still unproven?
**Why:** The "CI-tested in a VM against opcard-rs" premise collapses if a load-bearing op is unsupported/buggy on opcard-rs (a v3.4 implementation that may not match a YubiKey 5). Guards like KDF-before-PIN-change and the FIPS/Brainpool branches are only assertable if those ops run on the virtual card. This is an unverified assumption that would invalidate the test plan.
**Default:** During the foundation slice, extend the migrated keystone nixosTest to exercise *every* in-slice card op against opcard-rs; mark any unsupported op as a hard "HITL-only, stubbed in VM" annotation in the spec's test matrix. Do not assume parity with hardware.

### B9. Identity input schema (single + batch)

*(ops-ux Q-identity + Q-batch)*
**Question:** Which UID fields are collected (Real Name, Email, optional Comment), how many UIDs, which is primary, what validation/normalization (RFC-5322, NFC, max length)? And the batch-config schema: TOML array-of-tables? required vs optional per identity, processing order = audit-chain order, duplicate-email handling, and the rule that identity rows carry no card selectors (batch reuses one card with reset-between).
**Why:** Identity is the first operator input and is baked irreversibly into the certify key's self-signature — uneditable after keytocard + factory-reset. An undefined schema means CLI prompts, config keys, batch rows, and the audit UID field cannot be derived from the decision registry; this blocks writing the registry entries the design depends on, and the CI A-then-B batch test cannot be written.
**Default:** Slice #1: exactly one UID = Real Name + Email (Comment omitted per modern GnuPG guidance), email validated against a pragmatic RFC-5322 subset, NFC-normalized, echoed back for confirmation. Batch = TOML `[[identity]]` array of `{ real_name, email }` only (no device fields), processed in file order (= audit order), duplicate emails rejected. Single run accepts an interactive prompt or a one-element identity file (shared code path). Multi-UID/primary-UID deferred.

### B10. Operator-facing output layout (filesystem destinations + names)

*(drduh Q5+pubkey, corporate-reqs Q5, ops-ux Q-outputs)*
**Question:** Where do (a) public key, (b) revocation cert, (c) audit log, (d) any recorded secrets (PINs, Reset Code, tool-generated LUKS/session passphrase) land — with names and medium? ISO is read-only/ephemeral and tmpfs is shredded on exit, so the only writable persistent medium is the selected LUKS backup drives. The public key (non-secret, the thing the operator most needs) must be retrievable *without* the LUKS passphrase, or it is trapped behind the same secret as the certify key.
**Why:** An operator who walks away with a YubiKey but no public key, no revocation cert, and no record of the generated PINs has a provisioned-but-unusable identity — and "secrets never persisted to ISO" + RAII shredding means undefined destinations are *destroyed* at exit. This determines the on-disk LUKS layout the backup code must implement in the slice.
**Default:** Per-identity directory keyed by primary fingerprint on each LUKS drive: `<fpr>/master.key.asc`, `<fpr>.pub.asc`, `<fpr>.rev.asc`, hash-chained `audit.log`, and `summary.txt`. Generated secrets (PINs, Reset Code, LUKS passphrase if tool-generated) written ONLY inside the LUKS volume in `secrets.txt` (0600). Public key *additionally* exported to a dedicated non-secret output location and echoed to the terminal so it is retrievable without the LUKS passphrase; never co-mingle secret and public files such that one could be mistaken for the other.

### B11. Non-interactive trigger + destructive-confirmation gesture

*(ops-ux Q-CLI-sequence)*
**Question:** What flips the tool into non-interactive mode (`--batch`/`--non-interactive` flag? absent TTY? config value?), what is the ordered prompt sequence, and how is confirmation of destructive actions (factory-reset, `luksFormat` on operator drives) expressed — and expressed *non-interactively* for CI?
**Why:** The CI VM test is necessarily non-interactive, so the fully-non-interactive path MUST be specified to write the test at all. factory-reset and luksFormat are irreversible on operator hardware; without a defined confirmation gesture (and a non-interactive way to supply it) the tool either can't be tested or footguns the operator.
**Default:** Non-interactive iff `--batch <file>`/`--non-interactive` passed OR stdin is not a TTY; unmet required decision → hard error. Destructive confirmations satisfied non-interactively by an explicit token (`confirm_destructive = true` / `--yes`), never skipped silently. Guided sequence: show inventory → select card (show serial) → select ≥2 drives (show by-id+serial, typed confirm naming each drive to format) → collect identity → echo full plan + provenance → final "type the card serial to proceed" gate → run. CI uses `--batch` + `confirm_destructive`.

### B12. VM test plumbing: virtual reader topology + device-safety vs. virtio collision

*(test-ci Q-reader-topology + Q-multidrive)*
**Question:** Two test-infra blockers: (1) How is opcard-rs plumbed inside the VM — pcscd + virtualsmartcard(vpcd) as a single PC/SC reader, with scdaemon configured to find exactly one reader and started deterministically before gpg? (2) The DECIDED device-safety predicate filters on `rm:true` + `tran∈{usb,...}` + by-id/serial, but nixosTest disks are `/dev/vdX` with `tran=virtio` and no by-id/serial — so the safety filter would exclude *all* test disks, making the ≥2-drive LUKS backup path untestable.
**Why:** Reader topology is make-or-break for *every* card assertion: if the typed scdaemon wrapper assumes a YubiKey CCID reader but the VM presents vpcd PC/SC, the tested code path diverges from production. The device-safety/virtio collision is a direct contradiction between two DECIDED contracts that only surfaces under the test lens — the safety logic that must be asserted makes the backup test impossible without an override.
**Default:** (1) pcscd enabled, opcard-rs via vpcd as a single PC/SC reader, scdaemon on PC/SC (not internal-ccid); reader readiness is a poll-`gpg --card-status`-until-serial wait condition (not a fixed sleep); document that hardware uses the CCID path and is therefore HITL-divergent. (2) Give the VM's extra disks explicit qemu serials so `/dev/disk/by-id/...-<serial>` exists and drive the test through the allowlist path; assert the virtio boot disk is excluded by default AND two serial-bearing disks become selectable; document that real `rm`/`tran=usb` detection is HITL-divergent and stubbed via allowlist in VM.

### B13. GitHub Actions / binary-cache scope for spec #1

*(test-ci Q8 + Q-runner-contract)*
**Question:** Is an actual `.github/workflows/` file in spec #1's scope, and if so the exact contract: runner (ubuntu-latest public vs self-hosted), KVM gate, installer (DeterminateSystems nix-installer per the spike), `/mnt` reclamation (wimpysworld/nothing-but-nix), and binary cache (Cachix vs none) for opcard-rs + the VM-test closure? The repo currently has zero CI config (the spike workflow was deleted); DECIDED names only the Nix layer (`verify-hydra-jobset`).
**Why:** The headline claim is "CI-tested." With no Actions workflow, "CI" means only "runnable under Nix locally" — a materially different deliverable. Cachix-vs-none changes whether the opcard-rs Rust build is rebuilt every run, directly affecting whether the VM test fits the runner time/disk budget. Feasibility is already proven by the spike; only scope+config is open.
**Default:** In-scope and minimal: one `.github/workflows` file on ubuntu-latest using `DeterminateSystems/nix-installer-action` + `wimpysworld/nothing-but-nix`, invoking `verify-hydra-jobset` against `hydra-jobs/vm-tests.nix`, with a Cachix push/pull keyed on a project cache so opcard-rs and the VM-test closure are cached. Defer matrix/self-hosted.

______________________________________________________________________

## 2. Spec-time decisions

### S1. Per-role algorithm profile + certify-key expiration

*(drduh new-Q algorithm, drduh Q1; algorithm choice owned here, profile selection mechanism is B2)*
**Decision:** Define a per-role algorithm profile (not a single uniform KEY_TYPE) selected by the active policy. The encryption subkey may need a different algorithm than sign/auth under FIPS (cv25519/X25519 forbidden, RSA-decrypt blocked on FIPS hardware).
**Default:** Non-FIPS default: ed25519 certify + ed25519 sign + cv25519 encrypt + ed25519 auth; certify expiry = never (lifecycle via subkey expiry, matching drduh); subkey expiry = 2y. FIPS profile selects RSA-4096 across roles. Single decision-registry entry. (Getting this wrong produces keys that cannot decrypt on target hardware.)

### S2. Revocation certificate generated in-slice, stored secret-equivalent

*(drduh Q3 + new-Q, corporate Q3, security #3, test-ci Q3, ops-ux #3)*
**Decision:** drduh does NOT generate one, so there is no template and "do nothing" is unsafe — gpg's auto-written revocs.d cert is shredded with the tmpfs GNUPGHOME and lost forever. Generate it during the slice while the certify key is in tmpfs.
**Default:** Generate a full revocation certificate (`gpg --gen-revoke`), store it ONLY in the LUKS backups (it is secret-equivalent — anyone holding it can revoke the identity), never in the public export. Reason code = generic/unspecified (0). VM test asserts present in backup, absent from public export. Trivially VM-testable; if instead deferred, the audit/backup tests must not assume its presence.

### S3. Three independent secrets (GPG passphrase / LUKS passphrase / YubiKey PINs)

*(security-threat #LUKS-secret)*
**Decision:** The DECIDED list names only one "session passphrase." Confirm GPG master passphrase, LUKS backup-volume passphrase, and YubiKey PINs are *distinct* secrets — if LUKS pass == GPG pass, a single compromised passphrase yields the decrypted master directly from any stolen backup drive, collapsing the entire point of an encrypted offline backup.
**Default:** Three independent secrets. LUKS uses a tool-generated high-entropy key surfaced to the operator for custody; state explicitly that backup confidentiality depends on a secret NOT cached anywhere persistent. Revisit unification only with the escrow sub-project.

### S4. Entropy/CSPRNG preflight guard

*(security-threat #entropy, test-ci Q-RSA-budget)*
**Decision:** A freshly-booted air-gapped ISO with no persistent entropy store, no network, and possibly no hardware RNG can have a poorly-seeded pool early in boot. Weak entropy silently produces guessable keys/PINs/LUKS slots — catastrophic and undetectable after the fact. The CI VM masks this (virtio-rng); the real ISO may not.
**Default:** Preflight guard: require kernel "crng init done" / `getrandom()` readiness (prefer hardware RNG if present) before any key/secret generation; fail closed with a clear error otherwise. Provision the test VM with rng-tools/haveged and bump memory/disk. Real-hardware RNG validation stays deferred; the guard + stated assumption belong in spec #1.

### S5. Deterministic card-binding (reader + serial), not attestation

*(security-threat #device-trust)*
**Decision:** The flow has N YubiKeys plugged in at once; device-safety covers the *drive* side but not the symmetric *card* side. keytocard moves the only on-card copy of secret subkeys — binding scdaemon to the wrong reader or a rogue CCID device lands secrets on an attacker-controlled device. Genuine-YubiKey attestation is deferred; deterministic binding is not.
**Default:** Operator confirms the target card by reader name + card serial (AID/serial via `scdaemon --with-colons`); pin that exact card identity for the whole single-identity flow; assert the post-keytocard fingerprint readback comes from that same serial. Attestation stays deferred.

### S6. Locked-down tool-generated GNUPGHOME config

*(security-threat #gnupghome-config, drduh Q-gpgconf)*
**Decision:** DECIDED pins binary paths but says nothing about the gpg.conf/scdaemon.conf/dirmngr config the ephemeral GNUPGHOME is seeded with. A default config could attempt network access (dirmngr/keyserver), breaking the air-gap, or advertise weak cipher/digest preferences. Preference packets are baked into the key's self-signature and hard to change later.
**Default:** Tool-generated GNUPGHOME config: dirmngr/keyserver/auto-key-retrieve fully disabled (no network), cross-certification required, `personal-cipher-preferences`/`personal-digest-preferences` set per active policy (default AES256/SHA512 first). Treat as a baked, hash-pinned asset alongside the policy, not operator-editable. VM test verifies advertised prefs via `--export` + `--list-packets` / `--edit-key showpref`.

### S7. Bootstrap-path gating

*(corporate-reqs Q6)*
**Decision:** The bootstrap (self-asserted + ephemeral-signed) path relaxes the "operator YubiKey signs the audit" guarantee. If the tool silently takes it whenever no operator key is present, every run is trivially downgradable to self-asserted by just not presenting a key — the identity-binding guarantee collapses.
**Default:** Bootstrap taken only when `allow_bootstrap=true` AND no operator key is supplied; stamps record `identity_assurance=self-asserted` with embedded ephemeral pubkey. Default `allow_bootstrap=true` for slice #1 (genesis run works), but make it a policy-lockable field the security team sets false after the first operator key exists. Normal path preferred whenever an operator key is supplied; never silently prefer bootstrap.

### S8. Touch-policy decision recorded now, applied later (HITL)

*(drduh Q-touch)*
**Decision:** drduh sets touch=on for sig/dec/aut via ykman; ykman ops + touch policy are in the DEFERRED (HITL) set, and the flow uses a virtual opcard-rs that can't take the ykman call. But the *decision* (which slots require touch) should be in the registry now so flags/config/audit fields exist from day one.
**Default:** Declare a touch-policy decision in the registry now (default touch=on for sig/dec/aut, cached where supported), recorded in audit; mark the ykman application step deferred/HITL; do not attempt to apply it to opcard-rs in the slice.

### S9. On-card state read-back assertions (not just exit codes)

*(test-ci Q-readback)*
**Decision:** A test checking only that commands returned 0 passes even if keytocard moved nothing or factory-reset left key references — defeating the point of testing against a real virtual card.
**Default:** Require read-back: parse `gpg --card-status --with-colons` to assert the three subkey fingerprints present on-card post-keytocard and absent post-factory-reset; assert KDF DO + PIN-change took effect via an operation that consumes the new PIN.

### S10. RSA-4096 / batch test budget split

*(test-ci Q-RSA-budget)*
**Decision:** RSA-4096 keygen is slow and entropy-hungry in a headless nested-KVM guest; the 2-identity batch doubles all card ops plus a factory-reset. "Proven once locally" ≠ "reliably green on a time-boxed public runner."
**Default:** Fast ed25519/cv25519 path = per-PR gate; RSA-4096 + full 2-identity batch = separate (nightly) job. Provision rng-tools/haveged, bump memory/disk, set an explicit testScript timeout and assert on it.

### S11. Decision-provenance plan preview / dry-run

*(ops-ux Q-provenance)*
**Decision:** The registry says values "carry provenance" as an audit field, but nothing surfaces it to the operator *before* the irreversible run. Every mutating step (keygen into shredded tmpfs, luksFormat, factory-reset) is irreversible; provenance is only valuable if the operator catches a wrong policy/config/default pre-execution.
**Default:** Mandatory pre-execution plan summary printing every resolved decision with its provenance label, requiring confirmation (interactive) or logged-and-proceeds (non-interactive). Add `--plan`/`--dry-run` that resolves+prints the full plan + provenance and exits 0 without touching card or drives. CI asserts plan output for both identities.

### S12. Re-run / collision / idempotency guard

*(ops-ux Q-idempotency)*
**Decision:** Air-gapped operators re-run things (typos, aborted batches, wrong drive from the pile). Because backup uses destructive `luksFormat`, an unguarded re-run silently destroys a prior identity's only backup — fatal for an already-factory-reset card.
**Default:** Slice is non-idempotent / single-shot: refuse to luksFormat a drive already containing a recognizable Keywright LUKS backup unless explicitly allowlisted/forced; refuse a run whose identity fingerprint or email already has a backup directory on a selected drive. No resume/merge (consistent with abort-only). State as a backup-step precondition.

______________________________________________________________________

## 3. Minor / safe-to-default (confirm-or-object)

### M1. Audit log line-format reproducibility + success run-summary

*(ops-ux Q-readability)* — Overlaps B7's canonicalization but adds the operator-takeaway angle. **Default:** Audit = JSON Lines, fixed declared field order, hash over canonical-JSON of (prev_hash + payload). On success print a human-readable summary block (card serial, fingerprint, drives by-id, output locations, factory-reset confirmation) to the terminal AND append `summary.txt` next to the audit log on each drive. Both derive from the same registry values.

### M2. Subkey set = S/E/A

Effectively settled by the drduh procedure the tool automates (three subkeys, three keytocard ops). **Default:** Confirm S/E/A; no action needed beyond stating it.

### M3. On-card public-key URL attribute

Part of drduh's card-attribute step. **Default:** Defer setting the on-card `url` attribute unless card-config (B3) is in-slice and policy requires it; state as deferred so it isn't silently dropped.

______________________________________________________________________

## 4. Flagged but actually already-decided / deferred

- **Audit scheme (Option A): model + storage location** — DECIDED (hash-chained, YubiKey-signed, append-only, backed up alongside keys). Only the *format/canonicalization/genesis* details remain open (now B7); the scheme and location themselves are settled. *(raised by drduh Q6, ops-ux #6)*
- **Compliance tags wired to the policy engine** — DECIDED that tags are wired; what was open (selection mechanism, lockable set, gate-vs-tag, profile trust) is now B1/B2/B3. *(drduh Q7)*
- **Test harness = Nix/Hydra** — DECIDED (`overlays.nixosTests` + `hydra-jobs/vm-tests.nix` + `verify-hydra-jobset`; repo runs on Hydra). The "GitHub Actions + Cachix" framing is mis-stated relative to the chosen CI; the *Actions-layer scope* that genuinely remains is B13. *(drduh Q8, corporate Q8, security #8)*
- **Default algorithm exists / both profiles keytocard-proven** — DECIDED that ed25519/cv25519 and RSA-4096 both keytocard against opcard-rs. The *per-role profile + expiration + default selection* is S1; the *remaining unproven card ops* are B8. *(security #1)*
- **Public key is non-secret; export works regardless of ordering** — The security dimension (accidental co-location/leak of the secret) folds into B5/B10; the bare "where" is a UX decision (B10), not a separate security gap. *(security #5)*
- **Config precedence (policy-locked > CLI > config > non-interactive-error)** — DECIDED as a precedence *rule*; its integrity depends entirely on B1 (policy trust root) and B2 (lockable-field enumeration).
- **RAII/Drop tmpfs wipe + "no secrets in ISO"** — DECIDED as mechanisms; B5 extends them with the certify-secret disposal *assertion* and the swap/TMPDIR/coredump escape paths they don't currently close.
