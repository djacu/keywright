# Keywright — `programs.keywright` NixOS Module (Config + Policy) Design Spec

**Status:** Draft for review · **Date:** 2026-06-24
**Scope:** A dedicated NixOS module that lets an organisation declare keywright's **operator config** and its **org policy** in their host/ISO configuration, render them into the read-only `/nix/store` at build time, validate them with keywright's own checker as a build gate, and wire them to the `keywright` binary so the *normal* (wrapped) invocation cannot loosen the policy by accident or config.

Related artifacts:

- `docs/superpowers/specs/2026-06-22-keywright-core-decision-layer-design.md` — the L0–L3 decision layer (§3 registry; §4 config/policy resolution, incl. the policy `/nix/store` canonicalization and "the operator's `--config`/`--policy` override cannot redirect the policy path"). This module is the *delivery surface* for the config/policy that §3/§4 consume.
- `docs/superpowers/specs/2026-06-20-keywright-foundation-design.md` — §9 (policy trust root: "baked into the read-only `/nix/store` at ISO build time… resolved by the NixOS module to a store path"; and the named residual that defending an operator who controls the boot medium is out of scope) and §8 (the signed, hash-chained provisioning audit). This spec implements the "resolved by the NixOS module" half of §9.
- `docs/superpowers/plans/2026-06-23-keywright-plan2a-…` / `…-plan2b-…` — the implementation-plan split of the decision-layer spec (currently in PR #6; not yet on `main`). Where this spec says "Plan 2a/2b" it means those plans; the primitives they implement (`load_policy`/`parse_policy`, `resolve()`, `compliance::validate`) are defined in the decision-layer spec §2/§4/§5.

______________________________________________________________________

## 1. What this delivers, and what it does not

A NixOS module under the `programs.keywright` namespace (shaped like `programs.git`: `enable`, `package`, plus settings) that:

1. exposes the operator **config** and the org **policy** as free-form settings attrsets (or file paths);
1. renders them to TOML in `/nix/store`;
1. **gates the build** on keywright's own static validator (`keywright check`) — a malformed or self-contradictory config/policy is a build error, not a field surprise;
1. wires the validated policy to the binary so the normal (wrapped) invocation cannot loosen it (within the threat model of §2).

It is **not** the ISO image build, the `mkHost` host-builder, measured/Secure-Boot image integrity, or `keywright-cli` itself — it is a building block those consume. See §9.

______________________________________________________________________

## 2. Threat model (scoped), and the honest boundary

**The operating security team is trusted.** The locked policy here exists to (i) prevent an operator from **accidentally** loosening the org posture (a config typo, a stray `--config`, a no-policy invocation) and (ii) **enforce a default posture across the fleet** — *not* to defend against a deliberate malicious insider. This is the deliberate consequence of choosing the Approach-1 wiring (§6) for its simplicity and Plan-2 orthogonality.

What this module **does** deliver, for the normal (wrapped) invocation: the operator cannot loosen the policy via the CLI, a config file, or the environment, and cannot run keywright with *no* policy (fail-closed, §6).

What it **does not** prevent — the honest residual, **correctly scoped to an ordinary (non-root) operator**, not just root:

> A *deliberate* operator can run the `keywright` binary **directly from the store** (bypassing the wrapper) and point `KEYWRIGHT_POLICY_FILE` at a **weaker or empty policy** — either one already present in the booted closure (this module emits empty "locks-nothing" policies as a valid posture), or one they add (`nix store add` is content-addressed and permitted to **all** daemon users, not only root/trusted). Canonicalization passes (the path *is* under `/nix/store`) because it is a path-**confinement** check, **not** an authenticity check — it cannot constrain *which* store policy is used.

This residual is **inside** the runtime-operator threat surface, so we mitigate it in layers rather than claim prevention:

- **Trusted-operator assumption** — the operating team is not modelled as an adversary.
- **Detective control — the signed, hash-chained provisioning audit (foundation §8):** a bypassed provisioning is still *recorded* (the algorithms, profile, and resolved values actually used), so a deliberate deviation from the locked policy is **detectable after the fact and deterred** — it does not silently succeed.
- **Prevention is deferred** to the ISO-lockdown sub-project (kiosk / no arbitrary execution / restricted nix-daemon) and ultimately measured/Secure-Boot (the boot-medium adversary, foundation §9) — **out of scope here**, and now named as a dependency of *full* runtime prevention, not only of the boot-medium threat.

So, scoped honestly: **preventive** against accidents + posture-by-default; **detective** via the audit; **deferred** (ISO-lockdown) for a deliberate operator. The boot-medium adversary (a modified/self-built ISO) remains the separate measured-boot sub-project.

______________________________________________________________________

## 3. The `programs.keywright` module

```nix
programs.keywright = {
  enable     = mkEnableOption "Keywright YubiKey/OpenPGP provisioning";
  package    = mkPackageOption pkgs "keywright" { };

  # Operator config: a baked default, OVERRIDABLE at runtime (`keywright --config <path>`).
  config     = mkOption { type = with types; nullOr (pkgs.formats.toml { }).type; default = null; }; # XOR configFile
  configFile = mkOption { type = with types; nullOr path;                          default = null; };

  # Org policy: baked + forced on the wrapped binary (§6).
  policy     = mkOption { type = with types; nullOr (pkgs.formats.toml { }).type; default = null; }; # XOR policyFile
  policyFile = mkOption { type = with types; nullOr path;                          default = null; };
};
```

- **`null` is the genuine "unset" sentinel.** A freeform-TOML option with `default = { }` is *indistinguishable* from an operator setting an explicit `{ }` (the freeform type registers a definition for its own default), so a clean XOR is unimplementable with `{ }`. With `nullOr … type` + `default = null`, "unset" (`null`) is distinct from "explicitly empty" (`{ }`), and the XOR is a real check.
- **Assertions:** `assertion = !(cfg.config != null && cfg.configFile != null)` (and the same for `policy`/`policyFile`) — set the attrset XOR the file, not both.
- **"Locks nothing"** is an *explicit* `policy = { }` (or simply leaving both `policy` and `policyFile` unset → the module renders an empty policy, §5). Either way the binary still always receives *a* policy file (fail-closed, §6); it just locks no decisions. `null` ≠ `{ }`: `null` = "I didn't set this surface," `{ }` = "an empty policy."
- **Free-form settings** (RFC-42 idiom): keys map to decision ids; **keywright-core is the single validator** (§5). The module does **not** re-encode the registry in Nix types — that would be a second source of truth that could drift from the Rust `DECISIONS` slice.
- **`enable`** gates everything: when on, the wrapped binary (§6) is placed on the system PATH.
- Lives at `nixosModules/keywright/module.nix` (auto-discovered by the existing `nixosModules/default.nix`, which imports `*module.nix`).

______________________________________________________________________

## 4. Config vs Policy — one registry, overlapping keys

`config` and `policy` are **not** separate namespaces. They are two **input channels** that both target decision ids in the **same** `DECISIONS` registry (decision-layer §3). `resolve()` merges them by precedence (`policy-locked > CLI > config > default`) into one `ResolvedSet`. The difference is **enforcement, not key-space**:

| Decision class | settable in `config`? | lockable in `policy`? | examples |
|---|---|---|---|
| Governance (`lockable=true`) | yes | yes | `compliance-profile`, `algo`, `pin-min-length`, `device-allowlist` … (13) |
| Per-run / identity (`config=true, lockable=false`) | yes | no | `target-card-serial`, `asserted-date`, `real-name`, `email` |
| Secrets / destructive tokens | no | no | `user-pin` (fd/stdin), `confirm-format` (CLI-only) |

So the policy-lockable keys are a **subset** of the config-settable keys. A governance key can appear in **both** — `config` as an overridable default, `policy` as a lock. When both name it: **policy wins; a *different* `config` value is a named error; an *identical* value is accepted.** (This refines decision-layer §3's "rejects any lower-precedence override" to "rejects a *conflicting* override" — the conflict rule updated in PR #6's decision-layer §3/§4.) The build gate (§5) enforces **policy ⊆ lockable**: a non-lockable key placed in `programs.keywright.policy` fails the build, because `parse_policy` (Plan 2a) rejects a non-lockable or unknown id with a named error.

______________________________________________________________________

## 5. Build-time validation (the gate + the `check` contract)

The org builds the ISO once and ships it; a malformed or self-contradictory config/policy must fail **then**, not on an air-gapped box in the field. After rendering, the module runs keywright's own static validator as a **gate derivation**:

```nix
let
  fmt        = pkgs.formats.toml { };
  policyAttr = if cfg.policy != null then cfg.policy else { };   # unset → empty (locks nothing)
  configAttr = if cfg.config != null then cfg.config else { };
  policyToml = if cfg.policyFile != null then cfg.policyFile else fmt.generate "keywright-policy.toml" policyAttr;
  configToml = if cfg.configFile != null then cfg.configFile else fmt.generate "keywright-config.toml" configAttr;

  checked = pkgs.runCommand "keywright-checked" { } ''
    ${lib.getExe cfg.package} check --config ${configToml} --policy ${policyToml}
    mkdir -p $out                  # pass the validated files through; consumers depend on the check
    cp ${policyToml} $out/policy.toml
    cp ${configToml} $out/config.toml
  '';
in ...
```

A non-zero `keywright check` (which validates **both** config and policy) fails the derivation → fails the system/ISO build. Because the §6 wrapper points `KEYWRIGHT_POLICY_FILE` at `${checked}/policy.toml`, the wrapper cannot build unless the check passed on both.

**`keywright check --config <path> --policy <path>` contract** (a forward dependency on `keywright-cli`; this spec fixes its behaviour). Non-interactive; reads only the two TOML paths; **no devices / card / clock / network** → runs in the hermetic build sandbox. It runs:

1. `load_policy(<policy>)` — canonicalize under `/nix/store`; **reject any non-lockable or unknown key** (Plan 2a `parse_policy`; the policy ⊆ lockable gate).
1. `parse_config(<config>)` — TOML well-formedness (+ identity shape, if present).
1. `resolve(empty-cli, config, policy)` in a **check-lenient disposition** — per-value validation **+ the config↔policy conflict check**, but it **leaves missing per-run/identity fields (`real-name`/`email`/`asserted-date`) unresolved instead of hard-erroring or prompting**. This is a *distinct* resolve mode (see §7 forward contract 4): not `interactive=false` (which hard-errors on missing-required) and not `interactive=true` (which prompts — impossible in the sandbox). Those fields are supplied at provisioning, not baked.
1. `compliance::validate_static(resolved)` — the **clock-independent** compliance rules only (global RSA floor, FIPS/CNSA/BSI forbid-lists, RSA size bounds). It **skips the dated expiry-horizon checks**, which need the real provisioning date.

Exit `0` on success; non-zero + the named, non-secret reason on any failure (e.g. `compliance-profile: policy-locked; config value conflicts`; `decision target-card-serial is not lockable`; `RSA-1024 below global minimum`).

**Explicitly not checked at build:** per-run/identity fields, the dated expiry horizons, and anything needing hardware — all of which belong to the real provisioning run.

**Accepted residual (dated horizons):** a policy that *locks* a non-compliant expiry (past a dated BSI/CNSA horizon) passes the clock-independent build gate and is caught **only at the in-field provisioning run** (where runtime `compliance::validate(resolved, now)` hard-rejects it). This is safe-direction — refusal in the field, not bad keys — but it is a deferred-to-field failure for that one error class, by design, because the horizons cannot be evaluated without the provisioning clock.

______________________________________________________________________

## 6. Wiring (Approach 1: wrapper-set env + fail-closed binary)

```nix
pkgs.runCommand "keywright-wrapped" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
  makeWrapper ${lib.getExe cfg.package} $out/bin/keywright \
    --set         KEYWRIGHT_POLICY_FILE ${checked}/policy.toml \
    --set-default KEYWRIGHT_CONFIG_FILE ${checked}/config.toml
''
```

- **Policy path is forced** (`--set`): the wrapper exports `KEYWRIGHT_POLICY_FILE` unconditionally, clobbering any operator-set value, so a runtime env/flag cannot redirect it **through the wrapped binary**. (The unwrapped-binary path is §2's residual.)
- **Config path is a default** (`--set-default`): `keywright --config <path>` overrides it (config is overridable; §4). Note `--set-default` emits `${VAR-default}` (replaces only when *unset*, not when set-to-empty), so the binary's `--config`/`KEYWRIGHT_CONFIG_FILE`/built-in-defaults precedence must treat an **empty** `KEYWRIGHT_CONFIG_FILE` as "use built-in defaults," not "read the empty path."
- **The binary reads `KEYWRIGHT_POLICY_FILE`, canonicalizes it under `/nix/store` (decision-layer §4), and fail-closes if unset or invalid** — so there is no implicit "no-policy = unlocked" path. A standalone/dev run must pass an explicit policy (even an empty, locks-nothing one). This **fail-closed-on-unset** is the keystone safety property (§7 acceptance criterion).
- **No operator-facing flag sets the policy *path*** — it comes only from the env the wrapper controls (decision-layer §4: "the operator's `--config`/`--policy` override cannot redirect the policy path"). Any `--policy` the CLI exposes must not redirect the baked path.

This delivers §2's accident/config-level protection for the normal (wrapped) interface; the deliberate-operator residual (the unwrapped-binary path) is §2's stated, layered boundary — not prevented here.

______________________________________________________________________

## 7. Reconciliation with keywright-core (Plan 2) — forward contracts

This module needs **no change to keywright-core's `policy` module** (Plan 2a `load_policy`/`parse_policy`, incl. its existing rejection of a non-lockable/unknown key, and the `/nix/store` canonicalization). The *resolution* path gains a small additive mode (contract 4); the policy module itself is unchanged.

**Forward contracts** this spec defines, to be implemented in `keywright-cli` / a small keywright-core tweak in a later plan (not in PR #6 / Plan 2):

1. **A `check` subcommand** (§5) wiring `load_policy` + `parse_config` + check-lenient `resolve` + `compliance::validate_static` into a 0/non-zero exit.
1. **`compliance::validate_static(&ResolvedSet)`** — splitting the decision-layer §5 `validate(set, now)` into a clock-independent part (`validate_static`) + the dated horizon checks, so `check` can run the former without a clock. (Clean separation; useful regardless.)
1. **Policy-path wiring + fail-closed (a binding acceptance criterion):** the binary obtains its policy path from `KEYWRIGHT_POLICY_FILE` and **must fail-closed — exit non-zero, materialize no key/secret — when that env is unset or fails `/nix/store` canonicalization**, with no runtime override of the path. Config comes from `--config <path>` else `KEYWRIGHT_CONFIG_FILE` (empty ⇒ built-in defaults) else built-in defaults. *A future CLI that treated "no policy env" as "empty/locks-nothing" would violate this and must be caught by the integration test (§8).*
1. **A check-lenient resolve mode** — a *distinct* disposition (e.g. `resolve(..., Mode::CheckLenient)` / `resolve_lenient()`) that records missing per-run/identity (`required=true`, no value) decisions as **unresolved/deferred** rather than prompting or hard-erroring, while still running per-value validation, locked-override rejection, and the config↔policy conflict check. It is **not** expressible via the existing two-valued `interactive` flag, so it is a small additive change to the keywright-core resolution path.

______________________________________________________________________

## 8. Testing strategy (two tiers)

**Module-level (now — pure eval + build, no real keywright):**

- **XOR assertions:** evaluate the module with both `config`+`configFile` set, then `policy`+`policyFile` set; assert the eval fails — **including the `config = { }` + `configFile` case** (the `null` sentinel now distinguishes "explicitly empty" from "unset," so this is caught, unlike with a `{ }` default).
- **TOML render:** build the rendered `policy.toml`/`config.toml` from a sample attrset; diff against expected — confirms `pkgs.formats.toml` round-trips (incl. an empty `{ }`).
- **Wrapper wiring + fail-closed gate:** inspect the wrapped script — it `--set KEYWRIGHT_POLICY_FILE` (forced) **on every code path**, supplies **no fallback/default policy**, `--set-default KEYWRIGHT_CONFIG_FILE`, and the baked policy path is the gate's `checked` output (so the wrapper transitively depends on the check building). This asserts, in *this spec's own deliverable*, that the module never produces a no-policy invocation — a regression toward a no-policy path is caught here, before the deferred VM test.
- **Gate propagation:** with a **stub** `keywright` package whose `check` exits non-zero on a marker, assert a failing check fails the build and a passing one builds — tests the wiring (`runCommand` non-zero ⇒ build failure) without the real validator.

**Integration (deferred — needs the real `keywright check` + the fail-closed/policy-env binary):** a NixOS VM test (`overlays/nixos-tests/<name>/`): `programs.keywright.enable` with a real policy → the booted `keywright` enforces it; a config↔policy conflict **fails the build** with the named error; the binary **fail-closes** (non-zero, no key material) with `KEYWRIGHT_POLICY_FILE` unset (contract 3); `--config` overrides the baked config but **cannot redirect the policy**. Sequenced after `keywright-cli` gains `check` + policy-env reading.

______________________________________________________________________

## 9. Non-goals (deferred / separate)

- **ISO-integrity / kiosk lockdown / measured-/Secure-Boot** — both the boot-medium adversary (foundation §9) **and** the in-scope deliberate-operator residual of §2 (whose *prevention* needs the kiosk/no-arbitrary-execution/restricted-daemon lockdown). The audit trail (§2) is the detective backstop until then.
- **The ISO image build / `mkHost` / `nixos-configs` matrix** (foundation §1.1) — this module is a building block such a config consumes; building the ISO is separate.
- **Implementing `keywright check`, the check-lenient resolve mode, and the fail-closed policy-env reading in `keywright-cli`/core** — later-plan work; this spec only fixes the contracts (§7).
- **Build-time checking of the dated compliance horizons + any device/card behavior** — need the real provisioning clock/hardware; explicitly outside `check` (§5).
- **Home-Manager / non-NixOS deployment.**

______________________________________________________________________

## 10. Forward-contract summary (for later plans)

| Contract | Consumer | Owner |
|---|---|---|
| `keywright check --config <p> --policy <p>` (static, sandbox-pure, 0/non-zero) | the build gate (§5) | `keywright-cli` (later) |
| `compliance::validate_static(&ResolvedSet)` (clock-independent split of decision-layer §5 `validate`) | `check` | keywright-core (small tweak, later) |
| check-lenient `resolve` mode (missing per-run/identity → unresolved, not prompt/error) | `check` | keywright-core (small tweak, later) |
| policy path from `KEYWRIGHT_POLICY_FILE`, **fail-closed if unset/invalid**, non-redirectable; config from `--config`/`KEYWRIGHT_CONFIG_FILE`(empty⇒defaults)/defaults | the wrapper (§6) | `keywright-cli` (later, acceptance criterion) |

This module can be **specced and its module-level pieces built + unit-tested now** (§8 tier 1); the integration test + the four forward contracts land when `keywright-cli` exists.
