# Keywright Foundation — Plan 1: Infrastructure & CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Rust workspace, the `opcard-rs` virtual-card package, and the NixOS-VM test harness so that the proven keytocard test (ECC **and** RSA-4096) runs green in GitHub Actions CI against a virtual OpenPGP card.

**Architecture:** A Cargo workspace (`keywright-core` lib + `keywright-cli` bin) packaged via `buildRustPackage` and auto-discovered by the flake's `overlays/top-level`. `opcard-rs` is packaged the same way. VM tests live as directories under `overlays/nixos-tests/`, exposed by a separate `overlays.nixosTests` overlay as `pkgs.keywrightTests` and built per-system by `hydra-jobs/vm-tests.nix` (via `mapTestOn`), which a GitHub Actions workflow runs through `verify-hydra-jobset`.

**Tech Stack:** Rust (stable, edition 2021) · `rustPlatform.buildRustPackage` · nixpkgs-unstable (flake-pinned) · `pkgs.testers.runNixOSTest` · `vsmartcard-vpcd` + `pcscd` · `opcard-rs` v1.7.0 · GitHub Actions (`DeterminateSystems/nix-installer-action`, `wimpysworld/nothing-but-nix`, `cachix/cachix-action`) · `verify-hydra-jobset`.

## Global Constraints

- Target system for this plan: **`x86_64-linux`** only (`supportedSystems = [ "x86_64-linux" ]`); the per-system jobset structure is preserved so more arches drop in later.
- nixpkgs is **flake-pinned** (`flake.lock`); do not bump it in this plan.
- All commits are **GPG-signed** with the maintainer's YubiKey (`commit.gpgsign=true`); a `pinentry` prompt is expected per commit when the agent cache is cold — the maintainer enters the PIN. Do **not** use `--no-gpg-sign`.
- Formatting is enforced by `treefmt` (`nix fmt`); run it before each commit so `checks` stay green.
- This plan touches **no secrets and no real hardware** — the card is the `opcard-rs` virtual card; `ykman`-path ops are out of scope (the seam).
- The reusable, *proven* source for the migration is the throwaway spike at `/home/djacu/dev/djacu/yk-spike-keystone` (its `flake.nix` holds the working `opcard-vpicc` package + both test scripts; `opcard-src/Cargo.lock` is the generated lock). Copy from it; do not re-derive.

---

## File Structure

```
overlays/top-level/keywright/
  package.nix            # buildRustPackage of the workspace -> pkgs.keywright
  Cargo.toml             # workspace manifest
  Cargo.lock             # committed
  crates/keywright-core/{Cargo.toml, src/lib.rs}
  crates/keywright-cli/{Cargo.toml, src/main.rs}
overlays/top-level/opcard-rs/
  package.nix            # buildRustPackage of opcard-rs vpicc example -> pkgs.opcard-rs (bin: vpicc)
  Cargo.lock             # committed (generated; upstream ships none)
overlays/nixos-tests/
  keytocard-ecc/package.nix   # runNixOSTest: ed25519/cv25519 keytocard on the virtual card
  keytocard-rsa/package.nix   # runNixOSTest: RSA-4096 keytocard on the virtual card
overlays/default.nix     # MODIFY: add a separate `nixosTests` overlay exposing pkgs.keywrightTests
formatterModule/default.nix # MODIFY: enable rustfmt so `nix fmt` formats Rust
hydra-jobs/vm-tests.nix  # NEW: mapTestOn over pkgs.keywrightTests (tests overlay via extraOverlays)
.github/workflows/ci.yml # NEW: install nix -> assert KVM -> verify-hydra-jobset vm-tests
```

---

### Task 1: Rust workspace skeleton (`keywright-core` + `keywright-cli`)

**Files:**
- Create: `overlays/top-level/keywright/Cargo.toml`
- Create: `overlays/top-level/keywright/crates/keywright-core/Cargo.toml`
- Create: `overlays/top-level/keywright/crates/keywright-core/src/lib.rs`
- Create: `overlays/top-level/keywright/crates/keywright-cli/Cargo.toml`
- Create: `overlays/top-level/keywright/crates/keywright-cli/src/main.rs`
- Create: `overlays/top-level/keywright/Cargo.lock` (generated)
- Modify: `formatterModule/default.nix` (enable `rustfmt` so `nix fmt` formats Rust)

**Interfaces:**
- Produces: a Cargo workspace with a binary `keywright` (from `keywright-cli`) and a library crate `keywright-core` exposing `pub fn version() -> &'static str`. Task 2 packages this; Plans 2–3 add real modules/commands.

- [ ] **Step 1: Write the failing core test**

`overlays/top-level/keywright/crates/keywright-core/src/lib.rs`:
```rust
//! Keywright core engine (UI-agnostic). Real modules land in Plan 2.

/// Returns the compiled crate version (proves the lib builds and is testable).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }
}
```

- [ ] **Step 2: Enable `rustfmt` in treefmt, then create the manifests and CLI**

First enable Rust formatting so the `nix fmt` in Step 4 also formats the `.rs` files. In `formatterModule/default.nix`, add this alongside the other `programs.*` lines inside the `evalModule` block:

```nix
    programs.rustfmt.enable = true;
```

(No `edition` line needed — treefmt-nix's `rustfmt` already defaults `--edition` to `2024`, which matches the crates below. Only set `programs.rustfmt.edition` if the crates ever target a different edition.)

Then create the workspace files.

`overlays/top-level/keywright/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/keywright-core", "crates/keywright-cli"]
```

`overlays/top-level/keywright/crates/keywright-core/Cargo.toml`:
```toml
[package]
name = "keywright-core"
version = "0.0.1"
edition = "2024"
```

`overlays/top-level/keywright/crates/keywright-cli/Cargo.toml`:
```toml
[package]
name = "keywright-cli"
version = "0.0.1"
edition = "2024"

[[bin]]
name = "keywright"
path = "src/main.rs"

[dependencies]
keywright-core = { path = "../keywright-core" }
clap = { version = "4", features = ["derive"] }
```

`overlays/top-level/keywright/crates/keywright-cli/src/main.rs`:
```rust
use clap::Parser;

/// Keywright — air-gapped YubiKey/OpenPGP provisioning.
#[derive(Parser)]
#[command(name = "keywright", version)]
struct Cli {}

fn main() {
    Cli::parse();
    eprintln!(
        "keywright {} — provisioning commands arrive in plan 3",
        keywright_core::version()
    );
}
```

- [ ] **Step 3: Generate the lockfile and run the test (expect PASS)**

Run (from the workspace dir):
```bash
cd overlays/top-level/keywright
nix run nixpkgs#cargo -- generate-lockfile
nix run nixpkgs#cargo -- test
```
Expected: `Cargo.lock` created; `test version_is_nonempty ... ok`; `keywright --version` later prints `keywright 0.0.1`.

- [ ] **Step 4: Format and commit**

```bash
cd /home/djacu/dev/djacu/yubikey-loader
nix fmt   # now also formats the .rs files (rustfmt enabled in Step 2)
git add formatterModule/default.nix overlays/top-level/keywright/Cargo.toml overlays/top-level/keywright/Cargo.lock overlays/top-level/keywright/crates
git commit -m "feat(keywright): rust workspace skeleton + enable treefmt rustfmt"
```
Expected: signed commit succeeds (enter PIN at the pinentry).

---

### Task 2: Package `keywright` via `buildRustPackage`

**Files:**
- Create: `overlays/top-level/keywright/package.nix`

**Interfaces:**
- Consumes: the workspace from Task 1.
- Produces: `pkgs.keywright` (auto-discovered by `overlays/top-level` → in `overlays.default` → in `legacyPackages`), `meta.mainProgram = "keywright"`.

- [ ] **Step 1: Write `package.nix` (fileset src, committed lock)**

`overlays/top-level/keywright/package.nix`:
```nix
{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "keywright";
  version = "0.0.1";

  # Only the build-relevant files — editing package.nix must not bust the build cache.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./crates
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "Air-gapped YubiKey/OpenPGP key provisioning";
    mainProgram = "keywright";
  };
}
```

- [ ] **Step 2: Build it and verify the binary**

Run:
```bash
nix build .#keywright -L
./result/bin/keywright --version
```
Expected: build exits 0; `keywright 0.0.1`.

- [ ] **Step 3: Format and commit**

```bash
nix fmt
git add overlays/top-level/keywright/package.nix
git commit -m "feat(keywright): package the workspace with buildRustPackage"
```

---

### Task 3: Package `opcard-rs` (virtual OpenPGP card)

**Files:**
- Create: `overlays/top-level/opcard-rs/package.nix`
- Create: `overlays/top-level/opcard-rs/Cargo.lock` (copied from the spike)

**Interfaces:**
- Produces: `pkgs.opcard-rs` — a derivation whose `$out/bin/vpicc` is the opcard-rs `vpicc` example (RSA-4096-capable). `meta.mainProgram = "vpicc"`. Tasks 5–6 reference it as the `opcard-rs` arg.

- [ ] **Step 1: Copy the proven generated lockfile**

Run:
```bash
mkdir -p overlays/top-level/opcard-rs
cp /home/djacu/dev/djacu/yk-spike-keystone/opcard-src/Cargo.lock overlays/top-level/opcard-rs/Cargo.lock
test -s overlays/top-level/opcard-rs/Cargo.lock && echo OK
```
Expected: `OK`. (Fallback if the spike is gone: `nix run nixpkgs#cargo -- generate-lockfile` inside a fresh checkout of `github:Nitrokey/opcard-rs` at v1.7.0, then copy its `Cargo.lock`.)

- [ ] **Step 2: Write `package.nix` (fetchFromGitHub + the 7 git-dep outputHashes)**

`overlays/top-level/opcard-rs/package.nix`:
```nix
{
  lib,
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  pcsclite,
  nettle,
  openssl,
}:
let
  version = "1.7.0";
in
rustPlatform.buildRustPackage {
  pname = "opcard-rs";
  inherit version;

  src = fetchFromGitHub {
    owner = "Nitrokey";
    repo = "opcard-rs";
    rev = "v${version}"; # if the tag is absent, use the commit: 2b94d6a… (rev-parse the spike clone)
    hash = ""; # FILL: set to lib.fakeHash, run `nix build .#opcard-rs`, copy the reported hash
  };

  cargoLock = {
    lockFile = ./Cargo.lock;
    # opcard-rs pulls 7 git-patched deps; one representative crate per git source.
    outputHashes = {
      "admin-app-0.1.0" = "sha256-eWHEN2Wc0UwNKVpu2h1HFkVHEJCMXwYBjxJO1w6zBtY=";
      "p256-cortex-m4-0.1.0-alpha.6" = "sha256-rLDNp+cnh6NfYAss37nEw7/rgM2DXDWWjQ6KnBgcSr8=";
      "trussed-0.1.0" = "sha256-ZlVqYxmZJYgW57clO+gExzemAewhqZIFamrQ7zYWikg=";
      "trussed-auth-backend-0.1.0" = "sha256-JhyvAGa0g0ff4oE0+zZKRoA2SeZRtZsjAGkqkJNe6m4=";
      "trussed-rsa-alloc-0.4.0" = "sha256-nHDiq6mGU8ZpgJNOPnmPEW3XReuNh+sogozM1zgjKwU=";
      "trussed-staging-0.4.0" = "sha256-yanTqzjgt9yUIP34izrGK9GrGWuKDoBta1z0JUCX+4A=";
      "trussed-usbip-0.0.1" = "sha256-jB79OLTqzNkfaDn59bgj/PRKWjhmJ8EaP2zn0bvScYo=";
    };
  };

  # Build only the vpicc example, with the vpicc + RSA-4096 features.
  buildFeatures = [ "vpicc" "rsa4096-gen" ];
  cargoBuildFlags = [ "--example" "vpicc" ];
  # Upstream's cargo tests need a live card; the VM test is the real exercise.
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];
  buildInputs = [
    pcsclite
    nettle
    openssl
  ];

  # buildRustPackage installs declared bins, not examples — install the example by hand.
  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    find target -type f -name vpicc -path '*release/examples/*' -exec install -Dm755 {} $out/bin/vpicc \;
    test -x $out/bin/vpicc || { echo "vpicc example binary not found"; exit 1; }
    runHook postInstall
  '';

  meta = {
    description = "opcard-rs vpicc virtual OpenPGP smartcard (test dependency)";
    mainProgram = "vpicc";
  };
}
```

- [ ] **Step 3: Fill the source hash**

Run:
```bash
sed -i 's/hash = "";/hash = lib.fakeHash;/' overlays/top-level/opcard-rs/package.nix
nix build .#opcard-rs -L 2>&1 | tee /tmp/opcard-build.log || true
# copy the "got: sha256-…" value from the error into the hash field:
grep -E 'got:' /tmp/opcard-build.log
```
Then set `hash = "sha256-…";` to the reported value and rebuild:
```bash
nix build .#opcard-rs -L
./result/bin/vpicc --help 2>&1 | head -1 || ls -l result/bin/vpicc
```
Expected: build exits 0; `result/bin/vpicc` exists. (If `rev = "v1.7.0"` errors as an unknown ref, set `rev` to the spike's commit: `git -C /home/djacu/dev/djacu/yk-spike-keystone/opcard-rs rev-parse HEAD`, then refill the hash.)

- [ ] **Step 4: Format and commit**

```bash
nix fmt
git add overlays/top-level/opcard-rs/package.nix overlays/top-level/opcard-rs/Cargo.lock
git commit -m "feat(opcard-rs): package the vpicc virtual OpenPGP card (test dep)"
```

---

### Task 4: Add the `nixosTests` overlay (exposing `pkgs.keywrightTests`)

**Files:**
- Modify: `overlays/default.nix`

**Interfaces:**
- Consumes: `pkgs.opcard-rs` (Task 3); test packages discovered from `overlays/nixos-tests/` (Tasks 5–6).
- Produces: `inputs.self.overlays.nixosTests` — a **separate** overlay (NOT in `overlays.default`) that adds `pkgs.keywrightTests.<name>` for each directory under `overlays/nixos-tests/`. Task 7 injects it via `extraOverlays`.

- [ ] **Step 1: Add the overlay and export it**

In `overlays/default.nix`, add `recurseIntoAttrs` to the `lib.attrsets` inherit, define the overlay, and export it (do **not** add it to `default`). Apply this diff:

Add to the inherits near the top:
```nix
  inherit (lib.attrsets)
    recurseIntoAttrs
    ;
```

Add the overlay definition alongside `top-level` (after the `top-level` binding):
```nix
  # VM tests, kept OUT of `default` so they don't load nixos/lib into the
  # packages jobset. Injected into hydra-jobs/vm-tests.nix via extraOverlays.
  nixosTests =
    final: _prev: {
      keywrightTests = recurseIntoAttrs (packagesFromDirectoryRecursive {
        inherit (final) callPackage;
        directory = ./nixos-tests;
      });
    };
```

Add `nixosTests` to the returned set (the final `in { inherit … }` block):
```nix
  inherit
    default
    fixes
    nixosTests
    python-packages
    top-level
    ;
```

- [ ] **Step 2: Create the directory so discovery has something to read**

Run:
```bash
mkdir -p overlays/nixos-tests
```
(Tasks 5–6 add the test packages; the empty dir keeps `packagesFromDirectoryRecursive` happy.)

- [ ] **Step 3: Verify packages resolve (no build)**

Run:
```bash
nix eval .#legacyPackages.x86_64-linux.keywright.name --raw && echo
nix eval .#legacyPackages.x86_64-linux.opcard-rs.name --raw && echo
nix eval --impure --expr 'let p = (builtins.getFlake (toString ./.)).overlays.nixosTests; in builtins.isFunction p'
```
Expected: `keywright-0.0.1`, `opcard-rs-1.7.0`, `true`.

- [ ] **Step 4: Format and commit**

```bash
nix fmt
git add overlays/default.nix
git commit -m "feat(overlays): add nixosTests overlay exposing pkgs.keywrightTests"
```

---

### Task 5: Migrate the ECC keytocard VM test

**Files:**
- Create: `overlays/nixos-tests/keytocard-ecc/package.nix`

**Interfaces:**
- Consumes: `testers`, `opcard-rs` (Task 3) via `callPackage`.
- Produces: `pkgs.keywrightTests.keytocard-ecc` — a `runNixOSTest` derivation.

- [ ] **Step 1: Write the test package (rationale comments tie each assertion to a requirement)**

`overlays/nixos-tests/keytocard-ecc/package.nix`:
```nix
{
  testers,
  opcard-rs,
}:
# WHY: proves the project's core feasibility premise — gpg can drive the
# irreversible `keytocard` step against a VIRTUAL OpenPGP card, headlessly, with
# NO hardware — and is the regression guard against opcard-rs/nixpkgs/gpg bumps.
testers.runNixOSTest {
  name = "keywright-keytocard-ecc";

  nodes.machine =
    { pkgs, ... }:
    {
      # pcscd + vsmartcard-vpcd present opcard as a single "Virtual PCD" reader.
      services.pcscd = {
        enable = true;
        plugins = [
          pkgs.ccid
          pkgs.vsmartcard-vpcd
        ];
      };
      services.vsmartcard-vpcd.enable = true; # port 35963, listening mode
      programs.gnupg.agent.enable = true;
      environment.systemPackages = [
        pkgs.gnupg
        pkgs.pcsc-tools
        opcard-rs
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
    };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("pcscd.socket")
    machine.succeed("systemctl start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # WHY: force gpg/scdaemon onto PC/SC (the internal CCID driver can't see the
    # virtual reader). Mirrors opcard-rs ci/Dockerfile.
    machine.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg")
    machine.succeed("printf 'disable-ccid\\npcsc-shared\\n' > /root/.gnupg/scdaemon.conf")

    # Start the opcard vpicc card; it connects out to vpcd:35963.
    machine.succeed("systemd-run --unit=opcard-vpicc --setenv=RUST_LOG=info ${opcard-rs}/bin/vpicc")
    # WHY: gpg must actually SEE an OpenPGP card (the opcard AID), not just a reader.
    machine.wait_until_succeeds("gpg --card-status 2>&1 | grep -q 'D276000124010304'", timeout=60)

    PW3 = "12345678"
    GPG = "gpg --command-fd=0 --status-fd=2 --with-colons --pinentry-mode loopback --expert --no-tty"

    def gpg_feed(args, lines):
        script = "".join(l + "\n" for l in lines)
        return machine.succeed("printf %s " + shlex.quote(script) + " | " + GPG + " " + args + " 2>&1")

    # Generate an OFF-card ed25519 primary + cv25519 encryption subkey.
    gpg_feed("--full-gen-key", ["9", "1", "0", "ECC Tester", "ecc@example.com", "no comment", "", ""])

    before = machine.succeed("gpg -K --with-colons")
    assert "ssb:" in before, "expected an off-card encryption subkey before keytocard"

    # WHY: move the encryption subkey (slot 2) and the primary (slot 1) onto the card.
    gpg_feed("--edit-key ecc@example.com", ["key *", "keytocard", "2", PW3, PW3, "save"])
    gpg_feed("--edit-key ecc@example.com", ["keytocard", "y", "1", PW3, "save"])

    after = machine.succeed("gpg -K")
    status = machine.succeed("gpg --card-status")
    # WHY: the '>' stub markers are DISPOSITIVE — gpg only prints them once the
    # secret was actually moved onto the card and replaced by a stub.
    assert "sec>" in after, "primary not on-card (no sec> marker):\n" + after
    assert "ssb>" in after, "encryption subkey not on-card (no ssb> marker):\n" + after
    assert "D276000124010304" in status, "opcard AID missing from card-status"
    sig = [l for l in status.splitlines() if "Signature key" in l][0]
    enc = [l for l in status.splitlines() if "Encryption key" in l][0]
    assert "[none]" not in sig, "Signature slot empty: " + sig
    assert "[none]" not in enc, "Encryption slot empty: " + enc

    print("==== ECC keytocard PASS ====")
  '';
}
```

- [ ] **Step 2: Build the test (requires local KVM)**

Run:
```bash
nix build --impure --expr 'let s = builtins.getFlake (toString ./.); p = import s.inputs.nixpkgs { system = "x86_64-linux"; overlays = [ s.overlays.default s.overlays.nixosTests ]; }; in p.keywrightTests.keytocard-ecc' -L --no-link
echo "EXIT=$?"
```
Expected: build exits 0; log ends with `ECC keytocard PASS`.

- [ ] **Step 3: Format and commit**

```bash
nix fmt
git add overlays/nixos-tests/keytocard-ecc/package.nix
git commit -m "test(keywright): migrate ECC keytocard VM test from the keystone spike"
```

---

### Task 6: Migrate the RSA-4096 keytocard VM test

**Files:**
- Create: `overlays/nixos-tests/keytocard-rsa/package.nix`

**Interfaces:**
- Consumes: `testers`, `opcard-rs`.
- Produces: `pkgs.keywrightTests.keytocard-rsa`.

- [ ] **Step 1: Write the RSA test package**

`overlays/nixos-tests/keytocard-rsa/package.nix`:
```nix
{
  testers,
  opcard-rs,
}:
# WHY: proves keytocard for RSA-4096 — drduh's default and the FIPS-profile
# algorithm — including the real quirk that RSA keytocard prompts for the Admin
# PIN TWICE (vs once for ECC).
testers.runNixOSTest {
  name = "keywright-keytocard-rsa4096";

  nodes.machine =
    { pkgs, ... }:
    {
      services.pcscd = {
        enable = true;
        plugins = [
          pkgs.ccid
          pkgs.vsmartcard-vpcd
        ];
      };
      services.vsmartcard-vpcd.enable = true;
      programs.gnupg.agent.enable = true;
      environment.systemPackages = [
        pkgs.gnupg
        pkgs.pcsc-tools
        opcard-rs
      ];
      virtualisation.memorySize = 4096; # RSA-4096 keygen is heavier
      virtualisation.cores = 2;
    };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("pcscd.socket")
    machine.succeed("systemctl start pcscd.service")
    machine.wait_for_unit("pcscd.service")
    machine.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg")
    machine.succeed("printf 'disable-ccid\\npcsc-shared\\n' > /root/.gnupg/scdaemon.conf")
    machine.succeed("systemd-run --unit=opcard-vpicc --setenv=RUST_LOG=info ${opcard-rs}/bin/vpicc")
    machine.wait_until_succeeds("gpg --card-status 2>&1 | grep -q 'D276000124010304'", timeout=60)

    PW3 = "12345678"
    BATCH = "gpg --batch --pinentry-mode loopback --passphrase ''' "
    IDENTITY = "RSA Tester <rsa@example.com>"

    # Robust non-interactive RSA-4096 keygen (cert primary + sign + encr subkeys, off-card).
    machine.succeed(BATCH + "--quick-generate-key " + shlex.quote(IDENTITY) + " rsa4096 cert never 2>&1")
    FPR = machine.succeed("gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'").strip()
    assert len(FPR) == 40, "bad primary fpr: " + repr(FPR)
    machine.succeed(BATCH + "--quick-add-key " + FPR + " rsa4096 sign never 2>&1")
    machine.succeed(BATCH + "--quick-add-key " + FPR + " rsa4096 encr never 2>&1")

    before = machine.succeed("gpg -K --with-colons")
    sub = [l for l in before.splitlines() if l.startswith("ssb:")]
    assert len(sub) == 2, "expected 2 off-card subkeys:\n" + before
    for l in sub:
        f = l.split(":")
        assert f[3] == "1" and f[2] == "4096", "subkey not RSA-4096: " + l

    GPG = "gpg --command-fd=0 --status-fd=2 --with-colons --pinentry-mode loopback --expert --no-tty"

    def gpg_feed(args, lines):
        script = "".join(l + "\n" for l in lines)
        return machine.succeed("printf %s " + shlex.quote(script) + " | " + GPG + " " + args + " 2>&1")

    # WHY: RSA-4096 keytocard prompts for the Admin PIN TWICE — feed it twice or
    # "save" gets consumed as the 2nd PIN ("Bad PIN"). Matches opcard-rs tests.
    gpg_feed("--edit-key " + FPR, ["key 1", "keytocard", "1", PW3, PW3, "save"])
    gpg_feed("--edit-key " + FPR, ["key 2", "keytocard", "2", PW3, PW3, "save"])

    after = machine.succeed("gpg -K")
    status = machine.succeed("gpg --card-status")
    assert after.count("ssb>") == 2, "expected 2 on-card subkey stubs:\n" + after
    assert "D276000124010304" in status, "opcard AID missing from card-status"
    assert "rsa4096" in status.replace(" ", "").lower(), "card-status not reporting rsa4096:\n" + status

    print("==== RSA-4096 keytocard PASS ====")
  '';
}
```

- [ ] **Step 2: Build the test (KVM)**

Run:
```bash
nix build --impure --expr 'let s = builtins.getFlake (toString ./.); p = import s.inputs.nixpkgs { system = "x86_64-linux"; overlays = [ s.overlays.default s.overlays.nixosTests ]; }; in p.keywrightTests.keytocard-rsa' -L --no-link
echo "EXIT=$?"
```
Expected: build exits 0; log ends with `RSA-4096 keytocard PASS`.

- [ ] **Step 3: Format and commit**

```bash
nix fmt
git add overlays/nixos-tests/keytocard-rsa/package.nix
git commit -m "test(keywright): migrate RSA-4096 keytocard VM test from the keystone spike"
```

---

### Task 7: `hydra-jobs/vm-tests.nix` (per-system VM-test jobset)

**Files:**
- Create: `hydra-jobs/vm-tests.nix`

**Interfaces:**
- Consumes: `hydra-jobs/common.nix` (existing; provides `releaseLib`/`mapTestOn`/`packagePlatforms`/`pkgs`); `self.overlays.nixosTests`; `self.library.paths.getDirectoryNames`.
- Produces: a jobset attrset `keywrightTests.<name>.<system>` that `verify-hydra-jobset` evaluates + builds.

- [ ] **Step 1: Write the jobset**

`hydra-jobs/vm-tests.nix` (mirrors `packages.nix`, but injects the tests overlay via `extraOverlays`):
```nix
{
  supportedSystems ? [
    "x86_64-linux"
  ],
  evalSystem ? builtins.currentSystem or "x86_64-linux",
  nixpkgs ? null,
}@args:
let
  # self (for overlays + library) — same getFlake used by common.nix.
  self = builtins.getFlake "git+file://${toString ../.}";

  inherit
    (import ./common.nix (
      args
      // {
        extraOverlays = [ self.overlays.nixosTests ];
      }
    ))
    lib
    releaseLib
    ;

  inherit (releaseLib)
    mapTestOn
    packagePlatforms
    pkgs
    ;

  inherit (lib.attrsets)
    getAttrs
    recurseIntoAttrs
    ;

  inherit (self.library.paths)
    getDirectoryNames
    ;
in
mapTestOn (
  packagePlatforms {
    keywrightTests = recurseIntoAttrs (
      getAttrs (getDirectoryNames ../overlays/nixos-tests) pkgs.keywrightTests
    );
  }
)
```

- [ ] **Step 2: Run the jobset through `verify-hydra-jobset` (KVM)**

Run:
```bash
nix run .#verify-hydra-jobset -- ./hydra-jobs/vm-tests.nix --max-memory-size 6144
echo "EXIT=$?"
```
Expected: evaluates `keywrightTests.keytocard-ecc.x86_64-linux` and `keywrightTests.keytocard-rsa.x86_64-linux`, builds both (each ends in its PASS line), exits 0.

- [ ] **Step 3: Format and commit**

```bash
nix fmt
git add hydra-jobs/vm-tests.nix
git commit -m "feat(hydra-jobs): vm-tests jobset (mapTestOn over keywrightTests)"
```

---

### Task 8: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `hydra-jobs/vm-tests.nix`; a Cachix cache + `CACHIX_AUTH_TOKEN` secret (maintainer-provided — see Step 3).
- Produces: a CI workflow that fails visibly if KVM is unavailable and otherwise runs the VM-test jobset.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch: {}

jobs:
  vm-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Reclaim disk so the test closures (+ opcard-rs build) fit the runner.
      - uses: wimpysworld/nothing-but-nix@main

      - uses: DeterminateSystems/nix-installer-action@main

      - uses: cachix/cachix-action@v15
        with:
          name: keywright
          authToken: ${{ secrets.CACHIX_AUTH_TOKEN }}

      # "Green" must mean the VM tests actually ran. KVM-on-free-public-runners is
      # an undocumented perk; if it's absent, FAIL VISIBLY rather than skip silently.
      - name: Assert KVM is available
        run: |
          echo "DETERMINATE_NIX_KVM=${DETERMINATE_NIX_KVM:-<unset>}"
          if [ "${DETERMINATE_NIX_KVM:-0}" != "1" ] || [ ! -w /dev/kvm ]; then
            echo "::error::No usable /dev/kvm — VM tests cannot run on this runner."
            exit 1
          fi

      - name: Run the VM-test jobset
        run: nix run .#verify-hydra-jobset -- ./hydra-jobs/vm-tests.nix --max-memory-size 6144
```

- [ ] **Step 2: Format and commit**

```bash
nix fmt
git add .github/workflows/ci.yml
git commit -m "ci: run vm-tests jobset on GitHub Actions (fail-visible on no KVM)"
```

- [ ] **Step 3: Maintainer sets up Cachix, then push to trigger CI**

Maintainer actions (out-of-band, one-time): create a public Cachix cache named `keywright`, generate an auth token, add it as the `CACHIX_AUTH_TOKEN` repo secret, and publish the cache's public key in the README/flake. Then:
```bash
git push
gh run watch "$(gh run list --workflow=ci.yml --branch main --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status
```
Expected: the `vm-tests` job is green, having built `keytocard-ecc` and `keytocard-rsa` (both PASS) on the runner.

---

## Self-Review

**1. Spec coverage (against the §2.2/§14 scope of this plan):**
- Rust workspace + `keywright` package → Tasks 1–2. ✓
- Rust formatting wired into `nix fmt` (treefmt `rustfmt`; edition 2024 — its default, matching the crates) → Task 1 Step 2. ✓
- `opcard-rs` package (features `vpicc,rsa4096-gen`) → Task 3. ✓
- `overlays.nixosTests` (separate, not in `default`; `extraOverlays` injection) → Tasks 4, 7. ✓
- Migrated keytocard tests, ECC **and** RSA-4096, with rationale comments → Tasks 5–6. ✓
- `hydra-jobs/vm-tests.nix` via `mapTestOn`/`packagePlatforms`, `supportedSystems`-gated → Task 7. ✓
- GitHub Actions + `nothing-but-nix` + Cachix + `verify-hydra-jobset`, **KVM-unavailable = visible failure** (spec §14.4 / review B4) → Task 8. ✓
- Out of scope for this plan (later plans): the core engine (Plan 2), the provisioning state machine + the full slice VM test + acceptance §15 (Plan 3). Correct — this plan only delivers the harness + the migrated keytocard tests green in CI.

**2. Placeholder scan:** The only deliberate fill-ins are the `fetchFromGitHub` source hash (Task 3 Step 3 — standard fakeHash→build→copy, with the exact command) and the Cachix secret (Task 8 Step 3 — explicitly the maintainer's out-of-band action). No `TODO`/"add error handling"/"similar to Task N" — every file's full content is shown.

**3. Type/name consistency:** `pkgs.keywright` (Task 2) · `pkgs.opcard-rs` with bin `vpicc` (Task 3, consumed as the `opcard-rs` arg in Tasks 5–6) · `pkgs.keywrightTests.{keytocard-ecc,keytocard-rsa}` (Tasks 4–7) · `self.overlays.nixosTests` (Tasks 4, 7) · the test scripts use `${opcard-rs}/bin/vpicc` matching Task 3's install path. Consistent.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-21-keywright-foundation-infra.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
