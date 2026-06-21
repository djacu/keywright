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
