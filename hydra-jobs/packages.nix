{
  # The platforms supported.
  supportedSystems ? [
    "aarch64-linux"
    "x86_64-linux"
  ],

  # The system evaluating this expression.
  evalSystem ? builtins.currentSystem or "x86_64-linux",

  # The path to Nixpkgs.
  nixpkgs ? null,
}@args:
let

  inherit (import ./common.nix args)
    lib
    releaseLib
    self
    ;

  inherit (releaseLib)
    mapTestOn
    packagePlatforms
    pkgs
    ;

  inherit (self.library.paths)
    getDirectoryNames
    ;

  inherit (lib.attrsets)
    getAttrs
    recurseIntoAttrs
    ;

in
mapTestOn (
  packagePlatforms (
    (getAttrs (getDirectoryNames ../overlays/top-level) pkgs)
    // {
      python3Packages = recurseIntoAttrs (
        getAttrs (getDirectoryNames ../overlays/python-packages) pkgs.python3Packages
      );
    }
  )
)
