{
  # The platforms supported.
  supportedSystems ? [
    "aarch64-linux"
    "x86_64-linux"
  ],

  # The system evaluating this expression.
  evalSystem ? builtins.currentSystem or "x86_64-linux",

  # Whether to apply hydraJob to each derivation.
  scrubJobs ? true,

  # Additional overlays to apply to the package set.
  extraOverlays ? null,

  # The path to Nixpkgs.
  nixpkgs ? null,
}@args:
let

  # A self-reference to this flake to get overlays
  self = builtins.getFlake "git+file://${toString ../.}";

  # Default values won't make unsupplied arguments present; they just make the
  # variable available in the scope.
  nixpkgs = args.nixpkgs or self.inputs.nixpkgs.outPath;

  inherit (self.inputs.nixpkgs-lib) lib;

in
{

  inherit
    lib
    nixpkgs
    self
    ;

  releaseLib = import (nixpkgs + "/pkgs/top-level/release-lib.nix") {
    inherit
      scrubJobs
      supportedSystems
      ;
    system = evalSystem;
    nixpkgsArgs = {
      __allowFileset = true;
      config = {
        # By default, Nixpkgs allows aliases. Setting them to false allows us
        # to detect breakages sooner rather than later.
        allowAliases = false;
        allowUnfree = true;
        inHydra = true;
      };
      overlays = [
        self.overlays.default
      ]
      ++ args.extraOverlays or [ ];
    };
  };

}
