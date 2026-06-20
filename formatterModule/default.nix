inputs:
let

  inherit (inputs.nixpkgs-lib)
    lib
    ;

  inherit (lib.attrsets)
    mapAttrs
    ;

  inherit (lib.trivial)
    const
    ;

in
mapAttrs (const (
  pkgs:
  (inputs.treefmt-nix.lib.evalModule pkgs {

    projectRootFile = "flake.nix";

    programs.deadnix.enable = true;
    programs.deadnix.no-lambda-pattern-names = true;

    programs.mdformat.enable = true;

    programs.nixfmt.enable = true;

    programs.statix.enable = true;

  })
)) inputs.self.legacyPackages
