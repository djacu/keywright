inputs:
let

  # inherits

  inherit (inputs.nixpkgs-lib)
    lib
    ;

  inherit (lib.filesystem)
    listFilesRecursive
    packagesFromDirectoryRecursive
    ;

  inherit (lib.fixedPoints)
    composeManyExtensions
    ;

  inherit (lib.attrsets)
    recurseIntoAttrs
    ;

  inherit (lib.lists)
    filter
    ;

  # overlays

  misc = _final: _prev: {
    # projectNameRepoRoot = ../.;
  };

  # Fixes for upstream nixpkgs packages with broken hashes or other issues
  fixes = composeManyExtensions (
    map import (filter (path: baseNameOf path == "overlay.nix") (listFilesRecursive ./fixes))
  );

  top-level =
    final: prev:
    packagesFromDirectoryRecursive {
      inherit (final) callPackage;
      inherit (prev) newScope;
      directory = ./top-level;
    };

  # VM tests, kept OUT of `default` so they don't load nixos/lib into the
  # packages jobset. Injected into hydra-jobs/vm-tests.nix via extraOverlays.
  nixosTests = final: _prev: {
    keywrightTests = recurseIntoAttrs (packagesFromDirectoryRecursive {
      inherit (final) callPackage;
      directory = ./nixos-tests;
    });
  };

  python-packages = _final: prev: {
    pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
      (
        python-final: _python-prev:
        packagesFromDirectoryRecursive {
          inherit (python-final) callPackage newScope;
          directory = ./python-packages;
        }
      )
    ];
  };

  verification =
    final: prev:
    packagesFromDirectoryRecursive {
      inherit (final) callPackage;
      inherit (prev) newScope;
      directory = ./verification;
    };

  default = composeManyExtensions [
    misc
    fixes
    top-level
    python-packages
    verification
  ];

in
{
  inherit
    default
    fixes
    nixosTests
    python-packages
    top-level
    ;
}
