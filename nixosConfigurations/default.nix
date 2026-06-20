inputs:
let

  inherit (inputs.nixpkgs-lib)
    lib
    ;

  inherit (lib.attrsets)
    genAttrs
    ;

  inherit (lib.modules)
    mkDefault
    ;

  inherit (inputs.self.library.paths)
    getDirectoryNames
    ;

in
genAttrs (getDirectoryNames ./.) (
  host:
  (inputs.nixpkgs.lib.nixosSystem {

    extraModules = [

      inputs.self.nixosModules.default

    ];

    modules = [

      (
        { config, ... }:
        {
          networking.hostId = lib.substring 0 8 (builtins.hashString "sha256" config.networking.hostName);
          networking.hostName = mkDefault host;
        }
      )

      {
        nixpkgs.overlays = [ inputs.self.overlays.default ];
        # TODO @djacu figure out a nice way to use readOnlyPkgs
        # imports = [ inputs.nixpkgs.nixosModules.readOnlyPkgs ];
        # nixpkgs.pkgs = inputs.self.legacyPackages.x86_64-linux;
      }

      inputs.disko.nixosModules.disko

      (import ./${host}/configuration.nix)

    ];

  })
)
