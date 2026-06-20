{

  description = "<project name>";

  inputs = {
    disko.inputs.nixpkgs.follows = "nixpkgs";
    disko.url = "github:nix-community/disko";
    nixpkgs-lib.url = "github:nix-community/nixpkgs.lib";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs = inputs: {

    checks = import ./checks/default.nix inputs;
    formatter = import ./formatter/default.nix inputs;
    formatterModule = import ./formatterModule/default.nix inputs;
    legacyPackages = import ./legacyPackages/default.nix inputs;
    library = import ./library/default.nix inputs;
    nixosModules = import ./nixosModules/default.nix inputs;
    nixosConfigurations = import ./nixosConfigurations/default.nix inputs;
    overlays = import ./overlays/default.nix inputs;

  };

}
