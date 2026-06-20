inputs:

let

  inherit (inputs.nixpkgs-lib)
    lib
    ;

  inherit (lib.fixedPoints)
    makeExtensible
    ;

  library = makeExtensible (
    self:
    let
      callLibs =
        file:
        import file {
          inherit lib;
          library = self;
        };
    in
    {

      paths = callLibs ./paths.nix;
      systems = callLibs ./systems.nix;

    }
  );

in

library
