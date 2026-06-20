inputs:
let

  inherit (inputs.nixpkgs-lib)
    lib
    ;

  inherit (lib.filesystem)
    listFilesRecursive
    ;

  inherit (lib.lists)
    filter
    ;

  inherit (lib.strings)
    hasSuffix
    ;

in
{
  default =
    { ... }:
    {
      imports = filter (hasSuffix "module.nix") (listFilesRecursive ./.);
    };
}
