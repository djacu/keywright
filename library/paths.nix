{
  lib,
  library,
}:
let

  inherit (builtins)
    readDir
    ;

  inherit (lib.attrsets)
    attrNames
    filterAttrs
    ;

  inherit (lib.trivial)
    const
    flip
    pipe
    ;

  inherit (library.paths)
    filterDirectories
    getDirectories
    ;

in
{

  /**
    Get attribute set of directories under parent.

    # Inputs

    `path`

    : 1\. The parent path.

    # Type

    ```
    getDirectories :: Path -> AttrSet
    ```

    # Examples
    :::{.example}
    ## `lib.paths.getDirectories` usage example

    ```nix
    getDirectories ./home-modules
    => {
      djacu = "directory";
      programs = "directory";
      services = "directory";
    }
    ```
  */
  getDirectories = flip pipe [
    readDir
    filterDirectories
  ];

  /**
      Get list of directories names under parent.

      # Inputs

      `path`

      : 1\. The parent path.

      # Type

      ```
      getDirectoryNames :: Path -> [String]
      ```

      # Examples
      :::{.example}
      ## `lib.paths.getDirectoryNames` usage example

      ```nix
      getDirectoryNames ./home-modules
      => [
        "djacu"
        "programs"
        "services"
      ]
      ```
  */
  getDirectoryNames = flip pipe [
    getDirectories
    attrNames
  ];

  /**
     Filter the contents of a directory path for directories only.

     # Inputs

     `contents`

     : 1\. The contents of a directory path.

     # Type

     ```
     filterDirectories :: AttrSet -> AttrSet
     ```

     # Examples
     :::{.example}
     ## `lib.paths.filterDirectories` usage example

     ```nix
     x = {
       "default.nix" = "regular";
       djacu = "directory";
       programs = "directory";
       services = "directory";
     }
     filterDirectories x
     => {
       djacu = "directory";
       programs = "directory";
       services = "directory";
     }
     ```

     :::
  */
  filterDirectories = filterAttrs (const (fileType: fileType == "directory"));

}
