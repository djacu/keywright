{
  pkgs,
  ...
}:

{

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  fileSystems."/" = {
    device = "/dev/vda1";
    fsType = "ext4";
  };

  system.stateVersion = "26.05";

  nixpkgs.hostPlatform = "x86_64-linux";

  users.users.alice = {
    extraGroups = [ "wheel" ];
    initialPassword = "test";
    isNormalUser = true;
  };

  environment.systemPackages = [
    pkgs.cowsay
    pkgs.lolcat
    pkgs.vim
  ];

}
