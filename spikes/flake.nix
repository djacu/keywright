{
  description = "Keywright feasibility spikes: (1) KVM-accelerated nixosTest on CI, (2) representative air-gapped ISO build-budget measurement. THROWAWAY — not part of the product.";

  # Pinned to the same nixpkgs rev we verified locally (nixos-unstable ~2026-06-10).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/fdb57d83c188ea7e53fd5bb9b4a65ce42957a42b";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      # Representative air-gapped provisioning ISO: a minimal NixOS installer CD
      # carrying the realistic crypto/provisioning toolchain closure (this closure,
      # not the ISO file size, is what drives the runner disk budget).
      isoSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
          (
            { lib, pkgs, ... }:
            {
              isoImage.isoName = "keywright-spike.iso";
              isoImage.squashfsCompression = "zstd"; # faster than xz for CI

              # Air-gap: no networking on the booted system.
              networking = {
                wireless.enable = lib.mkForce false;
                networkmanager.enable = lib.mkForce false;
                useDHCP = lib.mkForce false;
                firewall.enable = true;
              };

              # The provisioning toolchain (drives the closure size).
              services.pcscd.enable = true;
              services.udev.packages = [ pkgs.yubikey-personalization ];
              programs.gnupg.agent = {
                enable = true;
                enableSSHSupport = true;
              };
              environment.systemPackages = with pkgs; [
                gnupg
                pinentry-curses
                paperkey
                pgpdump
                cryptsetup
                parted
                yubikey-manager
                yubikey-personalization
                yubico-piv-tool
                pcsc-tools
                ent
                diceware
                pwgen
                rng-tools
                tmux
                htop
              ];

              system.stateVersion = "25.05";
            }
          )
        ];
      };
    in
    {
      packages.${system}.iso-spike = isoSystem.config.system.build.isoImage;

      # Trivial VM test: proves KVM-accelerated nixosTest runs on the runner.
      checks.${system}.kvm-probe = pkgs.testers.runNixOSTest {
        name = "kvm-probe";
        nodes.machine = { ... }: { };
        testScript = ''
          start_all()
          machine.wait_for_unit("multi-user.target")
          machine.succeed("true")
        '';
      };
    };
}
