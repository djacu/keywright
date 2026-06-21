{
  testers,
  opcard-rs,
}:
# WHY: proves the project's core feasibility premise — gpg can drive the
# irreversible `keytocard` step against a VIRTUAL OpenPGP card, headlessly, with
# NO hardware — and is the regression guard against opcard-rs/nixpkgs/gpg bumps.
testers.runNixOSTest {
  name = "keywright-keytocard-ecc";

  nodes.machine =
    { pkgs, ... }:
    {
      # pcscd + vsmartcard-vpcd present opcard as a single "Virtual PCD" reader.
      services.pcscd = {
        enable = true;
        plugins = [
          pkgs.ccid
          pkgs.vsmartcard-vpcd
        ];
      };
      services.vsmartcard-vpcd.enable = true; # port 35963, listening mode
      programs.gnupg.agent.enable = true;
      environment.systemPackages = [
        pkgs.gnupg
        pkgs.pcsc-tools
        opcard-rs
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
    };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("pcscd.socket")
    machine.succeed("systemctl start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # WHY: force gpg/scdaemon onto PC/SC (the internal CCID driver can't see the
    # virtual reader). Mirrors opcard-rs ci/Dockerfile.
    machine.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg")
    machine.succeed("printf 'disable-ccid\\npcsc-shared\\n' > /root/.gnupg/scdaemon.conf")

    # Start the opcard vpicc card; it connects out to vpcd:35963.
    machine.succeed("systemd-run --unit=opcard-vpicc --setenv=RUST_LOG=info ${opcard-rs}/bin/vpicc")
    # WHY: gpg must actually SEE an OpenPGP card (the opcard AID), not just a reader.
    machine.wait_until_succeeds("gpg --card-status 2>&1 | grep -q 'D276000124010304'", timeout=60)

    PW3 = "12345678"
    GPG = "gpg --command-fd=0 --status-fd=2 --with-colons --pinentry-mode loopback --expert --no-tty"

    def gpg_feed(args, lines):
        script = "".join(l + "\n" for l in lines)
        return machine.succeed("printf %s " + shlex.quote(script) + " | " + GPG + " " + args + " 2>&1")

    # Generate an OFF-card ed25519 primary + cv25519 encryption subkey.
    gpg_feed("--full-gen-key", ["9", "1", "0", "ECC Tester", "ecc@example.com", "no comment", "", ""])

    before = machine.succeed("gpg -K --with-colons")
    assert "ssb:" in before, "expected an off-card encryption subkey before keytocard"

    # WHY: move the encryption subkey (slot 2) and the primary (slot 1) onto the card.
    gpg_feed("--edit-key ecc@example.com", ["key *", "keytocard", "2", PW3, PW3, "save"])
    gpg_feed("--edit-key ecc@example.com", ["keytocard", "y", "1", PW3, "save"])

    after = machine.succeed("gpg -K")
    status = machine.succeed("gpg --card-status")
    # WHY: the '>' stub markers are DISPOSITIVE — gpg only prints them once the
    # secret was actually moved onto the card and replaced by a stub.
    assert "sec>" in after, "primary not on-card (no sec> marker):\n" + after
    assert "ssb>" in after, "encryption subkey not on-card (no ssb> marker):\n" + after
    assert "D276000124010304" in status, "opcard AID missing from card-status"
    sig = [l for l in status.splitlines() if "Signature key" in l][0]
    enc = [l for l in status.splitlines() if "Encryption key" in l][0]
    assert "[none]" not in sig, "Signature slot empty: " + sig
    assert "[none]" not in enc, "Encryption slot empty: " + enc

    print("==== ECC keytocard PASS ====")
  '';
}
