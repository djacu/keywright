{
  testers,
  opcard-rs,
}:
# WHY: proves keytocard for RSA-4096 — drduh's default and the FIPS-profile
# algorithm — including the real quirk that RSA keytocard prompts for the Admin
# PIN TWICE (vs once for ECC).
testers.runNixOSTest {
  name = "keywright-keytocard-rsa4096";

  nodes.machine =
    { pkgs, ... }:
    {
      services.pcscd = {
        enable = true;
        plugins = [
          pkgs.ccid
          pkgs.vsmartcard-vpcd
        ];
      };
      services.vsmartcard-vpcd.enable = true;
      programs.gnupg.agent.enable = true;
      environment.systemPackages = [
        pkgs.gnupg
        pkgs.pcsc-tools
        opcard-rs
      ];
      virtualisation.memorySize = 4096; # RSA-4096 keygen is heavier
      virtualisation.cores = 2;
    };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("pcscd.socket")
    machine.succeed("systemctl start pcscd.service")
    machine.wait_for_unit("pcscd.service")
    machine.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg")
    machine.succeed("printf 'disable-ccid\\npcsc-shared\\n' > /root/.gnupg/scdaemon.conf")
    machine.succeed("systemd-run --unit=opcard-vpicc --setenv=RUST_LOG=info ${opcard-rs}/bin/vpicc")
    machine.wait_until_succeeds("gpg --card-status 2>&1 | grep -q 'D276000124010304'", timeout=60)

    PW3 = "12345678"
    BATCH = "gpg --batch --pinentry-mode loopback --passphrase ''' "
    IDENTITY = "RSA Tester <rsa@example.com>"

    # Robust non-interactive RSA-4096 keygen (cert primary + sign + encr subkeys, off-card).
    machine.succeed(BATCH + "--quick-generate-key " + shlex.quote(IDENTITY) + " rsa4096 cert never 2>&1")
    FPR = machine.succeed("gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'").strip()
    assert len(FPR) == 40, "bad primary fpr: " + repr(FPR)
    machine.succeed(BATCH + "--quick-add-key " + FPR + " rsa4096 sign never 2>&1")
    machine.succeed(BATCH + "--quick-add-key " + FPR + " rsa4096 encr never 2>&1")

    before = machine.succeed("gpg -K --with-colons")
    sub = [l for l in before.splitlines() if l.startswith("ssb:")]
    assert len(sub) == 2, "expected 2 off-card subkeys:\n" + before
    for l in sub:
        f = l.split(":")
        assert f[3] == "1" and f[2] == "4096", "subkey not RSA-4096: " + l

    GPG = "gpg --command-fd=0 --status-fd=2 --with-colons --pinentry-mode loopback --expert --no-tty"

    def gpg_feed(args, lines):
        script = "".join(l + "\n" for l in lines)
        return machine.succeed("printf %s " + shlex.quote(script) + " | " + GPG + " " + args + " 2>&1")

    # WHY: RSA-4096 keytocard prompts for the Admin PIN TWICE — feed it twice or
    # "save" gets consumed as the 2nd PIN ("Bad PIN"). Matches opcard-rs tests.
    gpg_feed("--edit-key " + FPR, ["key 1", "keytocard", "1", PW3, PW3, "save"])
    gpg_feed("--edit-key " + FPR, ["key 2", "keytocard", "2", PW3, PW3, "save"])

    after = machine.succeed("gpg -K")
    status = machine.succeed("gpg --card-status")
    assert after.count("ssb>") == 2, "expected 2 on-card subkey stubs:\n" + after
    assert "D276000124010304" in status, "opcard AID missing from card-status"
    assert "rsa4096" in status.replace(" ", "").lower(), "card-status not reporting rsa4096:\n" + status

    print("==== RSA-4096 keytocard PASS ====")
  '';
}
