use clap::Parser;

/// Keywright — air-gapped YubiKey/OpenPGP provisioning.
#[derive(Parser)]
#[command(name = "keywright", version)]
struct Cli {}

fn main() {
    Cli::parse();
    eprintln!(
        "keywright {} — provisioning commands arrive in plan 3",
        keywright_core::version()
    );
}
