{
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  pcsclite,
  nettle,
  openssl,
}:
let
  version = "1.7.0";
in
rustPlatform.buildRustPackage {
  pname = "opcard-rs";
  inherit version;

  src = fetchFromGitHub {
    owner = "Nitrokey";
    repo = "opcard-rs";
    rev = "v${version}"; # if the tag is absent, use the commit: 2b94d6a… (rev-parse the spike clone)
    hash = "sha256-Bn/6UmeKOJAWv3pldI3iKR7wf5opTuOjVawlB6SgAQw=";
  };

  # The upstream GitHub tarball ships no Cargo.lock (it's .gitignore'd).
  # Copy our generated lockfile (from the spike) into the source tree so that
  # cargoSetupPostPatchHook can validate it against the vendored deps.
  postPatch = ''
    cp ${./Cargo.lock} Cargo.lock
  '';

  cargoLock = {
    lockFile = ./Cargo.lock;
    # opcard-rs pulls 7 git-patched deps; one representative crate per git source.
    outputHashes = {
      "admin-app-0.1.0" = "sha256-eWHEN2Wc0UwNKVpu2h1HFkVHEJCMXwYBjxJO1w6zBtY=";
      "p256-cortex-m4-0.1.0-alpha.6" = "sha256-rLDNp+cnh6NfYAss37nEw7/rgM2DXDWWjQ6KnBgcSr8=";
      "trussed-0.1.0" = "sha256-ZlVqYxmZJYgW57clO+gExzemAewhqZIFamrQ7zYWikg=";
      "trussed-auth-backend-0.1.0" = "sha256-JhyvAGa0g0ff4oE0+zZKRoA2SeZRtZsjAGkqkJNe6m4=";
      "trussed-rsa-alloc-0.4.0" = "sha256-nHDiq6mGU8ZpgJNOPnmPEW3XReuNh+sogozM1zgjKwU=";
      "trussed-staging-0.4.0" = "sha256-yanTqzjgt9yUIP34izrGK9GrGWuKDoBta1z0JUCX+4A=";
      "trussed-usbip-0.0.1" = "sha256-jB79OLTqzNkfaDn59bgj/PRKWjhmJ8EaP2zn0bvScYo=";
    };
  };

  # Build only the vpicc example, with the vpicc + RSA-4096 features.
  buildFeatures = [
    "vpicc"
    "rsa4096-gen"
  ];
  cargoBuildFlags = [
    "--example"
    "vpicc"
  ];
  # Upstream's cargo tests need a live card; the VM test is the real exercise.
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];
  buildInputs = [
    pcsclite
    nettle
    openssl
  ];

  # buildRustPackage installs declared bins, not examples — install the example by hand.
  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    find target -type f -name vpicc -path '*release/examples/*' -exec install -Dm755 {} $out/bin/vpicc \;
    test -x $out/bin/vpicc || { echo "vpicc example binary not found"; exit 1; }
    runHook postInstall
  '';

  meta = {
    description = "opcard-rs vpicc virtual OpenPGP smartcard (test dependency)";
    mainProgram = "vpicc";
  };
}
