# <project name>

<project description>

## Project Structure

```
.
├── checks/              # Flake checks (formatting verification)
├── formatter/           # Formatter output (treefmt wrapper)
├── formatterModule/     # treefmt-nix module config (nixfmt, deadnix, statix)
├── hydra-jobs/          # Hydra CI jobset definitions
├── legacyPackages/      # Per-system nixpkgs instantiation with overlays
├── library/             # Custom lib functions
├── nixosConfigurations/ # Host configurations (auto-discovered by directory name)
├── nixosModules/        # NixOS modules (auto-discovered from module.nix files)
└── overlays/            # Nixpkgs overlays
```

## Adding a NixOS Host

Create a directory under `nixosConfigurations/` with a `configuration.nix` file.
The directory name becomes the hostname. Each host automatically gets:

- The default overlay applied
- All NixOS modules from `nixosModules/`
- Disko disk management module
- A deterministic `hostId` derived from the hostname

## Adding Packages

- **Top-level packages** — add a `package.nix` under `overlays/top-level/`
- **Python packages** — add a `package.nix` under `overlays/python-packages/`
- **Upstream fixes** — add an `overlay.nix` under `overlays/fixes/`

Packages are auto-discovered.

## Adding NixOS Modules

Place `module.nix` files under `nixosModules/`, nested to mirror the NixOS option namespace.
They are auto-discovered.

## Formatting

The project uses [treefmt-nix](https://github.com/numtide/treefmt-nix) with:

- **mdformat** - Markdown formatting
- **nixfmt** — Nix code formatting
- **deadnix** — dead code detection
- **statix** — static analysis for Nix

```sh
nix fmt
```

## Hydra CI

The `hydra-jobs/` directory defines jobsets for Hydra CI.
The `verify-hydra-jobset` tool evaluates and builds all jobs locally:

```sh
nix run .#verify-hydra-jobset -- ./hydra-jobs/packages.nix
```
