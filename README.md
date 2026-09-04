<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg">
    <img alt="pacvamp" src="assets/wordmark.svg" width="420">
  </picture>
</p>

> [!WARNING]
> This project is not ready to be reviewed and is still very much a work in
> progress. Nothing here is stable, supported, or intended for real use — do not
> depend on it.

pacvamp is a trust-focused package manager for pacman-based Linux distributions. It
installs from distribution repositories and the AUR through one command, with trust
tiers, commit-bound AUR builds, and policy that is stricter when nobody is watching.
[Omarchy](https://omarchy.org) is the reference integration. The repository also ships `pacvamp-repo`, the
server-side tooling a repository runs, `packslip`, a vendor-neutral standard for
signed release manifests, and a mise backend plugin for a vetted tool channel. The
full design, decisions, and implementation plan are in [PLAN.md](PLAN.md); the
documentation index is [docs/index.md](docs/index.md).

## The client

```bash
pacvamp search helix              # repositories, with trust tiers
pacvamp search --aur helix        # the AUR, with votes, maintainer, and age
pacvamp install helix             # a plan, then pacman with the Omarchy guard
pacvamp install --aur google-chrome   # review, approve, build in a jail, install
pacvamp add helix                 # declare it in the manifest
pacvamp apply                     # converge the machine to the manifest
pacvamp update                    # the whole update pipeline, holds and AUR included
pacvamp audit                     # installed packages against Arch's security tracker
pacvamp channel                   # which tested snapshot this machine follows
pacvamp tools list claude         # vetted versions from the tool channel
```

Every command has `--json`; transactions have `-n` for the exact pacman command and
`-y` for unattended runs, where every warning becomes a refusal.

## The server

`pacvamp-repo` runs on the repository: `index` and `attest` produce the signed index
and build provenance, `sign` is the signer gate, `vendor` builds packages from a
vendor's packslip, `sync-aur` gates AUR commits, `verdict` and `advisories` maintain
the signed feeds, `snapshot` runs the release train, and `tool-channel` publishes
vetted tools for mise. The [OPR adoption guide](docs/adoption/opr.md) lists the order.

## packslip

`packslip create` signs one document per release saying what shipped and how to
verify it; `packslip verify` checks it against a pinned key. The
[specification](docs/spec/packslip.md) is vendor-neutral.

## Developing

```bash
mise install          # tools
mise run build        # cargo build
mise run test         # unit, integration, and e2e tests
mise run lint         # rustfmt, clippy, taplo, shellcheck, shfmt through hk
mise run render       # regenerate docs/cli
```

Integration tests run without pacman, makepkg, gpg, or a network: fakes on a
temporary PATH, fixture databases, local HTTP servers, and bare git repositories
stand in for them. The mise plugin test runs when a `mise` binary is on `PATH`.
