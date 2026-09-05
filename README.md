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
server-side tooling a repository runs, and a mise backend plugin for a vetted tool
channel. It consumes the external `packslip` crate for signed release manifests. The
full design, decisions, and implementation plan are in [PLAN.md](PLAN.md); the
documentation index is [docs/index.md](docs/index.md).

## The client

```bash
pacvamp search helix              # repositories, with trust tiers
pacvamp search --aur helix        # the AUR, with votes, maintainer, and age
pacvamp install helix             # a plan, then pacman with the Omarchy guard
pacvamp install --aur google-chrome   # review, approve, build in a jail, install
pacvamp import                    # preview declarations from installed packages
pacvamp doctor --refresh          # check policy, sandbox, and signed publisher feeds
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

[packslip](https://packslip.dev) publishes signed release bundles and verifies
them against pinned keys or keyless identities. Pacvamp uses packslip 1.x from
crates.io; install its CLI separately. See the
[integration notes](docs/spec/packslip.md).

## Developing

```bash
mise install          # tools
mise run build        # cargo build
mise run test         # Rust tests and mandatory Arch E2E (requires Docker)
mise run test:unit    # Rust unit and integration tests only
mise run test:e2e     # real Arch pacman/makepkg tests (requires Docker)
mise run lint         # rustfmt, clippy, taplo, shellcheck, shfmt through hk
mise run render       # regenerate docs/cli
```

Integration tests run without pacman, makepkg, gpg, or a network: fakes on a
temporary PATH, fixture databases, local HTTP servers, and bare git repositories
stand in for them. The mise plugin test runs when a `mise` binary is on `PATH`.

CI runs the complete Rust suite on both Ubuntu and Arch. The Arch job has real
`/usr/bin/pacman` installed; integration fixtures explicitly select their fake
pacman with the `test-pacman` feature. A separate mandatory Arch E2E job tests real
package installation/removal, dry runs, and jailed builds. `mise run test` and
`mise run ci` include that E2E harness; missing Docker or container prerequisites
fail instead of silently skipping it.
