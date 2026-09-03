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

omapac is the system package manager for [Omarchy](https://omarchy.org): a pacman
frontend that installs from the Arch mirror, the Omarchy Package Repository, and the
AUR through one command, with trust tiers, commit-bound AUR builds, and policy that is
stricter when nobody is watching. The repository also ships `omapac-repo`, the
server-side tooling a repository runs, `packslip`, a vendor-neutral standard for
signed release manifests, and a mise backend plugin for a vetted tool channel. The
full design, decisions, and implementation plan are in [PLAN.md](PLAN.md); the
documentation index is [docs/README.md](docs/README.md).

## The client

```bash
omapac search helix              # repositories, with trust tiers
omapac search --aur helix        # the AUR, with votes, maintainer, and age
omapac install helix             # a plan, then pacman with the Omarchy guard
omapac install --aur google-chrome   # review, approve, build in a jail, install
omapac add helix                 # declare it in the manifest
omapac apply                     # converge the machine to the manifest
omapac update                    # the whole update pipeline, holds and AUR included
omapac audit                     # installed packages against Arch's security tracker
omapac channel                   # which tested snapshot this machine follows
omapac tools list claude         # vetted versions from the tool channel
```

Every command has `--json`; transactions have `-n` for the exact pacman command and
`-y` for unattended runs, where every warning becomes a refusal.

## The server

`omapac-repo` runs on the repository: `index` and `attest` produce the signed index
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

## Brand assets

Logo, wordmark, Open Graph image, and favicons live in [assets/](assets/). They are
generated from [assets/generate.py](assets/generate.py); rerun it with
`uv run assets/generate.py` after editing.
