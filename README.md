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

pacvamp is a pacman frontend with fangs: it installs from the official Arch
repositories, third-party repositories such as the [Omarchy](https://omarchy.org) one,
and the AUR through one command, with trust tiers, commit-bound AUR builds, and policy
that is stricter when nobody is watching. It also ships the server-side tooling the
Omarchy repository runs and `packslip`, a vendor-neutral standard for signed release
manifests. The full design, decisions, and implementation plan are in
[PLAN.md](PLAN.md).

## Brand assets

Logo, wordmark, Open Graph image, and favicons live in [assets/](assets/). They are
generated from [assets/generate.py](assets/generate.py); rerun it with
`uv run assets/generate.py` after editing.
