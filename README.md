# omapac

omapac is the system package manager for [Omarchy](https://omarchy.org): a pacman
frontend that installs from the Arch mirror, the Omarchy Package Repository, and the
AUR through one command, with trust tiers, commit-bound AUR builds, and policy that is
stricter when nobody is watching. It also ships the server-side tooling the Omarchy
repository runs and `packslip`, a vendor-neutral standard for signed release
manifests. The full design, decisions, and implementation plan are in
[PLAN.md](PLAN.md).
