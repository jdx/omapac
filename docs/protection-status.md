# Check this machine's protections

`pacvamp doctor` reports what this machine can enforce and what evidence
is available. Its default feed checks use the authenticated local cache;
they do not contact publishers. Use `pacvamp doctor --refresh` to fetch
current signed feeds. Both support `--json` and leave package state,
approval locks, and the ledger unchanged.

The report separates:

- **Sandbox policy and kernel support:** whether AUR confinement is enabled,
  plus a disposable process that exercises the real Landlock/seccomp helper
  on the running kernel. A disabled policy is not reported as active protection
  merely because the kernel supports it.
- **Trust roots and policy:** configured signing keys, effective index and
  provenance requirements, advisory policy, and downgrade protection.
- **Publisher evidence:** authenticated indexes and the number of packages
  for which the publisher advertises provenance, vendor manifests, or verdicts.
  These are signed claims; `doctor` does not verify every package sidecar.
- **Feed freshness:** signed publication times, cache versus network results,
  and failed refreshes. Seven days is a diagnostic warning threshold, not a
  new installation policy. A recent cached feed does not prove the publisher
  is currently reachable.
- **Snapshots:** configured snapshot storage and the authenticated active
  release's tests, promotion, holds, and tested-package count.
- **Installed evidence:** how many installed versions have repository
  verification recorded in the ledger. This does not reverify installed files.

Missing optional feeds warn; feeds required by policy fail their checks.
Arch repositories retain pacman's signature checks without being credited
with pacvamp-specific provenance they do not publish.
