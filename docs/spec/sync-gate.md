# AUR sync gate

Version 1, draft. How a repository that rebuilds AUR packages decides
which upstream commits to pull. This is `pacvamp-repo sync-aur`; it runs
the same policy engine as `pacvamp aur review` on the client, so a commit
the gate blocks is one every client would refuse unattended.

## State

`state.json` records the commit last merged per package:

```json
{ "packages": { "yay": { "commit": "...", "pkgver": "13.0.2-1", "synced_at": "2026-09-03T00:00:00Z" } } }
```

## Decision

For each package the gate syncs the AUR checkout, reviews the remote head
with the unattended policy against the recorded commit, and reports one
of:

- `unchanged`: the head is the recorded commit.
- `blocked`: a finding the unattended policy denies (an install script
  added, a skipped checksum, a changed source host, hostile content,
  a fresh maintainer change, and so on). Never merged.
- `needs-review`: anything a human should read, including every first
  commit of a new package, a flagged finding, an orphaned package, a
  maintainer outside the trusted list, or a diff that changes more than
  the version and checksums.
- `auto-merge`: a clean version bump (only `pkgver`, `pkgrel`, source,
  and checksum lines changed in PKGBUILD and .SRCINFO) by a maintainer on
  `--trusted-maintainer`, with no findings. With `--write` it is recorded
  in the state.

The exit status is non-zero when anything was blocked or failed, so a
scheduled run surfaces problems.

## Verdicts

With `--verdicts <feed> --key <key>` the gate appends one static verdict
per reviewed commit (`pass`, `flag`, or `block` with the finding ids,
reviewer `static`/`pacvamp-policy`) to the signed verdict feed. Clients
consult the feed in `aur review` and `update`, so the repository's review
of a popular AUR package reaches users who build it themselves.

Other reviewers add verdicts with `pacvamp-repo verdict`: a human after
reading a diff, an antivirus scan of a built package by digest, or later
an AI reviewer with its model and prompt hash as the reviewer version.
`pacvamp-repo advisories add|remove` maintains the kill list.

## Environment

`PACVAMP_AUR_RPC_BASE` and `PACVAMP_AUR_GIT_BASE` point the gate at another
AUR (tests use a local one); `PACVAMP_REPO_NOW` fixes the clock.
