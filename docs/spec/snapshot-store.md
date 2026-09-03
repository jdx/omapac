# Snapshot store

Version 1, draft. The server side of the release train
(`release-train.md` is the client side): how a mirror becomes a store of
immutable snapshots with channel pointers, and how `omapac-repo snapshot`
moves them.

## Layout

```
<store>/
  snapshots/<id>/                 immutable; id is YYYY-MM-DDTHH
    core/os/x86_64/core.db, *.pkg.tar.zst, *.sig
    extra/os/x86_64/...
    multilib/os/x86_64/...
    release.json, release.json.minisig
  channels/
    edge -> ../snapshots/<id>     symlinks: the pointers
    rc -> ../snapshots/<id>
    stable -> ../snapshots/<id>
```

A machine on channel `stable` has
`Server = <base>/channels/stable/$repo/os/$arch` in its mirrorlist and
reads `<base>/channels/stable/release.json`. Pinning writes
`<base>/snapshots/<id>/$repo/os/$arch`.

Package files are hard-linked from the previous snapshot when unchanged,
so a snapshot costs the churn since the last one, not a full copy.

## Commands

- `snapshot cut --store S --from <mirror> --key K [--id <id>]
  [--opr-index <omapac-index.json>]` copies the repositories from a
  synced Arch mirror into a new snapshot, records the database digests
  and the OPR index sequence, writes and signs `release.json` with no
  test result, and points `edge` at it.
- `snapshot test --store S --id <id> [--suite <command>]` runs the
  suite with `OMAPAC_SNAPSHOT_ID` and `OMAPAC_SNAPSHOT_DIR` set. Exit 0
  is a pass. Lines the suite prints as `tested: <pkgbase>` become
  `tested_pkgbases`. The result is recorded and signed; a pass points
  `rc` at the snapshot when it is newer than the current `rc`. Without
  `--suite` the built-in consistency check runs (below).
- `snapshot promote --store S --channel stable [--id <id>] [--soak 3d]
  [--expedited]` moves a pointer. Without `--id`, the current `rc` is
  promoted when it passed, is not held, and has soaked for `--soak`
  since reaching `rc`. With `--id` a maintainer promotes deliberately;
  `--expedited` marks a security snapshot that ran the short suite.
- `snapshot hold --store S --id <id> --reason <text>` marks a snapshot
  held and moves any channel pointing at it back to the newest earlier
  snapshot that was promoted to that channel and is not held.
  `snapshot unhold` clears the flag; pointers do not move forward on
  their own.
- `snapshot status --store S [--json]` lists snapshots and pointers.
- `snapshot prune --store S [--retain 90d] [--stable-retain 365d]`
  deletes snapshots older than the retention, keeping any that were
  ever `stable` for the longer period and never a channel target.

`OMAPAC_REPO_NOW` fixes the clock for tests.

## Built-in consistency check

For every repository in the snapshot: the database parses, its digest
matches `release.json`, and every package file present beside it has the
size and sha256 the database records. Missing files fail the check
unless `--allow-missing` (a partial mirror). It prints `tested: <name>`
for every package it verified, so a snapshot that only ran the built-in
check labels its packages honestly: consistent, not exercised.

## The Omarchy suite

The QEMU suite (install, boot to a session, update from the previous
stable, rollback) is a separate script that follows the same contract:
env in, exit code and `tested:` lines out. It lives with the Omarchy
image tooling; `harness/README.md` describes the contract and a sample.
