# Release train

Version 1, draft. The client side of PLAN.md's "Release train": tested
snapshots instead of a time delay.

## Snapshots and channels

The Arch mirror is a store of immutable snapshots, `<snapshot_base>/<id>/
{core,extra,multilib}/os/<arch>`, where `<id>` is `YYYY-MM-DDTHH`.
Packages are content-addressed and shared between snapshots. The channels
`edge`, `rc`, and `stable` are pointers: `edge` is the newest snapshot,
`rc` the newest that passed the test suite, `stable` the newest `rc` that
soaked without a hold.

A machine's channel is the one its Omarchy repository server names
(`https://pkgs.omarchy.org/stable/$arch` is `stable`). The snapshot store
base comes from the manifest:

```toml
[channel]
snapshot_base = "https://mirror.omarchy.org/snapshots"
```

The distro layer ships it.

## `release.json`

Each channel publishes a signed manifest next to its other feeds
(`<Server>/release.json` with `release.json.minisig`), and each snapshot
carries its own copy at `<snapshot_base>/<id>/release.json`.

```json
{
  "version": 1,
  "id": "2026-09-03T06",
  "channel": "stable",
  "arch_snapshot": "2026-09-03T06",
  "opr_index_sequence": 1042,
  "created_at": "2026-09-03T06:00:00Z",
  "tests": { "suite": "omarchy-train", "commit": "...", "result": "pass", "log_url": "..." },
  "tested_pkgbases": ["hyprland", "omarchy", "..."],
  "promoted": { "rc": "2026-09-03T08:00:00Z", "stable": "2026-09-06T08:00:00Z" },
  "expedited": false,
  "held": false,
  "db_digests": { "core": "...", "extra": "...", "multilib": "..." }
}
```

- `tested_pkgbases` is what the suite exercised. A client labels those
  `tested` and everything else in the snapshot `snapshot`: consistent,
  not tested.
- `promoted` records when the snapshot reached `rc` and `stable`.
  Rollback without `--force` requires one of them.
- `expedited` marks a security snapshot that ran the short suite;
  `held` marks one a maintainer pulled.
- `db_digests` let a client check the databases it downloaded belong to
  this snapshot.

## Client commands

- `omapac channel` shows the channel, the snapshot it points at with its
  test result and promotion, the tested-package count, whether the
  mirrorlist is pinned, and the last snapshot the machine converged to.
- `omapac channel pin <id>` writes `/etc/pacman.d/mirrorlist` to point at
  the snapshot (backing up the previous list once), after fetching and
  verifying the snapshot's manifest and checking it was promoted.
  `omapac channel unpin` restores the backup.
- `omapac rollback --snapshot <id>` pins, refreshes, and runs a sync that
  allows downgrades so every package matches the snapshot. Pair it with
  the filesystem snapshot Omarchy takes before updates.
- `omapac update` records the snapshot it converged to in the ledger.
