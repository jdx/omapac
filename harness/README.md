# Snapshot test harness

`pacvamp-repo snapshot test --id <id> --suite <command>` runs a suite
against a snapshot and records the result in the snapshot's signed
`release.json`. The contract between the two is small so any suite fits,
from the built-in consistency check to a QEMU matrix:

- The suite receives `PACVAMP_SNAPSHOT_ID` and `PACVAMP_SNAPSHOT_DIR`
  (the snapshot's directory, holding `<repo>/os/<arch>/`).
- Exit code 0 is a pass; anything else is a fail. A failed snapshot is
  never promoted and `rc` does not move to it.
- Every stdout line of the form `tested: <pkgbase>` names a package the
  suite exercised. They become `tested_pkgbases`, which clients use to
  label packages `tested` versus merely `snapshot`. Only claim what ran.
- Stderr is passed through for logs; `--log-url` records where the full
  log was published.

`smoke.sh` is a sample: it runs the built-in consistency check and adds
a host-level check that the databases can be read by pacman's own
tooling when it is installed. The Omarchy QEMU suite (installer, boot to
a session, `omarchy update` from the previous stable, rollback) follows
the same contract and lives with the image tooling.

The built-in check alone is `pacvamp-repo snapshot test --id <id>` with
no `--suite`.

The independent [boot acceptance suite](vm/README.md) creates a real Arch disk,
exercises package lifecycle and interruption recovery, and boots it again to check
persistence. It is a mandatory client CI job, separate from snapshot promotion.
