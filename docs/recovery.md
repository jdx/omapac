# Interrupted transaction recovery

`pacvamp recover` shows each package's intended version or removal alongside its
current installed state. `--id ID` selects one operation. `--json` returns reports
containing the original journal, package comparisons, whether restoration is
allowed, suggested commands, and bounded pacman log context.

Only a durably recorded successful pacman operation whose package state still
matches can be restored with `recover --id ID --write`. An uncertain journal never
becomes trusted because versions or log entries happen to match. Log context is
limited to the last 256 KiB and 50 matching lines since the intent; rotation,
missing logs, and concurrent operations can leave context incomplete.

For uncertain or divergent operations, inspect the differences and reconcile the
host through an explicitly reviewed package operation. Then `recover --discard ID`
removes the inspected journal entry only. It does not change packages or certify
evidence. Recovery never reruns an interrupted pacman command automatically.
