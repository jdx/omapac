# Build cache retention

`pacvamp cache status` shows retained runs. `pacvamp cache prune --dry-run`
previews cleanup; omit `--dry-run` to delete eligible runs. Both accept `--json`.
Pruning defaults to 30 days; use `--older-than-days` and optionally `--max-bytes`
to select oldest unused runs until reaching a total-size target.

Active builds block pruning. Runs less than an hour old are protected, as are
receipts referenced by the selected system ledger or its pending transactions.
If protected data exceeds the target, pruning leaves it intact. Missing referenced
receipts cause cleanup to fail rather than guess. Only build runs are removed;
recipe checkouts and synchronization locks remain. Prune each user's cache against
the system whose ledger records those builds; a shared cache across independent
sysroots is not supported.

Commands that may build or install AUR packages hold a shared cache lease through approval, installation, and ledger recording. Pruning cannot remove their artifacts during a long confirmation prompt.

Status and dry runs use shared leases and can inspect a running build. Their sizes are a live estimate; actual pruning takes an exclusive lease and calculates eligibility again.
