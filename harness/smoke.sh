#!/usr/bin/env bash
# A sample snapshot suite. Contract: OMAPAC_SNAPSHOT_ID and
# OMAPAC_SNAPSHOT_DIR in; exit status and `tested: <pkgbase>` lines out.
set -euo pipefail

: "${OMAPAC_SNAPSHOT_ID:?set by omapac-repo snapshot test}"
: "${OMAPAC_SNAPSHOT_DIR:?set by omapac-repo snapshot test}"

# The built-in consistency check prints `tested:` lines for every package
# it verified; forward them.
store="$(dirname "$(dirname "$OMAPAC_SNAPSHOT_DIR")")"
omapac-repo snapshot check --store "$store" --id "$OMAPAC_SNAPSHOT_ID" "$@"

# When pacman is available, make sure it can read every database.
if command -v pacman-conf >/dev/null 2>&1 && command -v bsdtar >/dev/null 2>&1; then
	for db in "$OMAPAC_SNAPSHOT_DIR"/*/os/*/*.db; do
		bsdtar -tf "$db" >/dev/null
	done
fi
