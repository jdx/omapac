#!/usr/bin/env bash
# A sample snapshot suite. Contract: PACVAMP_SNAPSHOT_ID and
# PACVAMP_SNAPSHOT_DIR in; exit status and `tested: <pkgbase>` lines out.
set -euo pipefail

: "${PACVAMP_SNAPSHOT_ID:?set by pacvamp-repo snapshot test}"
: "${PACVAMP_SNAPSHOT_DIR:?set by pacvamp-repo snapshot test}"

# The built-in consistency check prints `tested:` lines for every package
# it verified; forward them.
store="$(dirname "$(dirname "$PACVAMP_SNAPSHOT_DIR")")"
pacvamp-repo snapshot check --store "$store" --id "$PACVAMP_SNAPSHOT_ID" "$@"

# When pacman is available, make sure it can read every database.
if command -v pacman-conf >/dev/null 2>&1 && command -v bsdtar >/dev/null 2>&1; then
	for db in "$PACVAMP_SNAPSHOT_DIR"/*/os/*/*.db; do
		bsdtar -tf "$db" >/dev/null
	done
fi
