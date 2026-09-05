# Local AUR build receipts

Every successful AUR build writes `receipt.json` beside its `pkgs` directory.
The record includes the approved recipe commit, source-file SHA-256 hashes and
symlink targets, Git source refs, installed package versions observed before the
build, makepkg's executable digest, jail/network settings, resource limits, and
output hashes. Sources are inventoried after verification and checked again after
building. A source change refuses the build receipt and installation.

`pacvamp aur receipt /path/to/package.pkg.tar.zst --json` prints the record after
checking that the artifact still matches its recorded hash. Installation performs
the same check and stores the receipt path and hash in the package ledger.

Receipts are local observations, not signed attestations or reproducibility claims.
The installed-package inventory describes the available build environment, not
proof that every dependency was used. Sources downloaded outside SRCDEST during an
explicitly network-enabled build are not captured. The receipt and artifacts remain
in the run directory; deleting that directory removes the local evidence.

## Compare and replay

`pacvamp aur compare FIRST_ARTIFACT SECOND_ARTIFACT --json` verifies the named
artifacts and compares recipe commits, source inputs, VCS refs, image fingerprints,
dependencies, build settings, and output hashes. Exit 0 means all recorded fields
match; differences produce exit 1 with a structured report. Receipt timestamps and
local storage paths are not compared.

New builds set SOURCE_DATE_EPOCH to the approved commit's committer timestamp.
Image fingerprints include builder-readable content, symlink targets, ownership,
modification times and permissions. Inaccessible files and directories retain
metadata and an unreadable marker rather than requiring privileged reads. Special
entries such as sockets record metadata only and are never opened;
replaced runtime mounts are excluded. The image is checked again after building.

`pacvamp aur rebuild ARTIFACT --image ROOT` rechecks recipe approval, requires an
image matching the recorded fingerprint and packages, copies retained sources,
and runs verification and the build offline with the recorded source date. It
compares the new receipt and outputs and retains new artifacts even on mismatch.
A managed image root cannot be overridden. Missing/tampered sources, image drift,
and old receipts without a source date or image fingerprint fail before replay.
Network-enabled reference builds cannot be replayed by this command.

This is a local experiment, not independent attestation. Matching output hashes
show those two builds produced the same bytes; differing inputs and outputs are
reported without claiming which input caused a difference. Keep the base image or
an explicitly provisioned updated image if future replay is needed: disposable
images are removed after their original build.
