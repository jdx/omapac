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
