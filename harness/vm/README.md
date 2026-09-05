# Boot acceptance suite

Run `cargo build --workspace --all-features`, then `bash harness/vm/run`.
Prerequisites: Docker, QEMU x86, libarchive's bsdtar, e2fsprogs, Python 3,
GitHub CLI, and noninteractive sudo for extracting root-owned image files and
creating the filesystem. Docker provisions an Arch image; QEMU boots the exported
ext4 disk with an Arch kernel and initramfs. Tests execute in the VM, not Docker.
KVM is used when accessible; software emulation is the fallback.

The first boot installs a signed fixture package with the baseline binary,
upgrades it with the candidate, kills a transaction supervisor after pacman has
mutated packages, verifies recovery preserves uncertainty, and rolls back through
a signed snapshot. A second boot checks package contents, ledger version, cleared
journals and the snapshot pin survived shutdown. Both boots require success
markers; timeout, prerequisite failure or missing markers fail the job.

By default the baseline is the latest published non-prerelease tag, or merged
`origin/main` before the first release. `PACVAMP_VM_BASELINE_REF` selects a Git
commit/tag, and `PACVAMP_VM_PREVIOUS_BIN` supplies an already-built baseline.
These test compatibility with the actual selected baseline; before a release
exists, the suite cannot claim released-version upgrade coverage. Binary hashes
and the selected commit/ref are retained with logs in `target/vm-results`.

`PACVAMP_VM_CURRENT_BIN` overrides the candidate executable.
`PACVAMP_VM_REPORT_DIR` selects the log directory. `PACVAMP_VM_KEEP=1` keeps the
workspace and disk for debugging. The suite needs roughly 8 GiB of temporary disk
space plus compilation caches. Keys and repositories are generated test fixtures;
no production signing key is used. CI uploads logs and binary identities, not the
disk image or fixture private keys. This exercises package lifecycle and boot
persistence, not an Omarchy desktop session or full distro upgrade matrix.
