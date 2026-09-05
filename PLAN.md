<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg">
    <img alt="pacvamp" src="assets/wordmark.svg" width="420">
  </picture>
</p>

> [!WARNING]
> This project is not ready to be reviewed and is still very much a work in
> progress. Nothing here is stable, supported, or intended for real use — do not
> depend on it.

# pacvamp

pacvamp is a trust-focused package manager for pacman-based Linux distributions. It is a
pacman frontend in the yay and paru category, owned by the distro, with supply-chain
security as the product. This document is the design. Every pull request cites the
section it implements, and a pull request that changes the design edits this file in
the same change.

Status: design approved 2026-09-03. No code yet.

## Table of contents

1. [Why](#why)
2. [What exists today](#what-exists-today)
3. [Principles](#principles)
4. [Architecture](#architecture)
5. [Manifest, lockfile, ledger, managed config](#manifest-lockfile-ledger-managed-config)
6. [Security model](#security-model)
7. [packslip: the vendor-binary standard](#packslip-the-vendor-binary-standard)
8. [Release train](#release-train)
9. [Settings](#settings)
10. [Update flow](#update-flow)
11. [CLI surface](#cli-surface)
12. [Adoption](#adoption)
13. [Repository layout](#repository-layout)
14. [Implementation plan](#implementation-plan)
15. [Verification](#verification)
16. [Decisions](#decisions)
17. [Open questions](#open-questions)

## Why

Omarchy's package story is bash over `pacman -S --noconfirm` and `yay -S --noconfirm`.
Every install path is unattended, and `omarchy update` runs `yay -Sua --noconfirm` on
any machine with a foreign package. After the AUR malware campaigns of July 2025 and
June through August 2026, that is the weakest link in the distro.

Two product problems drive the design:

- Users need one safe way to install, remove, and update packages across the Arch
  mirror, the Omarchy Package Repository (OPR), and the AUR, that records what they
  chose, reviews what it builds, and is stricter when nobody is watching.
- Omarchy wants a package set that has been tested together before users get it,
  faster than the current 30-day mirror lag but not on the bleeding edge.

mise keeps its role as the declarative "my machine" layer (tools, dotfiles, services)
and delegates system packages to pacvamp on Omarchy.

## What exists today

Facts as of 2026-09-03.

### Omarchy (`omacom/omarchy`, 4.0.0.alpha)

- `omarchy pkg add|drop|aur-add|install|aur-install|remove|present|missing` are bash
  wrappers; every path passes `--noconfirm`. There is no dry-run, search, manifest, AUR
  review, or pacnew handling.
- `omarchy-update` runs: lock, disk-space check, paccache, snapper snapshot, keyring
  refresh, a full `pacman -Syu --noconfirm --overwrite '/usr/share/omarchy/*'` with a
  file-conflict quarantine fallback, migrations, hooks, `yay -Sua --noconfirm
  --cleanafter --ignore gcc14,gcc14-libs`, `MISE_MINIMUM_RELEASE_AGE=0 mise up`, then
  interactive orphan removal.
- A libalpm hook, `00-omarchy-update-guard`, aborts any `-Syu` unless
  `OMARCHY_UPDATE_PACMAN=1` or `OMARCHY_ALLOW_DIRECT_PACMAN=1` is set. Any wrapper must
  set it.
- `pacman.conf` uses `SigLevel = Required DatabaseOptional` and adds `[omarchy]` at
  `https://pkgs.omarchy.org/<channel>/$arch`. The T2 Mac install appends a repo with
  `SigLevel = Never`.
- yay is in the base install, built by OPR from the AUR. It broke on a libalpm soname
  bump once (omarchy issue 3877), which is the argument against linking libalpm.
- The `stable` mirror is a full rsync of Arch about a month behind; `edge` tracks Arch
  hourly.

### OPR (`omacom/omarchy-pkgs`)

- 121 pkgbases: 85 with `source: aur` (75 auto-synced at AUR HEAD every six hours
  through a bot pull request a human merges), 36 local, seven of those vendor-binary
  repackagings such as `mise-bin`, Perplexity, and Codex desktop.
- Packages are GPG-signed with a key shipped in `omarchy-keyring`; the database is not
  signed. Channels are edge, rc, and stable with artifact promotion. One self-hosted
  host builds, signs, and serves.
- The vendor feed fetches the GitHub releases list, picks the newest release older than
  `min_release_age` (only `mise-bin` sets it, 24h), fetches `SHASUMS256.txt` over TLS
  from the same release, and writes the checksum into the PKGBUILD. Nothing verifies an
  attestation, cosign, minisign, or PGP signature on the upstream artifact. Built
  packages carry `packager = Unknown Packager`.
- AUR sync has no age gate, diff scanner, or advisory mechanism. The human merge is the
  only review.
- The separate `omarchy-plugin-registry` (shell plugins) already designed an
  Ed25519-signed append-only index with a kill-bit; the same shape is reused here.

### What aube and mise already do

- aube: managed hardening config that user config can only tighten, a 24h minimum
  release age with strict and soft modes, a 30-day minimum package age for new names,
  a no-downgrade trust policy on provenance evidence, default-deny lifecycle scripts
  with explicit approval, a Landlock plus seccomp build jail, OSV malicious-package
  checks, low-download and similar-name gates, a `paranoid` bundle, and a scanner hook
  that Socket already implements.
- mise: `minimum_release_age` with per-tool override, a `mise-sigstore` crate that
  natively verifies GitHub attestations, cosign, SLSA, minisign, and OpenPGP, a lockfile
  with checksum, size, URL, and provenance, `paranoid`, `safe` mode, and trusted config
  paths with content hashing.

### Ecosystem reality

- No third-party scanner understands PKGBUILDs or `.pkg.tar.zst`. Socket supports nine
  language ecosystems, no distro packages, and publishes no signed verdicts; its useful
  primitives are batch purl lookup and the `sfw` firewall proxy. OSV has no Arch
  ecosystem. Arch's CVE feed is `security.archlinux.org/all.json`.
- Rekor accepts key-based entries, so self-hosted builds can have a public transparency
  log without Fulcio. The `sigstore-verify` Rust crate verifies bundles natively.
  Homebrew has attested every bottle since 2024. Nothing like trusted publishing exists
  for a pacman repository.
- in-toto has vetted predicate types for scan results and releases. A static rule
  engine, an antivirus scan, an AI reviewer, and a human sign-off can all be the same
  document shape with a different reviewer field.
- Arch's ALPM Rust project published `alpm-types`, `alpm-srcinfo`, `alpm-pkginfo`,
  `alpm-buildinfo`, `alpm-mtree`, `alpm-package`, `alpm-repo-db`, `alpm-db`,
  `alpm-lint`, and `alpm-solve` in March 2026.
- pacman fetches only `.sig` sidecars. Any other file next to a package is ignored, so
  extra sidecars are safe to publish. The `desc` format is not extensible.
- AUR RPC v5 exposes maintainer, submitter, first-submitted, last-modified, votes,
  popularity, out-of-date, and pending requests. It has no maintainer-change history.
  Full git history per pkgbase is available by clone.
- yay 13 shows PKGBUILD age and maintainer; paru shows diffs on upgrade. Chaotic-AUR
  auto-builds only when every maintainer of a package is on a trusted list.

## Principles

1. One verb for the whole thing. `pacvamp add helix` resolves across Arch mirror, OPR,
   and AUR, and never silently crosses into the AUR.
2. Trust tiers are first-class. Every package has an origin (`arch`, `opr`, `aur`, or
   `custom`) and its evidence is shown in every list, plan, and prompt.
3. AUR is commit-bound. The unit of approval is a pkgbase plus a git commit. pacvamp
   builds exactly that commit and refuses drift without a new review.
4. Declared intent, recorded fact. A manifest says what the machine should have; a
   ledger records what pacvamp did and why.
5. Unattended is stricter than interactive. `-y` and `omarchy update` deny where a
   human is only warned.
6. Policy can be tightened, never loosened, below the distro floor.
7. pacman stays authoritative on disk until the native engine lands, and the native
   engine keeps `/var/lib/pacman/local` byte-compatible forever.
8. Risk gating, not malware detection. Findings are signals and gates; the tool never
   claims to detect malware.
9. Evidence is portable. Every verdict, provenance statement, and vendor manifest is a
   signed in-toto style document any consumer can verify, so mise, OPR, and pacvamp
   share formats rather than integrations.
10. Scope decides the installer; vendor-built decides the evidence. A user-scoped tool
    goes through mise, a system-scoped package goes through pacvamp, and packslip
    applies to any vendor-built artifact whichever path consumes it. Vendor-built
    things are mostly user-scoped tools (agent CLIs, gh, language runtimes), so they
    reach users through mise and the tool channel with no PKGBUILD at all. A
    vendor-built thing is system-scoped, and therefore an OPR package, when it is
    needed before any user exists (mise, pacvamp), when it needs root-only integration
    (setuid helpers, udev, systemd units, PAM or kernel modules, polkit, system D-Bus),
    or when the launcher expects it system-wide (desktop files, icons, MIME handlers
    under `/usr/share`). Source-built software, which is Arch's repos, Omarchy's own
    apps, drivers, and the AUR, always goes through pacvamp.

Non-goals for v1: flatpak and snap, a GUI store, pacman's full flag surface,
multi-distro support, and the AI reviewer itself.

## Architecture

```
pacvamp (bin)           the client
 ├─ cli/               usage-rs surface, output, prompts, --json
 ├─ manifest/          layered TOML, lockfile, managed config
 ├─ ledger/            /var/lib/pacvamp/state.json
 ├─ resolve/           name to (tier, repo or pkgbase)
 ├─ aur/               rpc, git checkout, .SRCINFO, jailed makepkg
 ├─ trust/             index, release.json, sidecars, verdict feed, advisories
 ├─ update/            the omarchy-update package pipeline
 ├─ tui/               ratatui pickers
 └─ engine/            Engine trait; PacmanCli now, Native later
pacvamp-repo (bin)      the server side OPR runs: index, signer gate, sync gate, verdicts, snapshots, tool channel
pacvamp-policy (lib)    findings engine and rule catalog, shared by client and server
packslip (lib + bin)   the vendor-binary standard: schema, verifier, generator
alpm-db (lib)          pacman.conf, local db, sync db, .PKGINFO and .BUILDINFO, vercmp
```

### Engine trait

The engine is the seam that lets a native pacman reimplementation replace the shell-out
later without touching anything above it.

```rust
trait Engine {
    fn refresh(&self, opts: &RefreshOpts) -> Result<()>;
    fn plan(&self, tx: &Transaction) -> Result<ResolvedTx>;
    fn apply(&self, tx: &ResolvedTx, opts: &ApplyOpts) -> Result<Report>;
    fn install_files(&self, pkgs: &[PathBuf], opts: &ApplyOpts) -> Result<Report>;
}
```

`PacmanCli` plans with `pacman -S --print --print-format` and applies with
`sudo env OMARCHY_UPDATE_PACMAN=1 pacman ...` using inherited stdio so pacman's own
prompts and hooks work. Overwrite and ignore rules come from config, never from code.

`Native`, later, adds a resolver over `alpm-solve`, a parallel downloader with mirror
fallback, signature verification, extraction, `.INSTALL` scriptlets, libalpm hooks,
and local-database writes. The sequence is read path, then resolver, then download and
verify, then install.

`alpm-db` reads are native from day one. Search, menu guards, `present`, `missing`,
and `plan` need fast queries, and parsing the database tarballs is immune to libalpm
soname bumps. `vercmp` must match `/usr/bin/vercmp` exactly and is property-tested
against it in CI. The first alpm-db pull request decides whether to wrap Arch's
`alpm-*` crates or write minimal parsers.

### Sources and resolution

Tiers derive from `pacman.conf`: `core`, `extra`, and `multilib` are `arch`;
`[omarchy]` is `opr`; anything else is `custom` and shown by name. The AUR is a virtual
source that never appears in `pacman.conf`. A repo whose `SigLevel` is weaker than the
managed floor is flagged in `doctor` and in every plan.

Resolution walks the sync databases in repo order, then the AUR RPC. A package found
only in the AUR is returned as tier `aur`; interactively that means a confirmation with
a tier banner, unattended it requires `--aur` or a manifest entry with `source = "aur"`.
Virtual names resolve through the sync database `PROVIDES` entries.

## Manifest, lockfile, ledger, managed config

### Manifest

`pacvamp.toml` is layered lowest to highest: `/etc/pacvamp/pacvamp.toml`,
`/etc/pacvamp/conf.d/*.toml` (the omarchy package ships `omarchy.toml` there, generated
from `omarchy-base.packages`), then `~/.config/pacvamp/pacvamp.toml`. The same key wins
by last layer.

```toml
[packages]
helix = {}                                   # arch or opr only
google-chrome = { source = "aur" }           # explicit tier
libreoffice-fresh = { state = "absent" }     # remove a distro preinstall
nvidia-580xx-utils = { hold = true }         # IgnorePkg semantics

[policy]
mode = "warn"                                # interactive default; unattended is always deny
aur.min_commit_age = "72h"
repo.min_release_age.opr = "48h"             # this user chose to lag OPR; default is 0
aur.allow_network_build.google-chrome = { commit = "<approved-commit>" } # jail grant

[update]
overwrite = ["/usr/share/omarchy/*"]         # replaces the hardcoded flag in omarchy-update
ignore = ["gcc14", "gcc14-libs"]
```

### Managed config

`/etc/pacvamp/managed.toml` is owned by the omarchy package, root-only, and applied
last. Each key carries a combinator, exactly as aube does: `max` (the higher value
wins), `trueWins`, `ranked` (a fixed order of strictness), or `managedWins`. User
config can raise an age and never lower it below the floor, cannot turn off signature
or index verification, and cannot grant a network build the floor denies.
`PACVAMP_MANAGED_CONFIG_PATH` adds a stricter file for fleets.

### Lockfile

`pacvamp.lock` sits next to the user manifest and is git-friendly. Per AUR package it
records the approved commit, pkgver, approval time, and the hash of the findings that
were acknowledged. Per package with provenance it records the evidence level so
no-downgrade can be enforced. It also records the snapshot id the machine last
converged to. Copying manifest plus lock to a second machine reproduces the same
reviewed AUR commits.

### Ledger

`/var/lib/pacvamp/state.json` is root-owned, schema-versioned, and written atomically
under a lock. It records every package pacvamp installed with tier, repo, AUR commit,
explicit versus dependency, timestamp, verification results, and the index sequence
and snapshot id seen. It enables `prune`, drift reports, and rollback detection.

## Security model

### Threat model

| Threat | Example | Primary defence |
|---|---|---|
| Malicious new or typosquatted AUR package | `firefox-patch-bin`, July 2025 | package age, similar-name, votes floor, install-script deny, review |
| Malicious update to an adopted AUR package | Atomic Arch, June 2026, 1,500 pkgbases | commit-bound builds, maintainer-change finding, commit age, diff review, verdict feed |
| Malicious language dependency during build | `npm install atomic-lockfile` inside `build()` | network-denied jail, OSV and Socket purl lookup |
| Compromised vendor release | poisoned checksum file on a hijacked release | packslip verified against a pinned identity, no-downgrade, minimum release age |
| Compromised or stale mirror | old database, swapped package | signed database, signed index with sequence numbers, release manifest digests, sidecars |
| Compromised OPR build host | trojaned package with a valid GPG signature | build key separate from repo key, signer gate, Rekor transparency, reproducible cross-check |
| Compromised user config | user-level file disables checks | managed floor |
| Unattended automation | `omarchy update -y` at 3am | deny-and-skip semantics |

### Tier guarantees

| Tier | Integrity | Provenance | Review |
|---|---|---|---|
| `arch` | Arch developer OpenPGP via pacman | Arch build pipeline (opaque) | Arch review |
| `opr` | OPR GPG signature plus signed index entry | OPR build provenance sidecar; vendor packages chain a verified packslip | verdict attestations (static, AV, AI, human), PR review, channel promotion, release-train tests |
| `aur` | PKGBUILD checksums only | none | pacvamp policy engine on an exact commit plus verdict feed |
| `custom` | whatever `SigLevel` says | none | none; always shown |

### Client-side features

These ship with pacvamp alone and need nothing from OPR.

**Policy engine on AUR commits.** A finding is an id, a severity, and evidence.
Config maps each id to allow, warn, or deny. Interactive mode warns by default;
unattended mode denies, which means the package is skipped and reported, not that the
whole run fails.

| id | signal |
|---|---|
| `new-package` | first submitted younger than `aur.min_package_age` (14d) |
| `recent-commit` | target commit younger than `aur.min_commit_age` (48h) |
| `maintainer-changed` | maintainer differs from last approval, maintainer differs from submitter on first install, or pending requests exist |
| `orphaned` | no maintainer |
| `low-reputation` | votes and popularity below floor, first install only |
| `similar-name` | edit distance of two or less from an `arch` or `opr` name or a top-AUR name |
| `source-domain-changed` | any source host differs from the approved commit |
| `checksum-skip` | a non-VCS source with `SKIP` |
| `vcs-source` | git, hg, or svn source, or a `-git` pkgbase (info; warn unattended) |
| `install-script` | `.install` added or changed, or present on first install |
| `suspicious-content` | aube's sniff list over PKGBUILD and `.install` (pipe-to-shell, base64 decode, eval, ssh and cloud credential paths, token env reads, chat webhooks, bare-IP URLs), plus npm, pip, bun, or cargo installs inside build functions |
| `language-dep` | local detection of language package-manager commands; OSV/Socket lookups are not implemented and `scanner.socket_token` is rejected |
| `pkgbuild-large-diff` | a large diff after a quiet history |
| `commit-drift` | target commit differs from the locked commit |
| `verdict` | a block or flag verdict for this pkgbase and commit on the verdict feed |
| `upstream-advisory` | planned: upstream repository appears in OSV's malicious set; no external OSV query is implemented |
| `out-of-date` | AUR out-of-date flag (info) |

`pacvamp aur review <pkg>` prints findings, any published verdicts, the `.SRCINFO`
summary, and the git diff of PKGBUILD and install files between the approved and
target commits. `pacvamp aur approve <pkg> [--commit]` records approval in the lock so a
later unattended run proceeds.

**Jailed builds.** makepkg runs as the invoking user, never root, in two phases so the
jail can differ. The first phase runs `makepkg --verifysource` under Landlock plus
seccomp with network allowed and writes limited to the source cache and a disposable
verification workspace. That workspace is destroyed before later phases, so top-level
PKGBUILD code cannot rewrite the reviewed recipe or plant build inputs. Every phase,
including this network-enabled phase, receives an environment with known secret variables and agent socket variables
removed, and a private HOME. Filesystem access is separately restricted. This confines
top-level PKGBUILD code while downloading sources and verifying checksums.
The second phase runs `makepkg --holdver` in a network-denied jail, with the verified
source cache read-only, to extract, prepare, build, and package. Writable paths are
the private build tree, package output, and logs. TMPDIR, TMP, and TEMP point into
the build tree; shared `/tmp`, `/var/tmp`, and `/dev/shm` are not writable. Packages that
legitimately need network in `build()` get an explicit grant in
`aur.allow_network_build`, or in the OPR package manifest for OPR-built packages. An
AUR grant records the approved commit, becomes invalid when the candidate commit
changes, and must then be reviewed and approved again. Even with network enabled,
Landlock limits reads to the build tree, the declared source cache, and the read-only
system compiler/runtime paths needed by makepkg; the rest of the invoking user's home,
credential files and unrelated system data remain unreadable. This is a filesystem
and internet-socket boundary, not a complete process or Unix-socket namespace. If the
kernel cannot enforce the jail, the build fails instead of running unjailed. This is
the same Landlock strategy mise and aube already implement. An optional devtools
chroot sits behind `aur.chroot`.

**Install-script policy.** `.INSTALL` scriptlets from `aur` packages are default-deny:
shown in review, approved per pkgbase and script hash. Scriptlets from `opr` and
`arch` run, because they were reviewed upstream, but the sniff catalog still warns.

**Release-age quarantine, per tier, user-raisable.** `repo.min_release_age` has
separate values for `arch`, `opr`, and `custom`, all defaulting to zero because OPR is
trusted and the release train already provides a soak. A user who wants to lag can set
`opr = "7d"`. The managed combinator is `max`, so the floor can only raise it. Age
comes from the sync database build date until the index supplies a publish time.
Automation never bypasses the gate.

**Signature floor check.** `doctor` and every plan compare each repo's `SigLevel`
against the managed floor. An unsigned repo shows as `custom/unsigned` and is denied
unattended.

**Lock-and-verify with rollback protection.** Installing from the lock re-verifies AUR
commit hashes. A plan that moves an `opr` package or the index sequence backwards
without `--allow-downgrade` is denied.

**Paranoid mode and static planning.** `paranoid` hardens every soft gate: strict commit age,
install scripts denied everywhere, jail mandatory, network builds denied, advisories
and index verification required and failing closed when unreachable, custom repos
denied. The proposed `safe` setting is unsupported and rejected, even when false. Planning
uses `.SRCINFO` without executing PKGBUILD or hook code. `policy.scanner.socket_token`
is also rejected until external malicious-package lookups exist; the local sniff
catalog only detects language package-manager commands. Omit these unsupported
settings from ordinary and managed policy files.

**audit.** `pacvamp audit` joins the local database against Arch's security tracker so
users see which installed packages carry open issues.

### Server-side features

Everything OPR needs is a subcommand of the `pacvamp-repo` binary in this repository,
so OPR can adopt it by invoking it rather than by taking code. Formats are documented
under `docs/spec/` and shared with the client through the `pacvamp-policy` and
`packslip` crates.

**index.** Signs the pacman database and writes a signed, append-only
`pacvamp-index.json` with a monotonically increasing sequence. Per package file it
records the sha256, size, publish time, sidecar list, evidence flags (build provenance,
vendor manifest, verdicts, reproducible), and the channel record. The signing key is
Ed25519 in minisign format, shipped in `omarchy-keyring`, and separate from the
package GPG key so the two rotate independently. Each sequence's digest is also
published to Rekor so the log is externally auditable. This is the "decorate the
repository with metadata" idea, done as a sidecar because `desc` cannot carry it.

**attest.** Produces a SLSA v1 provenance statement per built package on the
self-hosted builder, signed with a build key that lives only on the build host and is
hardware-backed. The statement's resolved dependencies list the PKGBUILD commit and
every source artifact URI and digest. It is uploaded to Rekor as a hashedrekord and
ships as a `.sigstore.json` sidecar next to the package. The verification identity is
a key, not a Fulcio certificate; the public build key is published in the index.

**sign.** The signer gate is trusted publishing without Fulcio. The GPG repo key lives
on a separate signer host or HSM. The signer signs a package only after verifying that
the provenance bundle is signed by an allowlisted build key, the package digest matches
the bundle subject, the Rekor inclusion proof is present, and the index entry is
consistent. A build-host compromise therefore cannot produce a repo-signed package
without also compromising the signer.

**vendor.** One vetting core with two publishers. The core reads an upstream
declaration, fetches the vendor's release, verifies its packslip against the pinned
vendor identity (or the legacy evidence: checksum file plus minisign, cosign, GPG, or
GitHub attestation, recorded at a lower evidence level), enforces the provenance floor
(no-downgrade) and the minimum release age, and runs the verdict reviewers over the
artifact. The channel publisher, the default, mirrors the artifact with its sidecars
and appends it to the signed tool index for mise; see "Vetted tool channel for mise".
The package publisher, for the system-scoped exceptions in principle 10, emits the
PKGBUILD checksum lines plus a sidecar carrying the vendor's manifest so the built
package chains back to the vendor. Clients then verify the whole chain offline: OPR
bundle, to vendor artifact digest, to vendor packslip, to vendor identity.

**sync-aur.** Runs the shared policy engine on every commit pulled from the AUR and
posts findings on the pull request. Auto-merge happens only when every maintainer is
on a trusted list and the diff is a pure version and checksum bump, the Chaotic-AUR
model. Anything else waits for a pass verdict from a reviewer, human today and AI
later.

**verdict.** One attestation type covers every reviewer. The subject is a pkgbase plus
commit or a package digest. The reviewer field carries a kind (static, av, ai, human,
reproducible), an id, a version, and a rules hash, model name, or prompt hash. The
verdict is pass, flag, or block, with findings and the digests of the inputs reviewed.
Each verdict is signed by the reviewer's key and listed in the index. The first
reviewers are the static rule engine, ClamAV and VirusTotal hash checks, OSV and
Socket purl lookups, and reproducible-build results. An AI reviewer is the same
document with kind `ai`; its policy weight is a client setting, so shipping it later
requires no client change. Because verdicts are keyed by pkgbase and commit rather
than by OPR package, OPR can review popular AUR packages proactively and the feed
becomes an AUR review cache that `pacvamp aur review` consults. A third-party verdict
from any vendor plugs in as one more signed statement with its own reviewer id.

**advisories.** A signed kill list of pkgbase, commits or versions, tier, action
(block or hold), reason, URL, and issue time, merged from OPR maintainers, OSV
malicious entries, and Arch news. Clients cache it with a TTL, warn when stale
interactively, and deny AUR operations unattended once it is older than a grace
period.

**snapshot.** The release-train side: cut snapshots, write and sign the release
manifest, move channel pointers, and record test results and holds.


### Third-party scanning

Socket cannot scan PKGBUILDs or Arch packages today and publishes no signed verdicts.
What works now is purl lookups for the language dependencies a build pulls in, and the
`sfw` proxy inside the build jail. The verdict format is the integration point: a
vendor verdict is one more signed statement with its own reviewer id and needs no
client change. OPR's own reviewers ship first; no vendor is a dependency.

## packslip: the vendor-binary standard

A vendor publishes one signed, machine-readable document per release that says what
the artifacts are and how to verify them. Any consumer (mise, pacvamp and OPR, aqua,
Homebrew, a corporate mirror) verifies it with a single pinned identity and gets
checksums, platform mapping, provenance links, and an evidence level, without
per-vendor logic. The name is neutral on purpose: a packing slip is the paper in the
box listing exactly what shipped.

The document is an in-toto statement whose predicate type is the packslip, so existing
sigstore tooling verifies it unchanged:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "mise-v2026.9.1-linux-x64.tar.xz", "digest": { "sha256": "..." } }],
  "predicateType": "https://packslip.dev/release/v1",
  "predicate": {
    "project": "pkg:github/jdx/mise",
    "version": "2026.9.1",
    "published_at": "2026-09-01T12:00:00Z",
    "source": { "repo": "https://github.com/jdx/mise", "commit": "...", "tag": "v2026.9.1" },
    "artifacts": [
      {
        "name": "mise-v2026.9.1-linux-x64.tar.xz",
        "os": "linux", "arch": "x86_64", "libc": "gnu",
        "size": 12345678, "url": "https://...", "format": "tar.xz",
        "provenance": ["https://.../mise-v2026.9.1-linux-x64.tar.xz.sigstore.json"]
      }
    ],
    "identity": { "scheme": "sigstore-key", "key_id": "..." },
    "sbom": "https://.../sbom.cdx.json",
    "supersedes": "2026.9.0"
  }
}
```

Signing and discovery: the statement is wrapped in a sigstore bundle named
`packslip.sigstore.json`, signed with a vendor key (minisign or cosign key, logged to
Rekor) or with an OIDC identity for vendors who use hosted CI. It is published next to
the artifacts, as a GitHub release asset or under the version directory of a download
site, and optionally advertised at a well-known URL on the vendor's domain listing
recent versions so a consumer can find releases without a registry.

Consumer rules: pin the identity once (registry entry, OPR upstream declaration, mise
tool option). Verify bundle, then statement, then the subject digest of the downloaded
artifact. Enforce no-downgrade on the identity scheme and on the presence of
per-artifact provenance. Apply the minimum release age to the publish time. Treat
`supersedes` as the ordering hint for rollback detection.

Evidence levels, for no-downgrade and the UI: L0 checksums only; L1 signed checksums
or artifact signatures; L2 a signed packslip; L3 packslip plus per-artifact build
provenance; L4 L3 plus reproducible or independently verified.

The `packslip` crate ships the schema, a verifier, and a `packslip create` generator so
vendors adopt it in one CI step. mise's own release workflow is intended to be the
first publisher and the reference; that is a later change in the mise repository.

Consumers:

- OPR, through `pacvamp-repo vendor`. Vendor packages are generated from the packslip
  instead of hand-edited checksum lines.
- mise, through its `github` and `http` backends and a new field in aqua registry
  entries, verifying the packslip when present and recording the evidence level in
  `mise.lock`. Omarchy users running `mise use claude` then get the same guarantees as
  an OPR package.
- The Omarchy tool channel, described next, which vets vendor releases with the same
  pipeline and serves them to mise.

### Vetted tool channel for mise

On Omarchy the agent CLIs (claude, codex, gh, opencode, and the rest) are mise tools,
downloaded straight from vendor releases. Omarchy wants those to be vetted the way OPR
packages are. The answer is a tool channel: a signed index of vendor tool releases
Omarchy has vetted, plus a mirror of the vetted artifacts with their evidence. mise
resolves tools through the channel, so `mise use claude` on Omarchy installs the newest
vetted build rather than whatever the vendor pushed an hour ago. This is not a pacman
bridge; tools stay per-user and versioned in mise's own layout. Principle 10 says
which vendor-built things take this path: everything user-scoped, which on Omarchy is
the agent CLIs, gh, and the developer-tool long tail.

What vetting a tool version means, run by the channel publisher of
`pacvamp-repo vendor`:

- Fetch the vendor release and verify its packslip, or the legacy evidence (checksum
  file plus minisign, cosign, GPG, or GitHub attestation), against the pinned vendor
  identity. Record the evidence level and enforce no-downgrade.
- Apply the minimum release age, so a freshly pushed compromise sits in quarantine
  before any Omarchy machine can fetch it.
- Run the verdict reviewers over the artifact: hash lookups, static checks, and later
  the AI reviewer. A block verdict keeps the version out of the index.
- Copy the artifact to the tool mirror under `tools/<tool>/<version>/` next to three
  sidecars: the vendor's packslip, OPR's own provenance statement for the mirror copy,
  and the verdicts. Published files are immutable, so a vendor deleting or re-uploading
  an asset cannot affect Omarchy users.
- Append the version to the signed tool index. The index uses the same append-only,
  sequence-numbered, minisign-signed format as the package index, so a stale or
  rolled-back index is detected the same way.

Channels match the distro channels: `tools/edge`, `tools/rc`, and `tools/stable`. A
tool version reaches `stable` after the same soak as packages, so a stable machine gets
tools and packages that aged together. The release manifest lists the exact tool index
sequence and channel pointer alongside the package snapshot. Both the plugin and later
native mise integration first verify that manifest, reject a sequence below locally
recorded rollback state, fetch that exact immutable tool index generation, and resolve
versions only from it. A rollback pins the package snapshot, tool index sequence, and
tool-channel pointer as one unit; `latest` never consults a newer current index while a
release is pinned. This makes a given Omarchy stable state reproducible for tools too.

How mise consumes it, in two stages:

1. Now: a backend plugin shipped from this repository that mise installs as-is. It
   reads the channel index, lists vetted versions, downloads from the mirror, verifies
   the sidecars, and installs into mise's normal per-user layout. Omarchy's
   system-level mise config aliases the agent CLIs to it, so `claude` resolves through
   the channel without users typing a backend prefix.
2. Later: native tool-channel support inside mise, a setting listing channel URLs that
   is consulted before the registry for any tool the channel vets, with a paranoid rule
   that refuses unvetted versions of vetted tools. That is a mise change outside this
   repository and it retires the plugin.

Version semantics: `latest` means the newest vetted version in the selected channel. A
user pinning a version the channel has not vetted gets a warning by default and a
refusal under paranoid mode or the managed floor. The channel can place a hold on a
version, which is how a bad release is pulled after the fact.

The channel format is packslip plus verdicts plus an index and carries nothing
Omarchy-specific. A company can run the same `pacvamp-repo vendor` pipeline to publish
an internal vetted-tools channel and mise consumes it identically.

## Release train

The 30-day mirror lag is a proxy for "someone else hit the breakage first". It is
slow, it is not actually tested, and it still lets a broken combination through when
nobody upstream noticed. The model that already delivers "tested together" at rolling
speed is openSUSE Tumbleweed: every published snapshot passed openQA first. NixOS
channels advance the same way.

Snapshots: the mirror becomes a store of immutable snapshots, each identified by an
hour-resolution timestamp, holding `core`, `extra`, and `multilib`. Packages are
content-addressed and shared across snapshots, so a snapshot is its database files plus
a manifest. Arch's own archive is the precedent. Snapshots are retained for 90 days,
and any snapshot that was ever `stable` for a year.

Release manifest: each snapshot has a signed `release.json` recording its id, the Arch
snapshot and signed index sequence for each included repository, creation time, test suite results
with logs, promotion times, and whether it was expedited or held. It also contains a
map keyed by repository name with the SHA-256 digest of each exact sync database and a
canonical package map keyed by `repo/name` whose value is the selected version and
`tested` or `snapshot` label. The signed test result records the snapshot id, repository
index sequence, repository-qualified `repo/name`, exact package output, selected version, and
SHA-256 digest of the package bytes it exercised. `tested` is assigned only when the
snapshot, index sequence, repository, output name, version, and digest all match;
unexercised siblings from a split PKGBUILD remain `snapshot`. Imported results are held
to the same rule: their signed records carry that complete immutable identity for each
exact output exercised, and never expand a pkgbase result to sibling outputs. Keys are
unique and sorted bytewise before signing, so
clients can deterministically match a transaction package to its version and label.
The whole manifest is signed with the index key.

Channels are pointers: `edge` points at the newest snapshot; `rc` at the newest
snapshot that passed the test suite; `stable` at the newest `rc` snapshot that soaked
for three days without a hold. Failed snapshots are skipped and the pointer stays put.
Expected latency for `stable` drops from roughly 30 days to roughly four.

Test suite: build an Omarchy image from the snapshot plus OPR rc and run it in QEMU
across a hardware matrix. Checks: the installer completes, the machine boots to SDDM
and into a Hyprland session, the compositor reports healthy, every base package's
binaries start, each curated install entry installs and launches, `omarchy update`
from the previous `stable` succeeds including migrations and the pacman guard, snapper
rollback works, audio and network come up, and a desktop screenshot stays within
tolerance. Start with the boot and update paths and grow the matrix. The harness is
`pacvamp-repo snapshot test` plus QEMU; openQA is the reference if a full framework is
wanted later.

Tested versus consistent: the suite exercises only base and curated packages.
Everything else in a snapshot is consistent (built and resolved together, no
partial-upgrade hazards) but not tested. The release manifest carries the tested list
so the client labels each package `tested` or `snapshot`. This is Ubuntu's main and
universe distinction without splitting the repo.

Expedited lane: a snapshot cut for an Arch security advisory runs the short suite and
can be promoted straight to `stable` by a maintainer, recorded as expedited with the
advisory ids.

Holds and feedback: regressions are filed against a snapshot id, which appears in
`pacvamp doctor` and in the update log. A hold stops promotion or moves the pointer
back to the previous good snapshot. Opt-in update telemetry keyed by snapshot id is a
later, optional signal.

Client role: `pacvamp channel` shows the channel, the snapshot id it resolves to, and
when it was tested and promoted. `update` records the snapshot id and verifies the
downloaded databases against the release manifest digests, which closes the
mirror-integrity gap and guarantees a whole transaction comes from one snapshot.
`pacvamp channel pin <id>` freezes a machine; `pacvamp rollback --snapshot <id>` performs
the downgrade against the archived snapshot and pairs with the snapper snapshot omarchy
already takes. A three-day soak is also a three-day minimum release age for `arch`,
which is why the client default stays zero.

## Settings

| setting | default | managed combinator |
|---|---|---|
| `aur.min_commit_age` | 48h | max |
| `aur.min_package_age` | 14d | max |
| `aur.min_votes` | 10 | max |
| `aur.jail` | true | trueWins |
| `aur.chroot` | false | trueWins |
| `aur.allow_network_build` | [] | managedWins (floor deny list) |
| `aur.install_scripts` | approve | ranked: allow, approve, deny |
| `repo.min_release_age.arch` | 0 | max |
| `repo.min_release_age.opr` | 0 | max |
| `repo.min_release_age.custom` | 0 | max |
| `repo.min_release_age_excludes` | [] | managedWins |
| `trust.index` | verify | ranked: off, verify, required |
| `trust.provenance` | verify | ranked: off, verify, required |
| `trust.reviewers` | static gate, av gate, ai warn, human gate | managedWins |
| `trust.no_downgrade` | true | trueWins |
| `trust.advisories` | on | ranked: off, on, required |
| `trust.custom_repos` | warn | ranked: allow, warn, deny |
| `scanner.socket_token` | unsupported; rejected when present | — |
| `paranoid` | false | trueWins |
| `safe` | unsupported; rejected when present | — |

The omarchy package ships a managed file that sets the trust settings to verify, the
jail on, install scripts to approve, and a network-build deny list. `paranoid = true`
is the documented one-liner for people who want hard fails.

## Update flow

1. Take pacvamp's lock and wait on pacman's database lock.
2. Fetch and verify the index, release manifest, verdicts, and advisories. Refuse an
   index or snapshot older than the last one seen.
3. Refresh sync databases and verify their digests against the release manifest.
4. Plan repo upgrades by tier, with per-tier age holds and sidecar verification for
   `opr` packages.
5. Plan AUR upgrades: compare versions per foreign package, run the policy engine on
   each candidate commit against the approved commit, consult the verdict feed.
6. Print one plan: repo upgrades by tier with the tested or snapshot label, AUR
   upgrades with findings, packages held by policy, pacnew candidates, orphans.
7. Confirm unless `-y`. Under `-y`, candidate and package policy warnings become
   deny-and-skip. `trust.custom_repos = "warn"` instead emits a warning and permits a
   signed custom repository; an unsigned custom repository is always denied.
8. Run configured pre-update hooks, including the pre-transaction snapper snapshot.
9. Apply the repo transaction with the pacman guard variable set. Return a structured
   error on file conflicts; omarchy keeps its quarantine fallback in v1.
10. Build and install approved AUR upgrades one pkgbase at a time in the jail.
11. List orphans; remove only interactively or with `--prune-orphans`.
12. Report pacnew and pacsave files.
13. Run configured post-update hooks. Hook commands stay outside pacvamp; pacvamp only
    guarantees their ordering around all package mutations.

## CLI surface

```
pacvamp add <pkg>...        [--aur] [--absent]     write manifest, then converge
pacvamp drop <pkg>...                              remove from manifest, then converge
pacvamp install <pkg>...    [--aur] [-y] [-n]      imperative, ledger only
pacvamp remove <pkg>...     [--keep-deps]
pacvamp search <query>      [--aur] [--json]       tiered results with age, votes, maintainer
pacvamp info <pkg>                                 tier, evidence chain, verdicts, findings, tested label
pacvamp list                [--explicit|--aur|--orphans|--drift|--unverified]
pacvamp update              [-y] [--no-aur] [--prune-orphans]
pacvamp plan | apply | status                      manifest convergence, --json, --detailed-exitcode
pacvamp aur review|approve|diff|build <pkg>
pacvamp verify <pkg|file>                          re-run the evidence chain
pacvamp audit                                      Arch security tracker join
pacvamp channel             [pin <id> | unpin]     snapshot id, test and promotion status
pacvamp rollback            --snapshot <id>        downgrade to an archived snapshot
pacvamp pacnew              [--merge]
pacvamp present|missing <pkg>...                   exit-code predicates for menu guards
pacvamp doctor                                     SigLevel floor, keyring, index freshness, jail support

pacvamp-repo index | attest | sign | vendor [--publish channel|package] | sync-aur | verdict | advisories | snapshot
packslip create | verify
```

Every command has `--json`. `-n` prints the exact pacman argv it would run. Elevation
follows mise's policy: root runs directly, a TTY uses `sudo`, a non-TTY requires
`sudo -n`. makepkg never runs as root. The CLI is defined with `usage-rs` derive
macros so `docs/cli` and shell completions are generated. Interactive pickers are
`ratatui` views inside the binary; there is no fzf dependency.

## Adoption

All changes in this repository. The steps other projects would take are written as
guides under `docs/adoption/` so they can be picked up when ready.

Omarchy: package pacvamp in OPR as a vendor-feed package from this repository's
releases, using packslip from day one so pacvamp is the first package through the new
vendor pipeline, and make the `omarchy` package depend on it. Turn the `omarchy-pkg-*`
scripts into one-line shims. Replace the AUR step of `omarchy-update` first, then the
repo step, then drop yay from the base install. Point the menu at pacvamp pickers and
guards. Ship the distro manifest and the managed floor, and run `pacvamp apply` from
`omarchy update`. Point the lazy agent CLIs in the system-level mise config at the
tool channel so they resolve to vetted versions.

OPR: adopt the `pacvamp-repo` subcommands in order: index, attest and sign, vendor,
sync-aur, verdict reviewers, snapshot. Set the packager field. Move the mirror to
snapshots with `stable` and `rc` as pointers a human moves first, then the QEMU suite
gating `rc`, then the timed soak.

mise: publish a packslip from mise's own release workflow; verify packslips in the
`github` and `http` backends and record the evidence level in the lockfile; add native
tool-channel support (a setting listing channel URLs consulted before the registry)
and, until then, list the tool-channel backend plugin in the registry; on Omarchy,
have the `pacman` and `aur` bootstrap managers delegate to pacvamp; stop forcing a zero
minimum release age in the Omarchy update step once the tool channel covers it.

## Repository layout

```
Cargo.toml                 workspace
crates/alpm-db/            pacman.conf, local and sync databases, vercmp, with fixtures
crates/cli-support/        argv handling and the version command shared by the binaries
crates/pacvamp-policy/      findings engine and rule catalog
crates/packslip/           vendor standard: model, minisign, DSSE, verifier, generator, packslip binary
crates/pacvamp/             client binary and library; integration tests with fake pacman, sudo, makepkg, AUR
crates/pacvamp-repo/        server binary; integration tests with a fake gpg, Rekor, and vendor
plugins/mise-tool-channel/ mise backend plugin that consumes a vetted tool channel
harness/                   the snapshot test suite contract and a sample
docs/spec/                 packslip, feeds, provenance, vendor pipeline, sync gate, release train, snapshot store, tool channel
docs/adoption/             omarchy, opr, and mise guides
docs/cli/                  rendered CLI reference (mise run render)
e2e/                       bash tests against the built binaries, meant for an archlinux:base-devel container
```

Expected dependencies: `usage-lib` and `clap`, `serde` with `toml_edit` and
`schemars`, `tar` with `zstd` and `flate2`, `git2` or shell git, `reqwest`,
`sigstore-verify` with `sigstore-bundle` and `sigstore-rekor`, a minisign verifier
ported from mise, `landlock` and `seccompiler`, `ratatui` with `crossterm`, `nix`, and
`insta`.

Conventions, copied from mise: conventional commits, `mise.toml` tasks for build,
test, lint, and render, `hk` for checks, clippy with warnings denied and no `allow`
attributes, and end-to-end tests as bash under a mise task.

## Implementation plan

No direct commits to `main` beyond the bootstrap commit that created it. Work lands as
stacked pull requests, submitted open, never as drafts. Each pull request cites the
section of this document it implements. The stack is opened in groups so review depth
stays manageable; the first group is layers 1 through 6, a working pacman frontend.

1. Scaffold the workspace: crates, `mise.toml` tasks, CI, `hk`.
2. alpm-db: `pacman.conf` and `vercmp`, deciding whether to wrap Arch's crates.
3. alpm-db: local and sync database readers.
4. Engine trait and the pacman CLI engine with `--print` planning, sudo policy, the
   guard variable, and dry-run.
5. Read-only commands: search, info, list, present, missing, doctor.
6. install and remove.
7. Layered manifest and managed floor: add, drop, plan, apply, status.
8. Ledger.
9. AUR: RPC, git checkout, `.SRCINFO`.
10. pacvamp-policy crate.
11. AUR review, approve, and lockfile.
12. Jailed build and install.
13. Update pipeline.
14. packslip: spec, verifier, generator.
15. Trust: index, release manifest, verdicts, advisories, sidecars.
16. Channels and snapshots: channel, pin, rollback, tested labels.
17. pacvamp-repo index and attest.
18. pacvamp-repo sign gate and the vendor vetting core with the package publisher.
19. pacvamp-repo sync-aur gate, verdict, advisories.
20. pacvamp-repo snapshot and test harness.
21. ratatui pickers.
22. audit.
23. pacvamp-repo vendor channel publisher: artifact mirror and signed tool index.
24. mise tool-channel backend plugin.
25. Documentation: specs, adoption guides, rendered CLI docs.

Status, 2026-09-03: all 25 layers are open as one stack of pull requests, each
citing its layer, followed by pull requests closing the follow-ups the layers noted:
release-age floors from the index's `published_at`, one update at a time, AUR
dependency recursion, tested and snapshot labels in `info` and `update`, Merkle
inclusion-proof and checkpoint verification for transparency log entries, client
verification of the provenance and log-entry sidecars, and the Arch-container
end-to-end suite. Still open: verifying sigstore-scheme sidecars, and native
tool-channel support in mise, which is a mise change.

## Verification

- alpm-db: fixture tests; `vercmp` property tests against the real binary in CI.
- Policy engine: table tests over crafted AUR histories (maintainer change, checksum
  flip to SKIP, source domain swap, install-script add, npm install inside build),
  asserting findings and mode defaults. The same suite runs in `pacvamp-repo sync-aur`.
- Jail: an end-to-end test builds a PKGBUILD whose build function tries to reach the
  network; it fails under the default policy and succeeds with a grant.
- Trust: fixture bundles and packslips for valid, wrong key, wrong digest, expired
  trust root, and stale sequence. `packslip verify` round-trips `packslip create`.
- Release train: imported-result fixtures use identical repository/output/version
  triples with different package digests and prove only the exact snapshot and bytes
  exercised receive the `tested` label.
- Signer gate: a test build key and signer key in the container; a package without a
  valid provenance bundle is refused a repo signature.
- End-to-end in an `archlinux:base-devel` container with a local repo produced by
  `pacvamp-repo index`, a local AUR git fixture, and a fake snapshot store: add, drop,
  update, commit-drift denial under `-y`, lockfile round-trip on a second container,
  rollback to a snapshot.
- Benchmarks: `present` and indexed `search` target under 50 ms per fresh process
  on a typical host. The first search after sync rebuilds changed indexes and is
  measured separately; it is not subject to the menu target. The reproducible
  Arch-sized corpus and CI allowances are in `benchmarks/README.md` (150 ms median
  indexed search, 100 ms present, 3 s rebuild on shared runners).

## Decisions

Recorded 2026-09-03. Each states the decision and the reasoning in plain terms.

1. Name of the vendor standard: packslip. Neutral, no distro name in it. A packing slip
   is the paper in the box listing exactly what shipped. Free on crates.io with no
   exact-name repositories at the time of the decision.
2. Build-key custody. The builder signs provenance with a key. If that key is a file on
   disk, whoever breaks into the build host can sign fake provenance and the signer
   gate cannot tell. A hardware-bound key (the TPM already in the server, or a
   YubiKey) can sign but cannot be copied off the machine, so an intruder can only
   abuse it while present and it can be revoked afterwards. Decision: TPM-backed build
   key; the GPG repo key on a separate signer VM or a YubiKey; both public keys in the
   index; yearly rotation.
3. Index and advisory signing key. Reusing the GPG key pacman already trusts is
   tempting, but one key for everything means one rotation breaks everything, and
   verifying GPG from Rust needs an external binary or a large library. An Ed25519 key
   in minisign format verifies in a few hundred lines and rotates on its own.
   Decision: minisign key, shipped inside the existing keyring package.
4. Custom repos during unattended updates. If a user added CachyOS or Chaotic-AUR by
   hand, an overnight update refusing to touch them is safer but surprises people who
   added the repo on purpose and leaves the machine half-upgraded. Decision: warn by
   default, deny only when the repo is unsigned, and let paranoid mode or the managed
   floor deny all custom repos.
5. Native engine and pacman's local database. If pacvamp's future native installer
   writes exactly pacman's on-disk format, every Arch tool and pacman itself keep
   working as a fallback. Dropping that makes Omarchy a fork of Arch rather than a
   distro on Arch. Decision: compatibility is mandatory.
6. Release train soak and retention. Soak is how many days a tested snapshot sits in
   `rc` before it becomes `stable`, giving humans time to catch what tests miss.
   Retention is how long old snapshots stay downloadable for rollback; packages are
   shared between snapshots, so the cost is roughly Arch's churn over the window.
   Decision: three-day soak, 90-day retention, and a year for anything that was ever
   `stable`.
7. AI reviewer weight. A gating reviewer with false positives silently stalls updates
   and erodes trust in every other gate. Decision: start at warn, measure the
   false-positive rate on OPR's sync pull requests for a few months, then gate.
8. Stack size. Twenty-five stacked pull requests at once are hard to review, and a
   change low in the stack forces rebasing everything above it. Decision: land layers 1
   through 6 first, then open the next group.
9. OPR builds stay self-hosted, with no hosted CI. Provenance and trusted publishing
   are key-based with public transparency through Rekor.
10. OPR is trusted by default. Client release-age gating on `arch` and `opr` defaults
    to zero; users may raise it per tier.
11. The CLI uses usage-rs derive macros; interactive views use ratatui.
12. Vetted vendor binaries for mise come from a tool channel (signed index plus
    mirrored artifacts with evidence), not from a pacman bridge. mise tools stay
    per-user and versioned; the channel decides which versions are vetted and what
    `latest` means. A backend plugin from this repository is the bridge until mise
    supports channels natively.
13. Scope decides the installer (principle 10). Vendor-built user-scoped tools go
    through mise and the tool channel; system-scoped software, vendor-built or not,
    goes through pacvamp. The OPR vendor pipeline and the tool channel share one
    vetting core with two publishers, so OPR only keeps PKGBUILDs for the
    system-scoped exceptions such as mise, pacvamp, browsers, and desktop apps.
14. alpm-db writes its own parsers rather than wrapping Arch's `alpm-*` crates. The
    formats involved (`pacman.conf`, `desc` files, `.PKGINFO`, the version grammar)
    are small and stable, a direct port of pacman's C keeps behaviour identical
    (`vercmp` is tested against pacman's own vector table and against the `vercmp`
    binary when present), and the `alpm-*` crates are pre-1.0 with a large dependency
    tree. Revisit for the native engine, where `alpm-solve` and `alpm-package` carry
    real weight.

## Open questions

Living section. Items move to Decisions when settled.

- Whether `packslip.dev` is available for the predicate type host, and the fallback
  host under the `jdx` GitHub organization if not.
- Whether the devtools chroot should become the default for AUR builds once the jail
  has shipped and its overhead is measured.
- Which makepkg version in OPR's build image supports a PKGBUILD `verify()` function,
  which decides where the vendor re-verification step runs.

### Build concurrency and retained artifacts

AUR cache synchronization and building take a per-pkgbase lock outside recipe-writable
directories. A competing operation fails with a retry message. Builds export the
approved Git object rather than copying the mutable checkout, and each invocation
owns a private run directory containing sources, scratch, logs, and package outputs.
Returned artifacts remain available when another build starts.

### Required Arch acceptance job

Every pull request runs the Arch container end-to-end suite in the arch-e2e job.
Missing Docker, an unavailable image, or an unenforceable jail fails the job rather
than skipping it. This covers real pacman and makepkg in addition to the Rust fixtures.

### Interrupted transaction recovery

Before package mutations, persist the intended ledger patch and accepted evidence
in the root-owned ledger journal. After pacman exits successfully, durably mark
the transaction completed before merging the patch and clearing the intent.
Failures and interruptions retain the intent. `pacvamp recover` previews these
records; `--write` restores only completed records whose installed versions and
removals still match. Prepared records have uncertain outcomes and are never
promoted to verified state. `--discard ID` explicitly forgets an inspected intent.
This recovers bookkeeping, not package contents or failed pacman hooks.

### Build resource controls

All makepkg phases have configurable wall-clock, CPU, virtual-memory, process,
file-size and run-directory disk budgets. Managed values are upper bounds.
The helper sets kernel limits and prevents process-group escape; the parent
supervises cancellation and cleans up descendants. Per-process/account limits
and the sampled disk budget are explicitly distinguished from cgroup quotas.
See docs/build-controls.md for defaults and cancellation limits.

### Local AUR build receipts

Successful builds retain a local receipt with the recipe commit, verified-source
inventory, Git source refs, available dependency versions, makepkg digest, build
policy and output digests. Installation checks the artifact against this receipt
and records its path and hash in the ledger. Receipts are explicitly local records,
not publisher attestations or proof of reproducibility.

### Optional clean-chroot backend

aur.chroot selects an immutable Arch image provisioned with devtools, at
aur.chroot_root. Bubblewrap supplies filesystem and process namespaces around the
existing jailed helper. Builds resolve required dependencies against the image and
refuse missing dependencies without modifying the host; provisioning and updating
the shared image is an explicit administrator operation. There is no silent fallback.
The mandatory Arch CI job builds a real package through this backend.
