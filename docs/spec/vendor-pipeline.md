# Vendor pipeline

Version 1, draft. How a repository builds a package from a vendor's
binary release without trusting a checksum file fetched over TLS. This is
the `omapac-repo vendor` command; the document it consumes is a
[packslip](packslip.md).

## Package declaration

A vendor-built package carries `vendor.toml` beside its PKGBUILD:

```toml
[upstream]
project = "pkg:github/jdx/mise"
releases = "https://mise.jdx.dev/.well-known/packslip/mise.json"
pubkey = "vendor.pub"            # or the base64 line of the minisign key
min_release_age = "24h"
provenance_floor = "l2"          # default

[artifacts]
x86_64 = { os = "linux", arch = "x86_64", libc = "gnu" }
aarch64 = { os = "linux", arch = "aarch64", libc = "gnu" }
```

`pubkey` is the pinned vendor identity. It changes only through a
reviewed commit to the package, which is the trust decision.

## Release list

A vendor advertises releases at a stable URL, signed with the same key
(`<url>.minisig`):

```json
{
  "project": "pkg:github/jdx/mise",
  "releases": [
    { "version": "2026.9.1", "published_at": "2026-09-01T12:00:00Z",
      "packslip": "https://github.com/jdx/mise/releases/download/v2026.9.1/packslip.json" }
  ]
}
```

The list is signed so a hostile mirror cannot hide a release or point at
an older one silently; it cannot forge one either way, since the packslip
must verify too.

## What the command does

1. Fetch the release list and its signature; verify with the pinned key;
   check the project matches.
2. Pick the release: `--version`, or the newest by `published_at` that is
   at least `min_release_age` old. Ordering is by publish time, never by
   parsing version strings.
3. Fetch the release's packslip and signature; verify with the pinned
   key; check project and version match the list.
4. Enforce the evidence floor, and no-downgrade against `vendor.lock`:
   a lower level or a different key than last time is refused unless
   `--allow-downgrade`.
5. Select one artifact per pacman architecture from `[artifacts]`.
6. With `--write`: set `pkgver` and `pkgrel=1`, replace the
   `sha256sums_<arch>` arrays (or `sha256sums` for one architecture),
   write `<pkgbase>.vendor.json` (the packslip document, its signature,
   the level and key id) for the build to ship as
   `<package>.vendor.json`, and write `vendor.lock`.

Without `--write` the command reports what it would do; `--json` prints
the report. `OMAPAC_REPO_NOW` fixes the clock for tests.

## What a client gets

`<package>.vendor.json` travels as a sidecar and the index marks
`evidence.vendor_manifest`. Together with the build provenance envelope,
whose `resolvedDependencies` name the same artifact digests, a client can
chain: repository signature → build provenance → artifact digest →
vendor packslip → vendor identity, all offline.

## Vendors without a packslip

Not handled by this command. A package for such a vendor keeps its
hand-maintained checksums and gets no `vendor_manifest` evidence; the
adoption guide asks vendors to publish a packslip, which is one CI step
with `packslip create`.
