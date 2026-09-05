# Vendor pipeline

`pacvamp-repo vendor` generates a PKGBUILD from a verified
[packslip v1](https://packslip.dev/release/v1/) release bundle.

## Package declaration

Put `vendor.toml` beside the PKGBUILD:

```toml
[upstream]
project = "github.com/jdx/mise"
min_release_age = "24h"
provenance_floor = "l2"

[artifacts]
x86_64 = { os = "linux", arch = "x86_64", libc = "gnu" }
aarch64 = { os = "linux", arch = "aarch64", libc = "gnu" }
```

The GitHub project implies its repository workflow identity and GitHub OIDC
issuer. Use `identity`, `identity_prefix`, and `issuer` for an explicit policy.
A long-lived key uses `pubkey = "vendor.pub"` instead. Key and identity pins
cannot be combined. Bundles require a verified transparency log entry unless
the reviewed declaration sets `allow_unlogged = true`.

For a signed release list, set `releases` to its bundle URL. Non-GitHub
projects must supply one. Domain project names use a domain/path, such as
`downloads.example.com/tool`; legacy `pkg:` project URLs are not v1 names.

## Resolution and policy

1. Verify the signed list against the configured pin, including its project,
   expiry, and sequence. Refuse a sequence below the one in `vendor.lock`.
   Without a list, discover GitHub release assets and parse tags with
   packslip's tag parser, including monorepo prefixes.
2. Rank by semver precedence. An unconstrained request honors the signed
   list's `latest` recommendation when eligible. `--version 20` selects the
   highest eligible release on the 20 line; an exact version or listed tag
   can also be requested. Every request excludes yanked releases, enforces
   `min_release_age`, and excludes prereleases unless `prerelease = true`.
3. Verify the selected bundle and its digest from the signed list. Require
   the signed project and version to match the selected release and enforce
   age again using the signed publication timestamp.
4. Enforce the evidence floor and no-downgrade against `vendor.lock`.
   Signer comparisons retain the signing scheme and OIDC issuer. Only
   GitHub workflow identities from GitHub's issuer ignore their trailing
   workflow ref; email identities are compared in full.
5. Select each artifact using packslip's selection rules. Unlabelled
   artifacts are the default; set `variant = "fips"` to opt into a variant.
   The most specific platform match wins, then the format preference
   (tar.zst, tar.xz, tar.gz, tar.bz2, tar, zip, raw, gz, xz, zst, bz2,
   deb, rpm, appimage); unresolved ties fail. Linux selectors default to
   GNU libc. An exact `name` selector supports `{version}` substitution.
   Missing checksums are errors.
6. With `--write`, persist the protective lock first, then the bundle
   sidecar, and finally the updated PKGBUILD using atomic writes.

The sidecar is `<pkgbase>.vendor.json`, containing `bundle`, signing scheme,
signer, evidence level, attestor, verification time, and verified Rekor time.
The build ships it as `<package>.vendor.json`.
Without `--write`, report the proposed change; `--json` prints structured output.

`--allow-downgrade` explicitly permits an older list, lower evidence, or
changed signer. It never permits an expired list or invalid signature.
GitHub discovery is unsigned and cannot provide signed-list rollback
protection. Even a signed list may be replayed until expiry at a sequence
the consumer has not surpassed.

`PACVAMP_REPO_GITHUB_API` overrides the GitHub API base and
`PACVAMP_REPO_NOW` fixes the clock for tests.

## Evidence and repackaging

Levels belong to Pacvamp, not packslip:

| Level | Meaning |
| --- | --- |
| L0 | Checksums without a vendor signature |
| L1 | Vendor signatures recorded as checked by the repackager |
| L2 | A verified vendor packslip |
| L3 | A verified vendor packslip with provenance links for every artifact |
| L4 | L3 plus reproducible or independently verified builds |

Provenance links alone do not establish a SLSA build level. This command
records links; it does not verify the linked build provenance.

For vendors without packslips, `pacvamp-repo repack --pkgdir tool --key repack.key`
downloads the remote sources in `.SRCINFO` (or `makepkg --printsrcinfo`),
checks their checksums, and signs a packslip as `attested_by: repackager`.
Use a dedicated repackager key, separate from the build key.
Publish it with `pacvamp-repo index --repack-key repack.pub`.

```toml
[upstream]
project = "downloads.example.com/tool"

[attest]
evidence = [{ kind = "vendor-signature", detail = "checked by the reviewed bump hook" }]
```

The command records the hook's declared evidence and its own PKGBUILD checksum
checks. Each source needs at least one non-`SKIP` checksum unless
`[attest] allow_skip = true`; every supplied non-`SKIP` digest must match.
Downloads have 30-second setup timeouts and a 15-minute body deadline,
with a 15-minute-30-second overall limit including redirects.
Repackager attestations earn L1 for declared vendor-signature evidence, otherwise
L0. Consuming one requires an appropriate `provenance_floor`.
Moving from vendor to repackager attestation requires `--allow-downgrade`;
the reverse is an upgrade. The index distinguishes `vendor_manifest` from
`repackager_manifest` and publishes `repack_keys`.

## Migration

Regenerate legacy unsigned JSON/minisign release lists and two-file manifests
as v1 bundles. Existing package locks remain readable. Republish legacy tool
versions into a fresh tool store: immutable tool versions cannot be overwritten.
The tool channel currently requires an explicit vendor public key; package
generation additionally supports keyless identities.
