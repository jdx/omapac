# packslip: a signed release manifest

Version 1, draft. Predicate type `https://packslip.dev/release/v1`.

## Goal

A vendor publishes one signed, machine-readable document per release that
says what the artifacts are and how to verify them. Any consumer (mise,
pacvamp and the Omarchy Package Repository, aqua, Homebrew, a corporate
mirror) verifies it with a single pinned identity and gets checksums,
platform mapping, provenance links, and an evidence level, without
per-vendor logic. The name is neutral on purpose: a packing slip is the
paper in the box listing exactly what shipped.

## Document

The document is an [in-toto Statement v1](https://github.com/in-toto/attestation)
whose predicate type is the packslip. Existing sigstore tooling therefore
verifies it unchanged.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "mise-v2026.9.1-linux-x64.tar.xz", "digest": { "sha256": "..." } }
  ],
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
        "size": 12345678,
        "url": "https://github.com/jdx/mise/releases/download/v2026.9.1/mise-v2026.9.1-linux-x64.tar.xz",
        "format": "tar.xz",
        "provenance": ["https://.../mise-v2026.9.1-linux-x64.tar.xz.sigstore.json"]
      }
    ],
    "identity": { "scheme": "minisign", "key_id": "5A0A0B8B9C6D7E1F" },
    "sbom": "https://.../sbom.cdx.json",
    "supersedes": "2026.9.0"
  }
}
```

Rules:

- `subject` lists every artifact by file name with its sha256; `artifacts`
  carries the same names with platform, size, download URL, format, and
  provenance links. The two sets of names must match exactly.
- `project` is a package URL (`pkg:`). `version` is the vendor's version
  string, compared as opaque text. `published_at` is RFC 3339 UTC.
- `os`, `arch`, and `libc` use the values `linux`, `darwin`, `windows`,
  `freebsd`; `x86_64`, `aarch64`, `armv7`, `riscv64`, `i686`; `gnu`,
  `musl`. `format` is the archive or installer type.
- `provenance` holds URLs of build provenance statements (SLSA, sigstore
  bundles) for that artifact. A consumer that verifies them may raise the
  level to L3.
- `supersedes` names the release this one replaces, so a consumer can
  detect a rollback without a version-ordering scheme.
- `identity` says how the document is signed and by which key or
  certificate identity, so a consumer can check what it pinned against
  what it received.

The JSON schema is printed by `packslip schema`.

## Signing

The canonical bytes are the compact JSON serialisation with keys in the
order above, exactly as `packslip create` writes `packslip.json`. The
signature is over those bytes.

Schemes:

- `minisign`: a detached [minisign](https://jedisct1.github.io/minisign/)
  signature in `packslip.json.minisig`, prehashed (`ED`) or legacy
  (`Ed`), with a trusted comment covered by the global signature.
  `minisign -V -p vendor.pub -m packslip.json` verifies it, as does
  `packslip verify`. `identity.key_id` is the minisign key id in uppercase
  hex.
- `sigstore-key` and `sigstore-oidc`: a sigstore bundle
  (`packslip.sigstore.json`) signed with a long-lived key logged to Rekor
  or with a workload identity. Reserved; verification of these schemes is
  not in this build.

## Discovery

Publish `packslip.json` and its signature next to the artifacts: as
release assets, or under the version directory of a download site.
Optionally advertise recent releases at
`https://<vendor-domain>/.well-known/packslip/<project>.json` so a
consumer can find releases without a registry.

## Consumer rules

1. Pin the identity once (a registry entry, an OPR upstream declaration,
   a mise tool option). Never take the key from the document.
2. Verify the signature, then the document structure, then the subject
   digest and size of every artifact you downloaded.
3. Enforce no-downgrade: refuse a release whose `identity.scheme` is
   weaker than the last accepted one, or that dropped per-artifact
   provenance the last release carried.
4. Apply any minimum release age to `published_at`.
5. Treat `supersedes` as the ordering hint for rollback detection.

## Evidence levels

| level | meaning |
|---|---|
| L0 | checksums only, no signature |
| L1 | signed checksums or artifact signatures |
| L2 | a signed packslip |
| L3 | L2 plus per-artifact build provenance that the consumer verified |
| L4 | L3 plus reproducible or independently verified builds |

`packslip verify` reports L2 for a verified document, or L3 when every
artifact links provenance; it does not itself fetch or verify provenance
bundles.

## Tooling

- `packslip keygen -o release.key` writes a secret seed (mode 0600) and
  `release.pub` in minisign format.
- `packslip create --project pkg:github/o/r --version X --key release.key
  --out dist --url-base URL --source-repo URL --tag vX artifact...` digests
  the artifacts, infers platforms from file names (`path:os/arch[/libc]`
  overrides), and writes the document and signature.
- `packslip verify dist/packslip.json --pubkey release.pub --artifact
  file...` verifies and exits 1 on any failure; `--json` prints the result.
