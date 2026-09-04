# Build provenance

Version 1, draft. What a repository's build host attaches to every
package it builds, and how a client checks it.

## The envelope

`<package>.provenance.json` is a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 statement>",
  "signatures": [{ "keyid": "5A0A0B8B9C6D7E1F", "sig": "<base64 Ed25519>" }]
}
```

The signature is a raw Ed25519 signature over the DSSE pre-authentication
encoding of the payload type and payload, made with a build key in the
same format as packslip and minisign keys. The key id is the minisign key
id. A repository lists the build keys it accepts in its index under
`build_keys`, and marks a package's `evidence.build_provenance` only when
the envelope verifies with one of them and the subject digest matches the
package file.

`.sigstore.json` is reserved for a sigstore bundle carrying the same
statement, for repositories that log to Rekor.

## The statement

An in-toto Statement v1 with the SLSA v1 provenance predicate:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "mise-bin-2026.9.1-1-x86_64.pkg.tar.zst", "digest": { "sha256": "..." } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://omapac.dev/build/makepkg/v1",
      "externalParameters": {
        "pkgbase": "mise-bin",
        "source": "https://github.com/omacom/omarchy-pkgs",
        "commit": "..."
      },
      "resolvedDependencies": [
        { "uri": "https://github.com/jdx/mise/releases/download/v2026.9.1/mise-v2026.9.1-linux-x64.tar.xz", "digest": { "sha256": "..." } }
      ]
    },
    "runDetails": {
      "builder": { "id": "omapac-repo attest 5A0A0B8B9C6D7E1F" },
      "metadata": { "invocationId": "...", "finishedOn": "2026-09-03T06:00:00Z" }
    }
  }
}
```

- `externalParameters` name the PKGBUILD repository and the exact commit
  that was built.
- `resolvedDependencies` list every source artifact makepkg fetched with
  its digest. For a vendor-built package this is the vendor's release
  artifact, which is how a client chains from the OPR build to the
  vendor's packslip without downloading the artifact again.
- `builder.id` names the tool and the build key.

## Producing it

```
omapac-repo attest --key build.key --pkgbase mise-bin \
  --source https://github.com/omacom/omarchy-pkgs --commit <sha> \
  --dependency <uri>=<sha256> ... <package files>
```

The build host holds `build.key` (ideally hardware-backed; the seed file
is the interim form) and nothing else signs with it. The signer host that
holds the repository GPG key checks the envelope before signing a package
(the signer gate, a later layer).

## Consuming it

`omapac-repo index` verifies envelopes against the accepted build keys and
records the result. A client reads `evidence.build_provenance` from the
signed index and may fetch the sidecar to display or re-verify the
statement; the accepted keys travel in the index so the client needs no
extra configuration.
