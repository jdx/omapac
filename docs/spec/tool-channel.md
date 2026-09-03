# Tool channel

Version 1, draft. A signed index of vendor tool releases a channel
operator has vetted, mirrored with their evidence, for mise. On Omarchy
this is how `mise use claude` installs a build the distro checked rather
than whatever the vendor pushed an hour ago. Nothing in the format is
Omarchy-specific; a company can publish an internal channel the same way.

## Layout

The tool channel shares the snapshot store:

```
<store>/tools/index.json, index.json.minisig
<store>/tools/<tool>/<version>/<artifact>
<store>/tools/<tool>/<version>/<artifact>.vendor.json       the vendor's packslip
<store>/tools/<tool>/<version>/<artifact>.provenance.json   the channel's provenance
```

Published files are immutable: a vendor deleting or re-uploading an
asset cannot affect a channel user.

## `tools/index.json`

```json
{
  "version": 1,
  "sequence": 42,
  "generated_at": "2026-09-03T06:00:00Z",
  "tools": {
    "claude": {
      "project": "pkg:npm/@anthropic-ai/claude-code",
      "vendor_pubkey": "untrusted comment: ...\nRW...",
      "versions": {
        "2.4.1": {
          "published_at": "2026-09-01T12:00:00Z",
          "vetted_at": "2026-09-02T12:00:00Z",
          "level": "l2",
          "key_id": "5A0A0B8B9C6D7E1F",
          "channels": ["edge", "rc"],
          "artifacts": {
            "linux-x64": {
              "name": "claude-2.4.1-linux-x64.tar.gz",
              "sha256": "...", "size": 12345678,
              "path": "tools/claude/2.4.1/claude-2.4.1-linux-x64.tar.gz",
              "sidecars": ["claude-2.4.1-linux-x64.tar.gz.vendor.json", "claude-2.4.1-linux-x64.tar.gz.provenance.json"]
            }
          }
        }
      }
    }
  }
}
```

- The index is signed with the channel key (the same minisign key as the
  package index) and carries a sequence for rollback protection.
- Versions are keyed by the vendor's version string. Ordering for
  `latest` is by `published_at`, never by parsing the string.
- `channels` lists which of `edge`, `rc`, `stable` carry the version;
  `held` with a reason pulls it from all of them.
- `vendor_pubkey` is the pinned vendor identity so a client can verify
  the packslip in the sidecar itself.

## Publishing

`tool.toml` is a `vendor.toml` with a `[tool]` table and artifacts keyed
by mise platform:

```toml
[tool]
name = "claude"

[upstream]
project = "pkg:npm/@anthropic-ai/claude-code"
releases = "https://claude.ai/.well-known/packslip/claude-code.json"
pubkey = "claude.pub"
min_release_age = "24h"
provenance_floor = "l2"

[artifacts]
linux-x64 = { os = "linux", arch = "x86_64" }
linux-arm64 = { os = "linux", arch = "aarch64" }
```

`omapac-repo tool-channel publish --store S --key K --config tool.toml
[--version V]` resolves the release exactly as the vendor pipeline does
(signed release list, packslip, floor, no-downgrade against what the
index already carries), refuses a version any artifact of which has a
`block` verdict in the store's verdict feed, downloads each artifact and
checks its digest and size against the packslip, writes it with the
vendor sidecar and a channel-signed provenance envelope, and appends the
version to the index in `edge`.

`promote --tool --version --channel rc|stable` adds a channel; `hold`
and `unhold` pull and restore a version; `status` lists everything.

## Consuming

`omapac tools` is the client, and the mise plugin calls it:

- `omapac tools index` fetches and verifies the index with the keys
  under `/etc/omapac/keys` (or `--pubkey`), refusing a sequence below
  the last one seen.
- `omapac tools list <tool> [--channel stable]` prints vetted versions
  oldest first, held versions excluded.
- `omapac tools fetch <tool> <version> --platform linux-x64 --dest DIR`
  downloads the artifact, checks digest and size against the index,
  verifies the vendor packslip in the sidecar against the pinned vendor
  key and the file, and verifies the channel's provenance envelope names
  the digest. A held version is refused unless `--force`.

The channel base comes from `[channel] tools_base` in the manifest or
`--base`.
