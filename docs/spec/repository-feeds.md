# Repository feeds

Version 1, draft. What a repository publishes beyond pacman's database so
pacvamp clients can verify more than a package signature. Every feed is a
JSON file with a detached minisign signature beside it
(`<name>.minisig`), signed with a distro trust key that clients hold
under `/etc/pacvamp/keys/*.pub` or `/usr/share/pacvamp/keys/*.pub`. The
key is separate from the package GPG key so the two rotate independently.

Feeds live next to the database: `<Server>/pacvamp-index.json`,
`<Server>/advisories.json`, `<Server>/verdicts.json`, where `<Server>` is
the repository's `Server` line in `pacman.conf`. pacman ignores them.

## `pacvamp-index.json`

```json
{
  "version": 1,
  "repo": "omarchy",
  "sequence": 1042,
  "generated_at": "2026-09-03T06:00:00Z",
  "db": { "file": "omarchy.db", "sha256": "..." },
  "packages": {
    "mise-bin-2026.9.1-1-x86_64.pkg.tar.zst": {
      "sha256": "...",
      "size": 12345678,
      "published_at": "2026-09-02T18:00:00Z",
      "sidecars": [
        "mise-bin-2026.9.1-1-x86_64.pkg.tar.zst.sig",
        "mise-bin-2026.9.1-1-x86_64.pkg.tar.zst.sigstore.json",
        "mise-bin-2026.9.1-1-x86_64.pkg.tar.zst.vendor.sigstore.json"
      ],
      "evidence": {
        "build_provenance": true,
        "vendor_manifest": true,
        "verdicts": 2,
        "reproducible": null
      }
    }
  },
  "build_keys": ["untrusted comment: ...\nRW..."]
}
```

- `sequence` increases with every publish and never repeats. A client
  records the newest sequence it has seen and refuses a lower one, which
  catches a stale or rolled-back mirror.
- `db` is the pacman database this index describes; a client compares it
  with the file pacman downloaded.
- `packages` is keyed by file name. `published_at` is when the file was
  first served in this channel, which is what release-age floors use.
- `sidecars` are files next to the package that a client may fetch:
  pacman's `.sig`, the build provenance envelope (`.provenance.json`, see
  `provenance.md`), a sigstore bundle where one exists, the chained vendor
  packslip (`.vendor.json`), scan statements (`.scan.json`).
- `evidence` is what the repository claims; `build_provenance` is set
  only when the envelope verified with an accepted build key at index
  time. A client shows it and may verify the sidecars behind it.
- `build_keys` are the build hosts whose provenance statements the
  repository accepts.

## `advisories.json`

```json
{
  "version": 1,
  "sequence": 17,
  "issued_at": "2026-09-03T06:00:00Z",
  "advisories": [
    {
      "id": "OPR-2026-0007",
      "pkgbase": "helix-bin",
      "commits": ["3f9c1a2b"],
      "versions": [],
      "tier": "aur",
      "action": "block",
      "reason": "maintainer account compromised; commit fetches a payload",
      "url": "https://pkgs.omarchy.org/advisories/OPR-2026-0007",
      "issued_at": "2026-09-03T05:40:00Z"
    }
  ]
}
```

- `commits` and `versions` narrow the advisory; empty means every commit
  or version of the pkgbase. Commit prefixes match.
- `block` means never install or build; `hold` means do not move to it
  automatically, a human may decide.
- Clients cache the feed and warn when it is stale interactively; with
  `trust.advisories = "required"` a stale or missing feed denies AUR
  operations unattended.

## `verdicts.json`

```json
{
  "version": 1,
  "sequence": 3310,
  "issued_at": "2026-09-03T06:00:00Z",
  "verdicts": [
    {
      "subject": { "pkgbase": "helix-bin", "commit": "3f9c1a2b..." },
      "reviewer": { "kind": "static", "id": "pacvamp-policy", "version": "0.1.0" },
      "verdict": "flag",
      "summary": "install-script added; source host changed",
      "findings": ["install-script", "source-domain-changed"],
      "issued_at": "2026-09-03T05:30:00Z"
    },
    {
      "subject": { "sha256": "..." },
      "reviewer": { "kind": "av", "id": "clamav", "version": "1.4.2" },
      "verdict": "pass",
      "issued_at": "2026-09-03T05:31:00Z"
    }
  ]
}
```

- A subject is an AUR recipe at a commit, or a built package by digest.
- `reviewer.kind` is `static`, `av`, `ai`, `human`, `reproducible`, or a
  vendor's own kind. The client weights kinds through
  `trust.reviewers`; a `block` from a gating kind denies, a `flag` warns,
  a `pass` is silent.
- Because verdicts are keyed by pkgbase and commit, a repository can
  review popular AUR packages proactively and the feed doubles as an AUR
  review cache for `pacvamp aur review`.

## Producing the feeds

`pacvamp-repo index` writes the index; `pacvamp-repo verdict` and
`pacvamp-repo sync-aur --verdicts` append to the verdict feed;
`pacvamp-repo advisories add|remove` maintains the advisory feed. Every
write advances the sequence, sets `issued_at`, and re-signs the file with
the feed key. See `sync-gate.md`.

## Client behaviour

1. Load trust keys. With none, feeds cannot be verified and `trust.*`
   settings above `off` report that in `doctor`.
2. Fetch each feed and its signature; verify against a key whose id the
   signature names; parse; cache. When the network fails and a cached
   copy exists, use it and say so.
3. Enforce rollback protection on the index sequence against the ledger.
4. Use the index for `verify`, for `published_at` in release-age floors,
   and to show evidence in `info`; use advisories and verdicts as policy
   findings in `aur review` and `update`.
