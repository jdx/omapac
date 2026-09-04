# Adopting packslip and the tool channel in mise

These are mise changes, outside this repository; they are listed so the
two projects move in step.

## 1. Publish a packslip from mise's own release workflow

One step after the artifacts are built:

```bash
packslip create --project pkg:github/jdx/mise --version "$VERSION" \
  --key "$PACKSLIP_KEY" --url-base "https://github.com/jdx/mise/releases/download/v$VERSION/" \
  --source-repo https://github.com/jdx/mise --source-tag "v$VERSION" dist/mise-*
```

and upload `packslip.json` and `packslip.json.minisig` as release assets,
plus a signed release list at a stable URL (see
[the vendor pipeline spec](../spec/vendor-pipeline.md)). mise's existing
minisign key can sign both. This makes mise the reference adopter and
lets OPR build `mise-bin` from the packslip.

## 2. Verify packslips in the `github` and `http` backends

When a release carries a packslip and the registry entry (or tool
option) pins the vendor key, verify the document before trusting a
checksum, record `provenance = "packslip"` and the evidence level in
`mise.lock`, and apply no-downgrade on the level. The `packslip` crate
in this repository is the verifier.

## 3. The tool channel

Until native support exists, list the `tool-channel` backend plugin in
the registry so `mise plugin install tool-channel` is one command. Later,
a setting listing channel URLs consulted before the registry for any
tool the channel vets, with a paranoid rule that refuses unvetted
versions of vetted tools, retires the plugin.

## 4. On Omarchy

Have the `pacman` and `aur` bootstrap managers delegate to `pacvamp
install` and `pacvamp install --aur`, so mise's "my machine" config keeps
working and gains pacvamp's guarantees. Stop forcing a zero minimum
release age in the Omarchy update step once the tool channel covers the
tools it was for.
