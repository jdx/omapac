# Adopting pacvamp-repo in the Omarchy Package Repository

The server side, in the order that keeps each step independently
useful. Every command is documented under [the CLI reference](../cli/pacvamp-repo/).

## 1. Keys

```bash
packslip keygen -o /etc/pacvamp-repo/index.key      # feeds, release manifests, tool index
packslip keygen -o /etc/pacvamp-repo/build.key      # the build host only
```

Publish `index.pub` through `omarchy-keyring` (clients read
`/usr/share/pacvamp/keys/*.pub`). Keep `build.key` on the build host
(hardware-backed when possible) and the GPG repository key on a separate
signer host.

## 2. The index

After every `repo-add`, run

```bash
pacvamp-repo index --repo omarchy --dir /srv/repo/omarchy/x86_64 \
  --key /etc/pacvamp-repo/index.key --build-key /etc/pacvamp-repo/build.pub
```

Clients start verifying the database digest and rollback protection at
once; evidence fields fill in as the next steps land.

## 3. Provenance and the signer gate

On the build host, after `makepkg`:

```bash
pacvamp-repo attest --key /etc/pacvamp-repo/build.key --pkgbase "$pkgbase" \
  --source https://github.com/omacom/omarchy-pkgs --commit "$(git rev-parse HEAD)" \
  --dependency "<source url>=<sha256>" ... *.pkg.tar.zst --rekor https://rekor.sigstore.dev
```

On the signer host, instead of a bare `gpg --detach-sign`:

```bash
pacvamp-repo sign --dir /srv/repo/omarchy/x86_64 --build-key /etc/pacvamp-repo/build.pub \
  --gpg-key 40DFC571 --require-rekor --index /srv/repo/omarchy/x86_64/pacvamp-index.json
```

A package without accepted provenance is refused a signature.

## 4. Vendor packages

Replace the checksum-fetching `sync-upstream` step with a `vendor.toml`
per vendor package and

```bash
pacvamp-repo vendor --pkgdir pkgs/mise-bin --write
```

which rewrites the PKGBUILD from the vendor's packslip and writes the
`.vendor.json` sidecar the build ships. Vendors without a packslip keep
the old path until they publish one (`packslip create` is one CI step).

## 5. The AUR sync gate

Replace the bot that pulls AUR HEAD every six hours with

```bash
pacvamp-repo sync-aur --state aur-state.json --trusted-maintainer <name>... \
  --verdicts /srv/repo/omarchy/x86_64/verdicts.json --key /etc/pacvamp-repo/index.key --write
```

Clean bumps by trusted maintainers merge on their own; everything else
opens a review. Humans record decisions with `pacvamp-repo verdict`, and
`pacvamp-repo advisories add` publishes a block or hold within minutes of
a compromise report.

## 6. Snapshots

Move the mirror to a snapshot store:

```bash
pacvamp-repo snapshot --store /srv/mirror --key /etc/pacvamp-repo/index.key cut --from /srv/mirror-sync
pacvamp-repo snapshot --store /srv/mirror --key /etc/pacvamp-repo/index.key test --id <id> --suite ./omarchy-train.sh
pacvamp-repo snapshot --store /srv/mirror --key /etc/pacvamp-repo/index.key promote --channel stable
```

Serve `channels/{edge,rc,stable}` as the mirror roots. Start with a
human moving `stable`; add the QEMU suite to gate `rc`; then let the
timed soak promote.

## 7. The tool channel

For each agent CLI, a `tool.toml` and

```bash
pacvamp-repo tool-channel --store /srv/mirror --key /etc/pacvamp-repo/index.key publish --config tools/claude/tool.toml
```

on a schedule, with `promote` following the package channels.

## Also

Set `PACKAGER` in `makepkg.conf`; the plan's "What exists today" notes
the packages currently say "Unknown Packager".
