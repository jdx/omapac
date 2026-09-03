# Adopting omapac in Omarchy

The steps the `omarchy` repository takes to make omapac the system
package manager. Each step stands alone and can ship in its own release;
the order keeps every intermediate state working.

## 1. Package omapac

Package `omapac` in the Omarchy Package Repository as a vendor-built
package from this repository's releases, through `omapac-repo vendor`
and a `packslip` this repository publishes, so omapac is the first
package through the vendor pipeline. Make the `omarchy` package depend
on it. The package installs:

- `/usr/bin/omapac`
- `/etc/omapac/omapac.toml`, the distro manifest layer (base packages,
  `state = "absent"` entries, holds)
- `/etc/omapac/conf.d/10-omarchy.toml` with the channel settings:

  ```toml
  [channel]
  snapshot_base = "https://mirror.omarchy.org/snapshots"
  tools_base = "https://mirror.omarchy.org"
  ```

- `/etc/omapac/managed.toml`, the floor users cannot lower
- `/usr/share/omapac/keys/omarchy.pub`, the feed and channel key (or
  ship it in `omarchy-keyring`)

## 2. Shims

Turn `omarchy-pkg-add`, `omarchy-pkg-drop`, `omarchy-pkg-aur-add`,
`omarchy-pkg-install`, `omarchy-pkg-aur-install`, `omarchy-pkg-remove`,
`omarchy-pkg-present`, and `omarchy-pkg-missing` into one-line shims:

```bash
exec omapac add "$@"          # omarchy-pkg-add
exec omapac add --aur "$@"    # omarchy-pkg-aur-add
exec omapac install -y "$@"   # omarchy-pkg-install
exec omapac present "$@"      # omarchy-pkg-present
```

Guards that tested `pacman -Q` use `omapac present`.

## 3. The update path, in three moves

1. Replace `yay -Sua --noconfirm` in `omarchy-update-aur-pkgs` with
   `omapac update --aur-only -y`. Unattended, every warning denies and
   skips, so a hostile AUR commit is never built at 3am.
2. Replace the `pacman -Syu` step with `omapac update --no-aur -y`. It
   waits for the database lock, honours the manifest's overwrite and
   ignore lists, keeps the `OMARCHY_UPDATE_PACMAN=1` guard variable, and
   records the snapshot it converged to.
3. Drop `yay` from the base install. `omapac update -y` then runs both.

`omarchy update` also runs `omapac apply -y` so the distro manifest
converges (new base packages installed, retired ones removed).

## 4. Menus

Point the install and remove rows at the pickers: `omapac search --pick
<terms>`, `omapac search --aur --pick <terms>`, and `omapac remove
--pick`. `omapac aur review --pager <pkg>` is the review screen.

## 5. Channels

Have `omarchy-refresh-pacman` write `channels/<channel>/$repo/os/$arch`
mirror lines against the snapshot store; `omapac channel` then shows
the snapshot and its test status, `omapac channel pin` freezes a
machine, and `omapac rollback --snapshot` pairs with the snapper snapshot
taken before updates.

## 6. Agent CLIs through the tool channel

In the system-level mise config:

```toml
[alias]
claude = "tool-channel:claude"
codex = "tool-channel:codex"
opencode = "tool-channel:opencode"
```

with the `tool-channel` plugin installed system-wide, so `mise use
claude` resolves to the newest vetted build. Stop forcing
`MISE_MINIMUM_RELEASE_AGE=0` in `omarchy-update-mise` once the channel
covers the tools it was for.
