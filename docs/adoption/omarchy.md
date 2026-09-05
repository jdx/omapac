# Adopting pacvamp in Omarchy

The steps the `omarchy` repository takes to make pacvamp the system
package manager. Each step stands alone and can ship in its own release;
the order keeps every intermediate state working.

## 1. Package pacvamp

Package `pacvamp` in the Omarchy Package Repository as a vendor-built
package from this repository's releases, through `pacvamp-repo vendor`
and a `packslip` this repository publishes, so pacvamp is the first
package through the vendor pipeline. Make the `omarchy` package depend
on it. The package installs:

- `/usr/bin/pacvamp`
- `/etc/pacvamp/pacvamp.toml`, the distro manifest layer (base packages,
  `state = "absent"` entries, holds)
- `/etc/pacvamp/conf.d/10-omarchy.toml` with the channel settings:

  ```toml
  [channel]
  snapshot_base = "https://mirror.omarchy.org/snapshots"
  tools_base = "https://mirror.omarchy.org"
  ```

- `/etc/pacvamp/managed.toml`, the floor users cannot lower
- `/usr/share/pacvamp/keys/omarchy.pub`, the feed and channel key (or
  ship it in `omarchy-keyring`)

## 2. Ownership and scripted helpers

Keep four integration paths separate:

| Intent | Command / owner | Manifest behavior |
| --- | --- | --- |
| Distro base packages and retired packages | Root owns `/etc/pacvamp/conf.d/10-omarchy.toml`; run `pacvamp apply -y` | Updates the installed state from distro declarations |
| Packages deliberately chosen by a user | Run `pacvamp add <names>` / `pacvamp drop <names>` as that login user | Edits that user's manifest; prompts before applying |
| Installer, hardware detection, migration, temporary tools | The scripted helpers below use `install -y` / `remove -y` | Does not edit any manifest |
| Unattended updates | `pacvamp update --no-aur -y`, then AUR update as the build user | Reads policy/holds; does not declare packages |

`omarchy-pkg-add`, `omarchy-pkg-aur-add`, and `omarchy-pkg-drop` already serve
noninteractive setup/migration callers. Install the tested replacements from
[`omarchy/`](https://github.com/jdx/pacvamp/tree/main/docs/adoption/omarchy):

```bash
sudo install -m755 docs/adoption/omarchy/omarchy-pkg-{add,aur-add,drop} /usr/local/bin/
```

Check PATH precedence when replacing the packaged helpers. `pkg-add` runs
`pacvamp install -y -- "$@"` and verifies each exact package is installed.
`pkg-aur-add` checks exact installed names, builds only missing ones, and verifies
the result. `pkg-drop` filters absent and duplicate names before
`pacvamp remove -y --nosave`; it retains the recursive dependency cleanup of
`pacman -Rns`. These helpers accept package names, not arbitrary pacman options.
A missing database or failed post-install check fails the helper.

Keep the existing `omarchy-pkg-present` / `omarchy-pkg-missing` helpers until their
callers are audited: pacvamp's guards also accept virtual providers, and
`pacvamp missing a b` means **neither** is installed, not “at least one is missing.”
The replacement installers do not rely on that mixed-list ambiguity.

Run repository helpers in the caller's existing user context; pacvamp elevates
only pacman. `HOME` and `XDG_CONFIG_HOME` select the invoking user's policy layer;
`SUDO_USER` does not redirect it. Never run `sudo pacvamp add` to install a user's
selection. Automated root installers and migrations should explicitly use
`HOME=/root XDG_CONFIG_HOME=/var/empty/pacvamp` with that empty config directory
owned by root, and put mandatory controls in `/etc/pacvamp/managed.toml`.
Do not inherit another user's `PACVAMP_MANAGED_CONFIG_PATH` into a root service.
For example, after provisioning the root-owned empty directory:

```bash
env -u PACVAMP_MANAGED_CONFIG_PATH HOME=/root XDG_CONFIG_HOME=/var/empty/pacvamp   omarchy-pkg-add networkmanager
```

AUR builds must run as the intended non-root login/build user, with that user's
HOME and config. A root installer must select this account explicitly and use
`runuser -u <account> -- ...`; do not guess it from an inherited environment.
Preconfigure noninteractive elevation for allowed pacman transactions. Missing
sudo credentials fail promptly; `-y` does not provide them.

During migration, keep machine-detected driver selections imperative unless the
distro deliberately records them in a root-owned machine-specific `conf.d` file.
Do not import temporary tools into the user's manifest. Retire base packages by
changing the owning distro declaration to `state = "absent"` before `apply`.
An imperative removal leaves declarations intact, so a later `apply` can reinstall
the package. `drop` only removes the user's declaration and preserves lower-layer
requirements; it is not the scripted removal helper.

## 3. Unattended updates and failures

Preserve Omarchy's snapshot, update lock, logging and migration ordering. Replace
only the package steps. Tested `omarchy-update-system-pkgs` and
`omarchy-update-aur-pkgs` replacements are included in the same directory;
install them after configuring the execution contexts described above:

```bash
# omarchy-update-system-pkgs, in the established system context:
pacvamp update --no-aur -y
# Converge distro declarations before migrations that require them:
pacvamp apply -y
# omarchy-update-aur-pkgs, as the intended non-root build user:
pacvamp update --aur-only -y
```

Use `set -e` (as Omarchy's update entrypoint already does) and preserve stdout,
stderr and exit status in the update log. Failed required installs/removals or
repository updates stop dependent migration work. Do not add `|| true`, retry
with direct `pacman --noconfirm`, or disable policy to work around a refusal.
`-y` refuses install/remove warnings instead of presenting a prompt. Repository
upgrades allow the existing custom-repository warning exception but still enforce
configured trust checks and other blocking warnings.

Release-age holds and denied AUR candidates may be reported and skipped while
`update -y` exits successfully. Success therefore does not mean every package was
upgraded. Retain the `held` / `blocked unattended` / `skipped` reports and their
retry guidance in Omarchy's status/log view; a migration requiring a specific
version must verify it explicitly (for example `pacvamp present 'pacman>=7'`)
before running. Interactive review of a blocked AUR package is a separate user
action. Do not drop `yay` until these paths and required AUR build dependencies
have passed an installation/update rehearsal.

## 4. User menus

`omarchy-pkg-install`, `omarchy-pkg-aur-install`, and `omarchy-pkg-remove` are
interactive pickers, not aliases for the scripted helpers. Keep their selection
UI and pass the selected package-name array to `pacvamp add -- "${selected[@]}"`,
`pacvamp add --aur -- "${selected[@]}"`, or `pacvamp drop -- "${selected[@]}"`
as the login user when the choice is intended to be persistent. Explain that
`drop` cannot remove a lower-layer requirement. An explicit “remove anyway” action
can invoke `remove`, with a warning that future convergence may reinstall it.

`pacvamp search --pick <terms>` currently invokes imperative `install`, so it is
appropriate for a one-time install menu only. `pacvamp aur review --pager <pkg>`
is the review screen. Do not silently convert existing scripted callers to the
persistent menu path.

## 5. Channels

Have `omarchy-refresh-pacman` write
`channels/<channel>/$repo/os/$arch` mirror lines against the snapshot store;
`pacvamp channel` then shows
the snapshot and its test status, `pacvamp channel pin` freezes a
machine, and `pacvamp rollback --snapshot` pairs with the snapper snapshot
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
