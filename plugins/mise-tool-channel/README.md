# mise tool-channel plugin

A mise backend plugin that installs vendor tools from a vetted
[omapac tool channel](../../docs/spec/tool-channel.md). Listing and
fetching go through `omapac tools`, which verifies the channel's signed
index, the artifact digest, the vendor's packslip, and the channel's
provenance, so the plugin itself holds no crypto.

```bash
mise plugin install tool-channel https://github.com/jdx/omapac  # subdirectory plugins/mise-tool-channel
mise use tool-channel:claude@latest
```

`latest` is the newest vetted version in the selected channel, ordered by
publish time.

## Options

Set per tool in `mise.toml`, or through the environment:

| option     | environment             | meaning                                          |
| ---------- | ----------------------- | ------------------------------------------------ |
| `channel`  | `OMAPAC_TOOLS_CHANNEL`  | `edge`, `rc`, or `stable` (default)              |
| `base`     | `OMAPAC_TOOLS_BASE`     | the channel store URL; default omapac's setting  |
| `pubkey`   | `OMAPAC_TOOLS_PUBKEY`   | a minisign key file; default `/etc/omapac/keys`  |
| `platform` |                         | override the mise platform, such as `linux-x64`  |
| `exe`      |                         | the executable inside the archive to expose      |
| `strip`    | `1`                     | leading path components to strip (`0` or `1`) |

On Omarchy the distro ships the channel base and key, and its system
mise config aliases the agent CLIs to this backend:

```toml
[alias]
claude = "tool-channel:claude"
codex = "tool-channel:codex"
```

so `mise use claude` resolves through the channel without a prefix.

## Requirements

`omapac` on `PATH`. The plugin is Lua 5.1 and uses only mise's `cmd`,
`json`, `file`, `archiver`, and `strings` modules.
