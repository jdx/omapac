# Isolated Pacvamp registry

This is the first production-shaped Pacvamp registry. It serves one independent
pacman repository at `repo.pacvamp.com`; it does not read, write, proxy, or share
keys with OPR.

The deployment is intentionally static:

```text
publisher                         Caddy
/srv/pacvamp/sync/                /srv/pacvamp/store/
  pacvamp/os/x86_64/                snapshots/<id>/
    pacvamp.db                       channels/{edge,rc,stable}
    *.pkg.tar.zst                    keys/
    pacvamp-index.json
```

`publish-canary` builds a small package, writes signed build provenance, gates
its package signature on that provenance, updates the signed pacman database,
and writes `pacvamp-index.json`. `snapshot` then makes an immutable release,
runs the consistency suite, and advances `edge` and `rc`. Promotion to `stable`
is manual for the canary.

## Host

Use a clean Arch Linux VM with a dedicated disk or volume mounted at
`/srv/pacvamp`. Two vCPUs, 4 GiB RAM, and 40 GiB of storage are ample for the
canary. Do not connect the host to OPR infrastructure.

## Automatic deployment

Successful `ci` runs on `main` trigger `.github/workflows/registry-deploy.yml`.
The workflow builds `packslip` and `pacvamp-repo` from the exact tested commit,
bundles them with this directory, uploads the bundle over pinned-host SSH, and
runs the idempotent installer. Signing keys are generated on the server during
the first deployment and are never uploaded to or stored by GitHub.

Create a GitHub environment named `registry` with these values:

- variable `REGISTRY_SSH_HOST`: the VM address;
- variable `REGISTRY_SSH_PORT`: normally `22`;
- variable `REGISTRY_SSH_USER`: an SSH account that is root or has noninteractive
  sudo;
- secret `REGISTRY_SSH_PRIVATE_KEY`: its private deployment key;
- secret `REGISTRY_SSH_KNOWN_HOSTS`: a verified `known_hosts` line for the VM.

The VM needs only SSH access for the first run. The installer performs the
package upgrade, installs runtime dependencies and services, preserves existing
keys, publishes the first canary, promotes that first passing snapshot to
`stable`, and enables Caddy and the daily snapshot timer. Later deployments
replace code and configuration without rotating keys or republishing the same
canary.

The remaining commands in this guide describe what the installer does and are
also the manual recovery path.

Install `base-devel`, `caddy`, `git`, `gnupg`, and Rust, then install the two
publisher binaries into the system path (packslip is maintained separately):

```bash
cargo build --locked --release -p pacvamp-repo
cargo install packslip --version '=1.0.0' --locked --root target/packslip-cli
sudo install -Dm755 target/packslip-cli/bin/packslip /usr/local/bin/packslip
sudo install -Dm755 target/release/pacvamp-repo /usr/local/bin/pacvamp-repo
```

Install the deployment files:

```bash
sudo install -Dm644 deploy/registry/pacvamp-registry.sysusers \
  /usr/lib/sysusers.d/pacvamp-registry.conf
sudo systemd-sysusers /usr/lib/sysusers.d/pacvamp-registry.conf
sudo install -Dm644 deploy/registry/pacvamp-registry.tmpfiles \
  /usr/lib/tmpfiles.d/pacvamp-registry.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pacvamp-registry.conf
sudo install -Dm755 deploy/registry/bin/publish-canary \
  /usr/local/lib/pacvamp-registry/publish-canary
sudo install -Dm755 deploy/registry/bin/snapshot \
  /usr/local/lib/pacvamp-registry/snapshot
sudo cp -R deploy/registry/canary /usr/local/lib/pacvamp-registry/
sudo install -Dm644 deploy/registry/pacvamp-registry-snapshot.service \
  /etc/systemd/system/pacvamp-registry-snapshot.service
sudo install -Dm644 deploy/registry/pacvamp-registry-publish.service \
  /etc/systemd/system/pacvamp-registry-publish.service
sudo install -Dm644 deploy/registry/pacvamp-registry-snapshot.timer \
  /etc/systemd/system/pacvamp-registry-snapshot.timer
sudo install -Dm644 deploy/registry/Caddyfile /etc/caddy/Caddyfile
sudo install -Dm640 -o pacvamp-registry -g pacvamp-registry \
  deploy/registry/registry.env.example \
  /etc/pacvamp-registry/registry.env
```

## Keys

The canary uses three independent identities:

- the index key signs Pacvamp feeds and release manifests;
- the build key signs provenance envelopes;
- the repository GPG key signs packages and pacman databases.

Generate the minisign-format keys as the publisher account:

```bash
sudo -u pacvamp-registry packslip keygen -o /etc/pacvamp-registry/index.key
sudo -u pacvamp-registry packslip keygen -o /etc/pacvamp-registry/build.key
sudo -u pacvamp-registry env GNUPGHOME=/var/lib/pacvamp-registry/gnupg \
  gpg --batch --passphrase '' --quick-generate-key \
  'Pacvamp Registry <registry@pacvamp.com>' ed25519 sign 2y
sudo -u pacvamp-registry env GNUPGHOME=/var/lib/pacvamp-registry/gnupg \
  gpg --list-secret-keys --with-colons
```

Put the GPG fingerprint in `PACVAMP_GPG_KEY` inside
`/etc/pacvamp-registry/registry.env`. Copy the public trust roots into the
served tree:

```bash
sudo -u pacvamp-registry cp /etc/pacvamp-registry/index.pub \
  /srv/pacvamp/store/keys/index.pub
sudo -u pacvamp-registry env GNUPGHOME=/var/lib/pacvamp-registry/gnupg \
  gpg --armor --export registry@pacvamp.com | \
  sudo -u pacvamp-registry tee /srv/pacvamp/store/keys/repository.asc >/dev/null
```

For the proof of concept, all three keys live on this isolated host. Before publishing
anything users rely on, move the repository GPG key to a separate signer and
put the index key in hardware-backed storage. Cross-publish both public-key
fingerprints on the [Pacvamp trust-roots page](/trust); a key downloaded only
from the registry it authenticates is not a sufficient trust bootstrap.

## Manual first publish

Edit `registry.env`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl start pacvamp-registry-publish.service
sudo systemctl start pacvamp-registry-snapshot.service
sudo -u pacvamp-registry pacvamp-repo snapshot \
  --store /srv/pacvamp/store \
  --key /etc/pacvamp-registry/index.key \
  status
```

Promote the tested snapshot deliberately:

```bash
id=$(readlink /srv/pacvamp/store/channels/rc | xargs basename)
sudo -u pacvamp-registry pacvamp-repo snapshot \
  --store /srv/pacvamp/store \
  --key /etc/pacvamp-registry/index.key \
  promote --channel stable --id "$id"
```

Validate and start the web server, but leave the timer disabled until the
manual publish works end to end:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl enable --now pacvamp-registry-snapshot.timer
```

Create `A`/`AAAA` records for `repo.pacvamp.com` pointing at this host. Caddy
obtains and renews TLS automatically once DNS resolves and ports 80/443 reach
the VM.

## Client smoke test

Follow the [installation guide](/install) to import the repository key and add:

```ini
[pacvamp]
SigLevel = Required DatabaseRequired
Server = https://repo.pacvamp.com/channels/stable/pacvamp/os/$arch
```

Then install `pacvamp` and `pacvamp-registry-canary` on a disposable Arch VM.
Run `pacvamp doctor`, exercise repository search and package transactions, and
verify the AUR metadata path. The `registry smoke` workflow performs this journey
against every registry deployment.
