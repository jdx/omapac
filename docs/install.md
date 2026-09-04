# Install Pacvamp

Pacvamp currently ships as a proof-of-concept package for x86-64 Arch Linux and
other pacman-based distributions. Use it on a disposable or recoverable machine.

## 1. Verify and trust the repository key

Compare the full fingerprint with the independently published
[Pacvamp trust roots](/trust):

```bash
curl --fail --show-error --silent \
  https://repo.pacvamp.com/keys/repository.asc \
  -o pacvamp-repository.asc
gpg --show-keys --fingerprint pacvamp-repository.asc
```

The fingerprint must be:

```text
E5E3 DDD7 492A C50D 42BF EEA8 D9D6 D838 ADC4 20F3
```

Import and locally trust that key for pacman:

```bash
sudo pacman-key --init
sudo pacman-key --add pacvamp-repository.asc
sudo pacman-key --lsign-key E5E3DDD7492AC50D42BFEEA8D9D6D838ADC420F3
```

## 2. Add the repository

Append this repository to `/etc/pacman.conf`:

```ini
[pacvamp]
SigLevel = Required DatabaseRequired
Server = https://repo.pacvamp.com/channels/stable/pacvamp/os/$arch
```

Install Pacvamp:

```bash
sudo pacman -Syu pacvamp
```

The package includes the registry index key at
`/usr/share/pacvamp/keys/pacvamp-registry.pub`. Its key ID must be
`8C2D61867298C6DC`; its complete value and checksum are on the
[trust-roots page](/trust).

## 3. Check the installation

```bash
pacvamp version
pacvamp doctor
pacvamp search pacvamp
pacvamp info pacvamp
```

The repository is live, signed, and independently verifiable, but Pacvamp is
still a proof of concept. In particular, review the known limitations before
using AUR builds or unattended transactions.
