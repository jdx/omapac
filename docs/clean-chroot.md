# Clean-chroot builds

The optional backend builds against an independently provisioned Arch image using
bubblewrap's mount, PID, IPC, user, and (during offline builds) network namespaces.
Image paths, including /opt and /var, are mounted read-only. Runtime mounts
(/dev, /proc, /sys, /run, /tmp) are replaced; each run supplies its own writable
/build tree.
The regular Landlock/seccomp jail, source-verification separation, and resource
controls still apply.

Provision an image with Arch devtools, including the package's declared build and
runtime dependencies. For example, an administrator can run:

```sh
sudo pacman -S --needed devtools bubblewrap
sudo mkarchroot /var/lib/pacvamp/chroot/root base-devel
```

Configure the client:

```toml
[policy.aur]
chroot = true
chroot_root = "/var/lib/pacvamp/chroot/root"
```

Then use the normal `pacvamp aur approve` and `pacvamp aur build` commands as a
non-root user. The host's installed libraries do not satisfy image dependencies.
Missing dependencies stop the build before any host package installation. Provision
repository dependencies or previously reviewed AUR dependency artifacts into the
image separately with devtools; pacvamp does not mutate this shared base image.
Update the image explicitly when you want a newer build environment.

Bubblewrap and working user namespaces are required. Startup errors are fatal;
there is no fallback to a host build. `doctor` checks the configured image and
bubblewrap executable; namespace startup is tested by the actual build. Receipts
identify the image and inventory its installed package versions.

The CI container uses privileged mode only to exercise nested namespaces. The
package recipe still runs as the non-root builder inside the read-only image.
