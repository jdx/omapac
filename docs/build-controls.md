# Build controls

Every makepkg phase runs under a supervised process group, including when
`aur.jail = false`. Interrupts and timeouts kill the group. Descendants cannot
create a new session or process group; leftover children are killed when a phase
finishes. SIGKILL of pacvamp itself and uninterruptible kernel tasks are outside
this cooperative supervisor's guarantee.

Defaults can be adjusted in a manifest:

```toml
[policy.aur.limits]
wall_seconds = 7200
cpu_seconds = 7200
memory_mb = 32768
processes = 4096
file_mb = 4096
disk_mb = 20480
```

Values must be positive. Managed limits are upper bounds: user policy can lower
them but cannot raise them above the managed maximum. CPU time, virtual address
space, and individual file sizes use kernel resource limits per process. The
process count uses Linux's per-real-user limit; it includes other processes owned
by the build user and is not enforced for privileged users. These are not cgroup
limits on aggregate memory or CPU.

The supervisor checks the run directory's total regular-file size each second.
This disk budget can overshoot between checks; it is not a filesystem quota.
Symlinks are not followed. Transient unreadable directories receive a three-second
grace period for fakeroot permission probes; persistent accounting failures stop
the build. Metadata command output is capped at 1 MiB per stream.
Build files and logs remain in the private run directory for diagnosis.
