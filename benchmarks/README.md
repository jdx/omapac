# Repository search startup

Build the production binary, then run the deterministic synthetic ALPM corpus:

```bash
cargo build --locked --release -p pacvamp
python3 benchmarks/search.py
```

The benchmark generates gzip-compressed databases for core (300 packages), extra
(15,000), multilib (300), and OPR (500), plus 1,124 installed package records.
Entries include signatures, dependency lists and normal repository metadata.
These are synthetic scale fixtures, not a claim to reproduce any particular
mirror snapshot. No network, root access, or host database changes are required.
Use `--sysroot /path/to/root` for a captured real configuration and databases
containing pacman. The benchmark always uses a private user cache.

Every measurement starts a new CLI process and includes JSON output and local
installed-version lookup. `rebuild_ms` measures the first search with no index;
`indexed_median_ms` measures nine later fresh processes. OS filesystem caches are
not dropped: these measure process startup with warm filesystem pages, not cold
physical-disk I/O. The median reduces unrelated scheduling noise; the maximum is
also printed. `present` is measured separately.

The interactive target is under 50 ms for indexed search and present on a typical
host. After a sync database replacement (or the first run), search must parse the
changed databases once and rebuild their indexes; this is a separate, slower
operation. CI checks an indexed median under 150 ms, present under 100 ms and an
initial rebuild under 3 seconds to allow shared-runner variance. The old blanket
50 ms cold target did not distinguish these cases.

## Cache behavior

Search stores compact name/version/description records in
`$XDG_CACHE_HOME/pacvamp/search-v1` (or `~/.cache/pacvamp/search-v1`). Installed
versions are always read from the current local database. Canonical database paths
separate hosts/sysroots, and each record set is keyed by database device, inode,
size, nanosecond modification and change times, and a schema version. Atomic
replacement invalidates even when size and mtime are preserved. In-place changes,
removal, corruption and schema mismatches also cause a fresh read or empty result.
Cache hits and misses recheck the database identity after cache I/O, retrying up
to three times when a refresh overlaps the read. A database that keeps changing
or changes during parsing aborts the search with retry guidance.

Writes use an atomic rename, so concurrent searches never read a partial index.
Missing/unwritable caches fall back to database parsing. Indexes are disposable
and can be deleted at any time. Cache read/write size is limited to 32 MiB per
repository. Filesystems must expose normal local Linux inode/change-time semantics.

This index serves search display only. Installation, including after selecting a
search result, resolves again from the original database and enforces transaction
trust independently. Cache data is never verification evidence.

## Example measurement

On the development host on 2026-09-05, using release binaries and the same
synthetic corpus, the baseline at `f909b44` took a 308.09 ms median across fresh
search processes. The indexed implementation took 15.23 ms (16.40 ms maximum),
with a 262.32 ms first rebuild and about 2.4 MB of indexes. `present` took 9.51 ms.
This is roughly a 20x reduction in repeated startup latency on that host; it is
not a guarantee for other hardware or a disk-cold workload. The rebuild versus
indexed measurements isolate the cost removed from repeated database
decompression/full-record parsing; they are not a per-function CPU profile.
