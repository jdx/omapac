#!/usr/bin/env python3
"""Reproducible CLI startup benchmark; no network or privileged host modifications."""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import statistics
import subprocess
import tarfile
import tempfile
import time


def corpus(root):
    """Arch-sized synthetic corpus in real ALPM format, deterministic across runs."""
    database = root / "var/lib/pacman"
    sync = database / "sync"
    sync.mkdir(parents=True)
    repos = [("core", 300), ("extra", 15000), ("multilib", 300), ("omarchy", 500)]
    config = "[options]\nArchitecture = x86_64\n"
    for repo, count in repos:
        config += f"[{repo}]\nServer = https://example.invalid/{repo}\n"
        with (sync / f"{repo}.db").open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as archive:
                    for i in range(count):
                        name = "pacman" if repo == "core" and i == 0 else f"{repo}-package-{i:05}"
                        fields = {
                            "FILENAME": f"{name}-1.0-1-x86_64.pkg.tar.zst",
                            "NAME": name, "BASE": name, "VERSION": "1.0-1",
                            "DESC": f"Utilities and libraries for {name}: package management and development tools",
                            "ARCH": "x86_64", "CSIZE": "1048576", "ISIZE": "3145728",
                            "SHA256SUM": "f" * 64, "PGPSIG": "A" * 768,
                            "URL": f"https://example.invalid/{name}", "LICENSE": "MIT",
                            "BUILDDATE": "1788307200", "PACKAGER": "Benchmark fixture",
                            "DEPENDS": "glibc>=2.40\ngcc-libs\nzlib\nopenssl\nlibarchive",
                            "MAKEDEPENDS": "cmake\npython\ngit", "OPTDEPENDS": "bash: shell integration",
                        }
                        desc = "\n".join(f"%{key}%\n{value}\n" for key, value in fields.items()).encode()
                        entry = tarfile.TarInfo(f"{name}-1.0-1/desc")
                        entry.size = len(desc)
                        archive.addfile(entry, io.BytesIO(desc))
    (root / "etc").mkdir()
    (root / "etc/pacman.conf").write_text(config)
    for i in range(1124):
        name = "pacman" if i == 0 else f"extra-package-{i:05}"
        directory = database / "local" / f"{name}-1.0-1"
        directory.mkdir(parents=True)
        (directory / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n0\n")


def main():
    """Measure fresh CLI processes and enforce optional startup latency budgets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/pacvamp"))
    parser.add_argument("--sysroot", type=Path, help="use an existing ALPM sysroot instead of the generated corpus")
    parser.add_argument("--runs", type=int, default=9)
    parser.add_argument("--max-indexed-ms", type=float)
    parser.add_argument("--max-rebuild-ms", type=float)
    parser.add_argument("--max-present-ms", type=float)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("--runs must be at least 3")
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="pacvamp-search-bench-") as directory:
        base = Path(directory)
        root = args.sysroot.resolve() if args.sysroot else base / "root"
        if not args.sysroot:
            corpus(root)
        env = dict(os.environ, HOME=str(base / "home"), XDG_CONFIG_HOME=str(base / "config"), XDG_CACHE_HOME=str(base / "cache"))
        env.pop("PACVAMP_MANAGED_CONFIG_PATH", None)

        def run(*command):
            """Return wall-clock milliseconds and stdout for a successful CLI invocation."""
            start = time.perf_counter_ns()
            result = subprocess.run([str(binary), "--sysroot", str(root), *command], env=env, capture_output=True, check=True)
            return (time.perf_counter_ns() - start) / 1_000_000, result.stdout

        rebuild, expected = run("search", "--json", "pacman")
        assert json.loads(expected), "corpus must return pacman"
        indexed, present = [], []
        for _ in range(args.runs):
            elapsed, output = run("search", "--json", "pacman")
            assert output == expected, "cached search changed the results"
            indexed.append(elapsed)
            elapsed, _ = run("present", "pacman")
            present.append(elapsed)
        results = {
            "corpus": str(args.sysroot) if args.sysroot else "16100 sync / 1124 installed / core, extra, multilib, OPR",
            "runs": args.runs,
            "rebuild_ms": round(rebuild, 2),
            "indexed_median_ms": round(statistics.median(indexed), 2),
            "indexed_max_ms": round(max(indexed), 2),
            "present_median_ms": round(statistics.median(present), 2),
            "index_bytes": sum(p.stat().st_size for p in (base / "cache/pacvamp/search-v1").glob("*.json")),
        }
        print(json.dumps(results, indent=2))
        for value, threshold, label in [
            (statistics.median(indexed), args.max_indexed_ms, "indexed search"),
            (rebuild, args.max_rebuild_ms, "index rebuild"),
            (statistics.median(present), args.max_present_ms, "present"),
        ]:
            if threshold is not None and value > threshold:
                raise SystemExit(f"{label}: {value:.2f} ms exceeds {threshold:.2f} ms")


if __name__ == "__main__":
    main()
