#!/usr/bin/env python3
"""Benchmark mf-scan's I/O modes (mmap vs ranged) on one archive.

Runs the same `grep` scenarios under `--io-mode mmap` and `--io-mode ranged`,
measuring wall time, peak memory, and page faults per run — the numbers that show
whether the positioned-read path actually helps on a remote (SMB/NFS) share. Match
output is discarded (so a `-c` sweep can't flood the terminal); mf-scan's own scan
statistics (entries, bytes scanned, elapsed) are captured from stderr.

Read-only: every scenario is a `grep` with `--no-report`, so nothing is written —
the archive is never modified.

Usage:
    python3 benchmark/io_bench.py "/path/to/EXTRACTION_FFS.zip"
    python3 benchmark/io_bench.py ARCHIVE --repeat 3 --modes ranged,mmap \
        --scenarios listing,sqlite

Cross-platform: uses os.wait4 / getrusage (macOS + Linux). On a platform without
them it still reports wall time.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Scenarios: name -> the grep args (the pattern + filters). Each is appended after
# `grep <pattern>`; all are read-only and suppress the report.
SCENARIOS: dict[str, list[str]] = {
    # Open + parse the central directory only (no file data read): the "listing is
    # cheap" claim. --match-path searches names, so no content is fetched.
    "listing": ["zzz_no_match_zzz", "--match-path"],
    # Header-first in action: classify every file, read only the SQLite ones. -c
    # would print a count per file, so the harness discards stdout.
    "sqlite": ["SQLite format 3", "--type", "sqlite", "-c"],
    # A tightly scoped fetch — the realistic targeted remote search. --path filters
    # before any byte is read, so only matching files are fetched.
    "scoped": ["SQLite format 3", "--path", "*/sms.db", "--path", "*/sms.db-wal"],
    # Everything except media (media skipped by header-first on ranged). Heaviest.
    "no-media": ["the", "--exclude-media", "-c"],
}


def default_bin() -> str:
    """The release binary beside this repo, else `mf-scan` on PATH."""
    here = Path(__file__).resolve().parent.parent
    cand = here / "target" / "release" / "mf-scan"
    return str(cand) if cand.exists() else "mf-scan"


def maxrss_mib(ru) -> float:
    """getrusage ru_maxrss is bytes on macOS, kibibytes on Linux."""
    rss = ru.ru_maxrss
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


STAT_KEYS = ("entries:", "files scanned", "bytes scanned:", "elapsed:")


def grab_stats(stderr: str) -> str:
    """Pull mf-scan's own one-line stats out of its stderr for context."""
    bits = []
    for line in stderr.splitlines():
        s = line.strip()
        if any(k in s for k in STAT_KEYS):
            # Compact: keep just the informative part.
            bits.append(re.sub(r"\s+", " ", s))
    return " | ".join(bits)


def run_once(cmd: list[str]) -> dict:
    """Run `cmd`, discarding stdout, capturing stderr + rusage + wall time."""
    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
    if hasattr(os, "wait4"):
        _pid, status, ru = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        rss = maxrss_mib(ru)
        majflt, minflt = ru.ru_majflt, ru.ru_minflt
    else:  # pragma: no cover - non-Unix fallback
        proc.wait()
        rss = majflt = minflt = float("nan")
    wall = time.monotonic() - t0
    return {
        "wall": wall,
        "rss_mib": rss,
        "majflt": majflt,
        "minflt": minflt,
        "code": proc.returncode,
        "stats": grab_stats(stderr),
        "stderr": stderr,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark mf-scan I/O modes.")
    ap.add_argument("archive", help="path to the .zip archive to scan")
    ap.add_argument("--bin", default=default_bin(), help="mf-scan binary path")
    ap.add_argument("--repeat", type=int, default=2,
                    help="runs per (scenario, mode); run 1 is cold, later runs warm")
    ap.add_argument("--modes", default="ranged,mmap",
                    help="comma list of io-modes to compare (ranged,mmap,auto)")
    ap.add_argument("--scenarios", default="listing,sqlite,scoped",
                    help=f"comma list from: {','.join(SCENARIOS)}")
    args = ap.parse_args()

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    scen_names = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for s in scen_names:
        if s not in SCENARIOS:
            ap.error(f"unknown scenario {s!r}; choose from {','.join(SCENARIOS)}")

    print(f"archive : {args.archive}")
    print(f"binary  : {args.bin}")
    print(f"modes   : {modes}   repeat: {args.repeat}\n")
    hdr = f"{'scenario':<10} {'mode':<7} {'run':<4} {'wall(s)':>9} {'RSS(MiB)':>9} {'majflt':>9} {'minflt':>10}"
    print(hdr)
    print("-" * len(hdr))

    for scen in scen_names:
        for mode in modes:
            for run in range(1, args.repeat + 1):
                cmd = [args.bin, "grep", *SCENARIOS[scen][:1], args.archive,
                       *SCENARIOS[scen][1:], "--io-mode", mode, "--no-report"]
                r = run_once(cmd)
                flag = "" if r["code"] == 0 else f"  !! exit {r['code']}"
                print(f"{scen:<10} {mode:<7} {run:<4} {r['wall']:>9.2f} "
                      f"{r['rss_mib']:>9.1f} {r['majflt']:>9} {r['minflt']:>10}{flag}")
                if run == args.repeat and r["stats"]:
                    print(f"           └ {r['stats']}")
                if r["code"] != 0:
                    print(f"           └ stderr: {r['stderr'].strip()[:300]}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
