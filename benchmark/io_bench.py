#!/usr/bin/env python3
"""Benchmark mf-scan's I/O modes (mmap vs ranged) on one archive or folder.

Runs the same `grep` scenarios under each `--io-mode` and reports, per run, the
numbers that tell you *what* the scan was bound on:

  * wall time              — the clock the operator feels;
  * user / sys CPU time    — the diagnosis. User ≫ sys means CPU/regex bound;
                             sys ≫ user means the kernel is the bottleneck (page
                             faults for `mmap`, read syscalls for `ranged`). On a
                             large `mmap`'d archive sys time explodes while user
                             stays flat — that is the page-fault storm made visible;
  * peak RSS               — `mmap` maps (and, when searched, faults in) the whole
                             archive; `ranged` holds only the file(s) it read;
  * major / minor faults   — majflt are the disk/network ones; an `mmap` sweep
                             racks up minor faults page-by-page across all threads.

After the table a per-scenario summary prints the ranged-vs-mmap speedup, so the
headline ("ranged is the fast path for a large archive, local OR remote") is
impossible to miss.

Match output is discarded (so a `-c` sweep can't flood the terminal); mf-scan's
own scan statistics (entries, bytes scanned, elapsed) are captured from stderr.

Read-only: every scenario is a `grep` with `--no-report`, so nothing is written —
the source is never modified.

Usage:
    python3 benchmark/io_bench.py "/path/to/EXTRACTION_FFS.zip"
    python3 benchmark/io_bench.py ARCHIVE --repeat 3 --modes ranged,mmap \
        --scenarios listing,content
    # A directory operand is scanned as a folder (--dir-mode is added). Folders
    # have no mmap/ranged toggle, so they are measured once per scenario:
    python3 benchmark/io_bench.py "/path/to/00008120-...A2201E"

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
    # cheap" claim. --match-path searches names, so no content is fetched. On a
    # huge archive this isolates the central-directory parse (one cost both modes
    # pay regardless of how few files a real search then touches).
    "listing": ["zzz_no_match_zzz", "--match-path"],
    # The realistic hot path: a full-text sweep with media skipped. This is what a
    # real search spends its time on, so it is the headline mmap-vs-ranged number.
    # `the` matches almost everywhere, exercising the preview/line builder too.
    "content": ["the", "--exclude-media", "-c"],
    # Header-first in action: classify EVERY file by a header read, read only the
    # SQLite ones. Heavy on a million-entry FFS (one header read per file over the
    # network) — scope with --path in real use; here it stress-tests classification.
    "sqlite": ["SQLite format 3", "--type", "sqlite", "-c"],
    # A tightly scoped fetch — the realistic targeted remote search. --path filters
    # before any byte is read, so only matching files are fetched. On a large
    # archive this exposes how much of the wall time is just the directory parse.
    "scoped": ["SQLite format 3", "--path", "*/sms.db", "--path", "*/sms.db-wal"],
    # Everything except media (media skipped by header-first on ranged). Heaviest.
    "no-media": ["the", "--exclude-media", "-c"],
    # The forensic-integrity axis: hash the whole archive before/after the scan to
    # attest it was read intact (`--verify`). This is the one capability the two I/O
    # modes do NOT share — `mmap` has the whole archive addressable and hashes it;
    # `ranged` has no single backing buffer and reports "verify: skipped". The run
    # still searches (scoped, so the search itself is cheap) — the cost measured is
    # the whole-archive SHA-256. Watch the stderr line: mmap attests, ranged skips.
    "verify": ["SQLite format 3", "--path", "*/sms.db", "--verify"],
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


def grab_verify(stderr: str) -> str:
    """Summarise the `--verify` outcome in one word: did the mode attest or skip?

    The forensic axis the two I/O modes differ on — `mmap` hashes the whole
    archive ("integrity confirmed"); `ranged` has no single buffer and prints
    "verify: skipped". Empty when the scenario was not a verify run.
    """
    s = stderr.lower()
    if "integrity confirmed" in s or "sha256 after" in s:
        return "verify: ATTESTED (whole-archive sha256)"
    if "verify: skipped" in s:
        return "verify: SKIPPED (no single backing buffer for this mode)"
    if "verify: warning" in s:
        return "verify: WARNING — archive changed"
    return ""


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
        # User vs system CPU time — the diagnosis of *what* the scan was bound on.
        utime, stime = ru.ru_utime, ru.ru_stime
    else:  # pragma: no cover - non-Unix fallback
        proc.wait()
        rss = majflt = minflt = utime = stime = float("nan")
    wall = time.monotonic() - t0
    return {
        "wall": wall,
        "user": utime,
        "sys": stime,
        "rss_mib": rss,
        "majflt": majflt,
        "minflt": minflt,
        "code": proc.returncode,
        "stats": grab_stats(stderr),
        "verify": grab_verify(stderr),
        "stderr": stderr,
    }


def build_cmd(bin_: str, scen: str, source: str, mode: str, is_dir: bool) -> list[str]:
    """Assemble one read-only `grep` invocation.

    A directory operand is scanned as a folder (`--dir-mode`); folders ignore
    `--io-mode`, so it is omitted for them (passing it would be a no-op that only
    muddies the recorded command).
    """
    args = SCENARIOS[scen]
    cmd = [bin_, "grep", *args[:1], source, *args[1:], "--no-report"]
    if is_dir:
        cmd.append("--dir-mode")
    else:
        cmd += ["--io-mode", mode]
    return cmd


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark mf-scan I/O modes.")
    ap.add_argument("source", help="path to the .zip archive OR folder to scan")
    ap.add_argument("--bin", default=default_bin(), help="mf-scan binary path")
    ap.add_argument("--repeat", type=int, default=2,
                    help="runs per (scenario, mode); run 1 is cold, later runs warm")
    ap.add_argument("--modes", default="ranged,mmap",
                    help="comma list of io-modes to compare (ranged,mmap,auto)")
    ap.add_argument("--scenarios", default="listing,content,scoped",
                    help=f"comma list from: {','.join(SCENARIOS)} "
                         "(sqlite/no-media classify every file — heavy on a large FFS)")
    args = ap.parse_args()

    is_dir = Path(args.source).is_dir()
    # A folder source has no mmap/ranged toggle (FolderSource reads loose files
    # directly), so there is exactly one mode to measure.
    modes = ["folder"] if is_dir else [m.strip() for m in args.modes.split(",") if m.strip()]
    scen_names = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for s in scen_names:
        if s not in SCENARIOS:
            ap.error(f"unknown scenario {s!r}; choose from {','.join(SCENARIOS)}")

    print(f"source  : {args.source}  ({'folder' if is_dir else 'archive'})")
    print(f"binary  : {args.bin}")
    print(f"modes   : {modes}   repeat: {args.repeat}\n")
    hdr = (f"{'scenario':<10} {'mode':<7} {'run':<4} {'wall(s)':>9} {'user(s)':>9} "
           f"{'sys(s)':>9} {'RSS(MiB)':>9} {'majflt':>9} {'minflt':>10}")
    print(hdr)
    print("-" * len(hdr))

    # Last warm wall time per (scenario, mode), for the speedup summary.
    warm: dict[tuple[str, str], float] = {}

    for scen in scen_names:
        for mode in modes:
            for run in range(1, args.repeat + 1):
                cmd = build_cmd(args.bin, scen, args.source, mode, is_dir)
                r = run_once(cmd)
                flag = "" if r["code"] == 0 else f"  !! exit {r['code']}"
                print(f"{scen:<10} {mode:<7} {run:<4} {r['wall']:>9.2f} "
                      f"{r['user']:>9.2f} {r['sys']:>9.2f} {r['rss_mib']:>9.1f} "
                      f"{r['majflt']:>9} {r['minflt']:>10}{flag}", flush=True)
                if run == args.repeat:
                    warm[(scen, mode)] = r["wall"]
                    if r["stats"]:
                        print(f"           └ {r['stats']}", flush=True)
                    if r["verify"]:
                        print(f"           └ {r['verify']}", flush=True)
                if r["code"] != 0:
                    print(f"           └ stderr: {r['stderr'].strip()[:300]}", flush=True)
            print(flush=True)

    # Speedup summary: ranged vs mmap on the warm run, per scenario. Only meaningful
    # when both were measured (an archive source with both modes selected).
    if "ranged" in modes and "mmap" in modes:
        print("ranged vs mmap (warm wall time):")
        for scen in scen_names:
            rg, mm = warm.get((scen, "ranged")), warm.get((scen, "mmap"))
            if rg and mm and rg > 0:
                faster = mm / rg
                verdict = (f"ranged {faster:.2f}x faster" if faster >= 1
                           else f"mmap {1/faster:.2f}x faster")
                print(f"  {scen:<10} ranged {rg:6.2f}s   mmap {mm:6.2f}s   → {verdict}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
