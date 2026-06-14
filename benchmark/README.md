# I/O-mode benchmark

[`io_bench.py`](io_bench.py) compares mf-scan's `--io-mode mmap` against
`--io-mode ranged` on one archive — the measurement that matters for a remote
(SMB/NFS) source, where memory-mapping a multi-GB archive faults page-by-page over
the network while positioned reads fetch only what's searched.

It's **read-only** (every run is a `grep --no-report`, so the archive is never
modified) and **discards match output**, so a `-c` sweep can't flood the terminal.
Per run it reports wall time, peak RSS, and page faults (major faults are the
disk/network ones), plus mf-scan's own scan statistics.

## Run

```bash
# Build the release binary first:
cargo build --release

python3 benchmark/io_bench.py "/path/to/EXTRACTION_FFS.zip"

# Options:
python3 benchmark/io_bench.py ARCHIVE \
    --modes ranged,mmap \      # which io-modes to compare
    --repeat 3 \               # runs each; run 1 is cold, later runs warm (cache)
    --scenarios listing,sqlite,scoped
```

Scenarios (each is a read-only `grep`):

| Scenario | What it measures |
|---|---|
| `listing` | open + parse the central directory only (no file data) — "listing is cheap" |
| `sqlite` | header-first classification: read only the SQLite files, skip the rest |
| `scoped` | a tightly `--path`-scoped fetch — the realistic targeted remote search |
| `no-media` | a heavier sweep that skips media (header-first on ranged) |

## Reading the numbers

- **Run 1 vs run 2**: the first run is cold; later runs hit the SMB client cache.
  Compare like-for-like (cold vs cold).
- **`majflt` (major page faults)**: expected to be high for `mmap` over a network
  mount (each fault pulls a page over the wire) and ~0 for `ranged`.
- **RSS**: `mmap` maps the whole archive into the address space; `ranged` holds only
  the file(s) it actually read.
- **`bytes scanned`** (in the stats line): for the `sqlite`/`no-media` scenarios,
  shows header-first skipping media without fetching it.

## macOS note

Accessing a network volume under `/Volumes` may require granting the controlling app
(Terminal / iTerm / VS Code / the Claude app) **Full Disk Access** in *System Settings
→ Privacy & Security* — otherwise `open()` returns `Operation not permitted` even
though `stat` works.
