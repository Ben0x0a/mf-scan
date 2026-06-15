# I/O & speed benchmark

[`io_bench.py`](io_bench.py) compares mf-scan's `--io-mode mmap` against
`--io-mode ranged` on one source (archive **or** folder), and reports — per run —
**what each scan was bound on**: wall time, the user/sys CPU split, peak RSS, and
page faults, plus mf-scan's own scan statistics.

It's **read-only** (every run is a `grep --no-report`, so the source is never
modified) and **discards match output**, so a `-c` sweep can't flood the terminal.

## Run

```bash
# Build the release binary first:
cargo build --release

python3 benchmark/io_bench.py "/path/to/EXTRACTION_FFS.zip"

# A directory operand is scanned as a folder (--dir-mode is added automatically);
# folders have no mmap/ranged toggle, so they are measured once per scenario:
python3 benchmark/io_bench.py "/path/to/00008120-…A2201E"

# Options:
python3 benchmark/io_bench.py SOURCE \
    --modes ranged,mmap \            # which io-modes to compare (archives only)
    --repeat 3 \                     # runs each; run 1 is cold, later runs warm
    --scenarios listing,content,scoped
```

Scenarios (each is a read-only `grep`):

| Scenario | What it measures |
|---|---|
| `listing` | open + parse the central directory only (no file data) — isolates the CD parse, the fixed cost both modes pay before any file is touched |
| `content` | **the realistic hot path**: a full-text sweep (`the`) with media skipped — what a real search actually spends its time on, and the headline mmap-vs-ranged number |
| `scoped` | a tightly `--path`-scoped fetch — the targeted search; on a huge archive shows how much wall time is *just* the directory parse |
| `sqlite` | header-first classification: read only the SQLite files, skip the rest |
| `no-media` | a heavier sweep that skips media (header-first on ranged) |

> **`sqlite` and `no-media` are heavy on a large FFS:** with no `--path`, they
> classify *every* file by a header read — a million small reads. They stress-test
> classification, not a typical search. The defaults (`listing,content,scoped`) are
> the representative ones; scope real searches with `--path`.

## Reading the numbers

- **user vs sys CPU** — the diagnosis. `user ≫ sys` ⇒ CPU/regex bound; `sys ≫ user`
  ⇒ the kernel is the bottleneck (page faults for `mmap`, read syscalls for
  `ranged`). On a large `mmap`'d archive sys time and `minflt`/`majflt` explode
  while user stays flat — the page-fault storm, made visible.
- **Run 1 vs run 2** — run 1 is cold (no page cache); later runs are warm. Compare
  like-for-like. `mmap`'s cold penalty is large even for `listing`/`scoped`,
  because faulting the central-directory region cold is slower than `ranged`'s two
  positioned reads.
- **`majflt`** — the disk/network page-ins. High for an `mmap` sweep of an archive
  bigger than free RAM (pages get evicted and re-faulted); ~0 for `ranged`.
- **RSS** — `mmap` maps *and faults in* the searched bytes (≈ archive size for a
  full sweep); `ranged` holds only the file(s) it actually read.

## What this revealed (and what was done about it)

Measured on a **local** 23 GB iOS FFS `.zip` (603 789 entries), 10 cores. Warm
unless noted; cold = run 1 of a repeat sweep.

| scenario (warm) | mmap | ranged | notes |
|---|--:|--:|---|
| `listing` | **0.39 s** | 0.63 s | mmap 1.6× faster |
| `scoped` (read 2 files) | **0.49 s** | 0.69 s | mmap 1.4× faster |
| `content` (full sweep) | 32 s / **18 GB** RSS | **24 s** / 2.9 GB RSS | ranged 1.35× faster, **6× less RAM** |
| `verify` (whole-archive hash) | 201 s, **attests** | 0.57 s, **skipped** | only mmap can verify (but it is slow) |

The findings, and the changes that addressed them:

1. **mmap's *open* cost was the problem, not mmap itself.** Resolving every entry's
   data offset from its Local File Header — hundreds of thousands of reads
   scattered across the whole map — was done *sequentially* at open, so a cold
   `listing`/`scoped` cost 2.4–3.1 s before a single file was searched.
   **Fix (shipped):** resolve those offsets **in parallel** (`parse_entries_with_crc`
   in `src/source/zip.rs`). Cold `listing` 2.4 s → **0.49 s**, cold `scoped`
   3.1 s → **0.62 s** — mmap now *wins* the common targeted-search scenarios while
   keeping every forensic field (exact STORED offset, export `file_start`,
   `--match-path`) byte-identical, because the offsets stay resolved (not deferred).

2. **The `content` full-sweep is mmap's one inherent weakness.** Mapping a 23 GB
   archive and touching ~21 GB of it faults the whole file into RSS page-by-page
   across every thread — ~18 GB resident, ~800 k major faults — which no `madvise`
   hint relieves on macOS (tried `MADV_SEQUENTIAL`; no measurable effect, so it was
   not kept). Positioned reads (`ranged`) hold bounded memory and win this case by
   1.35× and 6× RAM. This is the reason to keep `--io-mode ranged` available: it is
   the right tool for a **broad sweep over an entire large archive, or on a
   memory-constrained machine**.

3. **Forensic parity, with one exception.** `ranged` now reports the **same exact
   STORED archive offsets** as mmap (it resolves the data start on read and threads
   it into the record — `Source::archive_data_start`, `MatchRecord::new`), so the
   two modes are forensically equivalent *except* `--verify`: only mmap can hash the
   whole archive (`ranged` has no single backing buffer and prints
   `verify: skipped`). Note `--verify` on a 23 GB archive is itself slow (~201 s,
   it SHA-256s the whole image before and after) — practical for evidence-sized
   archives, a deliberate choice for a full FFS.

4. **Folder small-file reads opened each file twice** (open+stat, then `fs::read`
   re-opens). **Fix (shipped):** read from the already-open handle
   (`src/source/folder.rs`) — one `open()` per small file.

**Default I/O mode: `mmap` stays the default** (auto → mmap locally, ranged on a
network mount). After fix 1 it wins the common targeted searches, keeps exact
offsets, and is the only mode that can `--verify`. Reach for `--io-mode ranged` on
a broad whole-archive sweep or when RAM is tight. Re-run this benchmark after any
related change to confirm the deltas hold.

## macOS note

Accessing a network volume under `/Volumes` may require granting the controlling app
(Terminal / iTerm / VS Code / the Claude app) **Full Disk Access** in *System Settings
→ Privacy & Security* — otherwise `open()` returns `Operation not permitted` even
though `stat` works.
