# Architecture

mf-scan is a Rust **library crate** (`mf_scan`) with a thin **binary** on top. All
logic lives in the library so it is unit-testable without the CLI; the binary is only
argument parsing, source resolution, and I/O.

```
src/
  lib.rs        library root (declares the modules below)
  main.rs       BINARY entry point: parse Cli, dispatch Grep | Export | Diff
  cli/          BINARY: clap argument structs, split per subcommand
    mod.rs        Cli + Command enum
    grep.rs export.rs diff.rs   per-subcommand args
    common.rs     shared value types + size parser + the flatten arg-groups
                  (FilterArgs / DecryptArgs / ExportSink) reused by grep & diff
  run/          BINARY: one orchestrator per command (grep.rs / export.rs / diff.rs)
  support/      BINARY: machinery the commands share — sources (resolve operands),
                presets, decryption setup, progress reporter, reporting, exporting

  models.rs     data containers: Method, Entry+Location, SearchHit, MatchRecord,
                Inspection, ContentDiff, RunInfo
  source/       the container abstraction the engine reads through (see ADR 0002)
    mod.rs        Source trait: entries() + content() -> Cow + byte_size()
    zip.rs        ZIP central-directory parser + ZipSource (mmap, zero-copy STORED)
    folder.rs     FolderSource: a directory of loose files (+ nested-archive arena)
    nested.rs     --archive-depth expansion of nested .zip files into the arena
  search/       per-entry byte search: scan.rs (regex + line preview)
  engine/       orchestration: search_source over a Source -> Findings
    mod.rs        drivers + Findings/Query/Progress; classify.rs is the per-entry body
  filter.rs     EntryFilter: path globs (--path/--not-path) + --type / media skip
  diff/         compare two Sources -> DiffReport (mod.rs) using compare.rs (meta|hash)
  preset/       behaviour presets behind one flag; fast.rs is the --fast exclude list
  inspect/      "what does this match mean" inspectors + file-type detection + diff
    mod.rs        Inspector trait (detect/inspect/diff) + registry + detect_type
    txt.rs json.rs xml.rs csv.rs plist.rs sqlite.rs   (resolve offsets; some diff)
    value_diff.rs  shared JSON-tree diff used by json + plist
    media/        the `media` category (classification only)
  report/       output.rs (matches txt/json/csv) · stats.rs · export.rs · diff.rs
```

## Module dependencies

The binary layer (`main`/`cli`/`run`/`support`) depends on the library; within the
library, `engine` and `diff` read through the `source` abstraction, and every data type
bottoms out in `models`.

```mermaid
flowchart TD
    subgraph binary
        main[main.rs] --> cli
        main --> run
        run --> support
    end
    subgraph library["library — mf_scan"]
        engine
        diff
        source
        search
        filter
        inspect
        report
        preset
        models
    end
    run --> engine
    run --> diff
    run --> report
    run --> source
    support --> source
    support --> report
    engine --> source
    engine --> search
    engine --> filter
    engine --> inspect
    diff --> source
    diff --> filter
    diff --> inspect
    report --> source
    report --> inspect
    source --> models
    inspect --> models
    engine --> models
```

## Data flow (grep)

Entries come from a `Source` (a ZIP archive or a folder); they are selected first
(path-only filter), then searched in parallel (rayon, one task per entry).

```mermaid
flowchart TD
    A["Source (ZipSource | FolderSource)"]
    A --> B["source.entries()"]
    B --> C["filter.select(path)<br/>--path / --not-path (path-only)"]
    C --> D["source.content(entry) -> Cow<br/>STORED: borrow · DEFLATE/loose/nested: own"]
    D --> E{"inspect::detect_type (header-first)<br/>+ filter.accept_type<br/>--type / media skip"}
    E -->|excluded| Z["skip entry"]
    E -->|kept| F["search::search_bytes — hits"]
    F -->|"--inspect"| G["inspect::inspect — Inspection"]
    F --> H["engine::Findings<br/>records + files + stats"]
    G --> H
    H --> I["report::output::write_results"]
    H --> J["report::export::plan / export_files"]
```

`engine::search_source` produces **both** `records` (one `MatchRecord` per match) and
`files` (one `MatchedFile` per matched file, de-duplicated for export) in a single pass,
so printing and exporting never re-scan. `diff::diff_sources` runs the analogous flow
over two sources, pairing entries by path (see [diff.md](diff.md)).

## Why these choices

- **The `Source` trait.** The engine used to assume every source was a memory-mapped ZIP
  addressed by byte offsets. A trait with `content() -> Cow` lets folders and nested
  archives flow through the same search/inspect/export pipeline; the offset model becomes
  `Option` where there is no archive byte. See [ADR 0002](adr/0002-source-container-abstraction.md).
- **CD-first ZIP parsing.** The Central Directory is the authoritative list of entries;
  the true data offset is resolved from each Local File Header (whose name/extra lengths
  may differ from the CD's — a classic pitfall).
- **mmap + `regex::bytes`.** STORED data is uncompressed on disk, so a memory-mapped SIMD
  byte-regex runs with no copy. Matching is on `&[u8]`, never `&str` — forensic data is
  arbitrary bytes.
- **Parallelism via rayon.** Entries are searched in parallel; `collect` preserves order,
  so output is deterministic.
- **Library has no UI.** `engine::Progress` is a trait the engine calls; the terminal
  reporter lives in `support`. `report::output::OutputFormat` parses via `FromStr`, so the
  core never depends on clap.
- **Inspectors are a small API, reused for four jobs.** Each format is an `Inspector`:
  `detect` (header), `inspect` (resolve an offset), optional `diff` (intra-file diff for
  `diff --inspect`), and optional `sidecars`. The same registry powers deep inspection,
  `--type`/media filtering (`detect_type`), BLOB classification inside SQLite, and the
  diff — a format is described once. Adding one is a new submodule plus a line in
  `INSPECTORS`.
- **Errors, not panics.** All parsing uses bounds-checked reads returning `Result`;
  anything an inspector can't resolve degrades gracefully (forensic inputs are partial).

## Key types (`models.rs`)

- `Method` — `Stored` or `Deflate`.
- `Location` — where a file's bytes live: `Zip { … }` (mmap offsets), `Loose { path }`
  (disk), or `Nested { archive, … }` (offsets into a folder source's in-memory arena).
- `Entry` — a located file: `name`, `uncompressed_size`, `mtime` (for diff), `location`.
- `SearchHit` — one match within an entry: `offset`, line-preview bytes, match range.
- `MatchRecord` — an archive-level match. `archive_offset` is `Option<u64>` — `None` for a
  loose/nested/DEFLATE/decrypted match. `MatchRecord::new` is the single home of the
  offset rule.
- `Inspection` / `ContentDiff` — `{ format, summary, detail }`: a human one-liner plus a
  structured JSON value, for `--inspect` and `diff --inspect` respectively.

## Testing

Tests live in `tests/` (integration) and inline `#[cfg(test)]` modules (unit), using the
library directly — the CLI is exercised manually, not by tests, so CLI changes don't churn
them. ZIP fixtures are **hand-built byte by byte** (`tests/common`) so they are
deterministic and need no external `zip` tool; binary-format inspectors and the SQLite diff
are tested against committed real fixtures (`tests/fixtures/`).

`cargo test` runs the full suite (lib unit + integration, ~110 tests);
`cargo clippy --all-targets` and `cargo fmt --all -- --check` are clean.
