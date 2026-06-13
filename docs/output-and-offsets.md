# Output formats, offsets, and the inspection schema

## Offsets

Every match carries the location, completely:

| Field | Meaning |
|---|---|
| `path` | File name and path inside the source. |
| `file_start` | Byte offset where the matching file's data begins in the archive (`0` for a loose file — it is its own data from byte 0). |
| `file_offset` | The match position **within the file's logical content**. |
| `archive_offset` | The match's **absolute** byte position in the archive, when one exists. |

For **STORED** entries `archive_offset == file_start + file_offset`, and it is
byte-accurate — you can seek to it directly:

```
dd if=acquisition.zip bs=1 skip=<archive_offset> count=16 2>/dev/null
```

`archive_offset` is **absent** (omitted in json, empty in csv) when there is no single
archive byte for the match:

- **DEFLATE** entries — the match exists only in the decompressed stream, so
  `file_offset` is the position in the **decompressed** data and the record is flagged
  **compressed** (`~` prefix in txt, `compressed: true` in json/csv);
- **loose files** in a `--dir-mode` folder source — there is no enclosing archive
  (`file_start` is `0`);
- files inside an **opened nested archive** (`--archive-depth`) — the bytes live in an
  in-memory blob, not the archive on disk;
- **decrypted** content — the offsets are within the plaintext, not the archive.

`file_offset` (the in-file position) is always meaningful and is what txt shows.

**Output rules:** at most one line per match, and binary file content is never
raw-dumped. The matched line is shown only when it looks **textual**; binary
files (SQLite, bplist, …) contribute location only. Per-format context is opt-in
via `--inspect`.

**Multiple archives:** when more than one archive is searched in a run, each
result is tagged with its source archive — a `archive:` prefix in txt, an
`archive` field in json, and the leading `archive` column in csv. With a single
archive there is no tag (json omits the field; the csv column is empty).

## txt

One line per match:

```
path:0x<file_offset>[:line][  [format  labelled summary]]
```

- The offset is **hex** (`0x…`) to match how analysts read a hex editor.
- `:line` (the matched line) appears only for **textual** files; binary files
  show just `path:0x<offset>`.
- `--colour` wraps the matched bytes in ANSI bold-red (terminal only).
- With `--inspect`, a labelled `  [format  key: value  …]` tag is appended.
- With `--base64`, a base64 hit appends `  [base64 → "decoded value"]` so the
  encoded run is flagged and the decoded value shown (see [base64 search](#base64-search--base64)).

Examples:

```
notes.txt:0x1a2:the meeting is at 5pm
notes.txt:0x1a2:the meeting is at 5pm  [txt  line: 12  col: 4]
sms.db:0x500000                          (binary: location only)
sms.db:0x500000  [sqlite  table: message  column: text  row: 4213  cell: hello there]
config.txt:0x13:...U3VwZXJTZWNyZXRUb2tlbg...  [base64 → "SuperSecretToken"]
```

> Note: the absolute `archive_offset` and `compressed` flag are not in txt (they
> are in json/csv). txt favours the in-file offset, which is what you seek to.

## json

A single pretty-printed object with three members: `run` (the query and every
filter in effect, so the file is self-describing), `stats` (the coverage tally —
see [scan statistics](#scan-statistics--the-report-sidecar)), and `results` (one
object per match). Offsets are `0x…` hex strings. `archive` is the source
archive's full path; `line` appears only for textual matches; `format`/`context`
only with `--inspect`; `encoding`/`decoded` only for base64 hits.

```json
{
  "run": {
    "tool": "mf-scan",
    "version": "0.1.0",
    "pattern": "hello",
    "literal": false,
    "ignore_case": false,
    "match_path": false,
    "inspect": true,
    "archives": ["/cases/acquisition.zip"],
    "path_globs": [],
    "not_path_globs": [],
    "types": ["sqlite"],
    "exclude_media": false,
    "base64": false,
    "base64_urlsafe": false
  },
  "stats": { "files_scanned": 1280, "files_skipped": 4096, "...": "..." },
  "results": [
    {
      "archive": "/cases/acquisition.zip",
      "path": "private/var/.../sms.db",
      "file_start": "0x1000",
      "file_offset": "0x500000",
      "archive_offset": "0x1000",
      "compressed": true,
      "format": "sqlite",
      "context": { "page": 1281, "table": "message", "rowid": 4213, "column": "text", "type": "TEXT", "cell": "hello there" }
    }
  ]
}
```

`context` is format-specific (see below). For binary formats the decoded value
lives in `context` (e.g. `cell`); for text formats the surrounding `line` is the
content. A base64 match adds `"encoding": "base64"` and `"decoded": "<value>"`;
plain matches omit both (the `encoding` key is absent).

## csv

A header row plus one row per match. Columns are fixed (so the set never varies):

```
archive,path,file_start,file_offset,archive_offset,compressed,encoding,decoded,format,context,line
```

Offsets are `0x…` hex strings. `archive` is the source archive's display label,
empty unless several archives were searched (the full path is in json's `run`);
`encoding` is always present (`plain` or `base64`) and `decoded` holds the
decoded value for base64 hits (empty otherwise); `format`/`context` are empty
unless `--inspect` matched; `line` is empty for binary files. `context` is the
human labelled one-liner (the same text as the txt tag). Run metadata (pattern,
filters) and the coverage stats are not in csv; use json for those.

## counts (`--count`)

One line per file (only files with at least one match):

```
sms.db:3
app.json:1
```

`--format json` emits `[{ "path": …, "count": N }]`; `--format csv` emits a
`path,count` table.

## Inspection `context` by format

| `format` | `context` (json) | summary (txt tag / csv) |
|---|---|---|
| `txt`    | `{ "line": N, "col": N }` | `line: N  col: N` |
| `json`   | `{ "path": "$.a.b[2]", "line": N }` | `key: $.a.b[2]  line: N` |
| `xml`    | `{ "path": "/a/b/c", "line": N }` | `path: /a/b/c  line: N` |
| `csv`    | `{ "row": N, "col": N, "header": "..." }` | `row: N  col: N  header: H` |
| `plist`  | `{ "path": "$.Account.Servers[1]", "line": N }` | `key: $.Account.Servers[1]  line: N` |
| `bplist` | `{ "path": "...", "object": N }` | `key: $.Account.Servers[1]` |
| `bplist` (NSKeyedArchiver) | `{ "path": "$.root.key", "archiver": "NSKeyedArchiver", "class": "NSDictionary" }` (`class` omitted when unresolvable) | `nskeyed key: $.root.key` |
| `sqlite` (in a row) | `{ "page": N, "table": "...", "rowid": N, "column": "...", "type": "TEXT", "cell": "..." }` | `table: T  column: C [TYPE]  row: R  cell: V` |
| `sqlite` (BLOB cell, recognised) | the above **plus** `"blob_format": "bplist"` and `"blob_context": { … }` | `… [BLOB]  cell: <blob N bytes>  blob: bplist  key: $.…` |
| `sqlite` (elsewhere) | `{ "page": N, "page_offset": N }` | `page: N  offset: N  (not in a table cell)` |

`cell` (and the txt `cell:` field) is the **decoded**, length-capped, text-safe
value — a TEXT/INTEGER/REAL value as text, a NULL as `NULL`, a BLOB as
`<blob N bytes>`. Raw bytes are never shown.

## base64 search (`--base64`)

Secrets, tokens, and identifiers are often stored **base64-encoded**, where a
plaintext search would miss them. `--base64` also searches for the pattern's
base64 form, tagging each hit with its encoding so an analyst can tell an encoded
hit from a literal one — and see the decoded value.

How it works: base64 packs **3 bytes into 4 characters**, so where the target
falls relative to those 3-byte groups (its offset **mod 3**) changes its
encoding. There are three such alignments; for each, the characters in the middle
of the encoded run depend only on the target and so are a literal that must
appear. `--base64` searches all three (≈3× the work), which finds the value at
any alignment. See `src/search/base64.rs` for the bit-level derivation.

Constraints and behaviour:

- **Requires `-l`** (a literal can be encoded; a regex has no byte form) and is
  **incompatible with `--match-path`** (a path is not base64).
- Searches **both** plaintext and base64 in one run; plain hits are unaffected.
- Standard alphabet (`+/`) by default; `--base64-urlsafe` uses the URL-safe one
  (`-_`). Base64 matching is always case-sensitive (the `-i` flag does not apply
  to it).
- Very short terms produce short fragments and may match unreliably; a warning is
  printed when that is likely.

A base64 hit's offset points at the **base64 text** in the file (the matched
`line` is the encoded run); the `decoded` field carries the value you searched
for. See the txt/json/csv sections above for how it is rendered.

## Scan statistics & the report sidecar

Every search records **coverage statistics** — what was scanned, what each filter
skipped, and why — so a run leaves a defensible record of what it did and did not
look at (important when `--fast` or a preset excludes whole subtrees).

- **stderr:** the active skip rules are printed *before* results; a summary
  (scanned/skipped counts, per-rule and per-type breakdowns, bytes scanned vs
  total, throughput) is printed at the end.
- **JSON output:** the `stats` object is embedded in the `{ run, stats, results }`
  report (see [json](#json)).
- **Sidecar file:** a `{ run, stats }` report is written for *every* run,
  regardless of output format. Its path is `--report <FILE>` if given, else
  `<output>.report.json` beside `-o`, else `mf-scan-report.json` in the current
  directory. `--no-report` suppresses it.

The `stats` object:

```json
{
  "total_entries": 5376,
  "directories": 410,
  "files_scanned": 1280,
  "files_skipped": 3686,
  "bytes_total": 8123456789,
  "bytes_scanned": 1203456789,
  "archive_bytes": 7000000000,
  "skipped_not_included": { "count": 0, "bytes": 0 },
  "skipped_media": { "count": 3201, "bytes": 6800000000 },
  "skipped_type": { "count": 0, "bytes": 0 },
  "skipped_not_path": [ { "glob": "*/Caches/*", "count": 485, "bytes": 120000000 } ],
  "scanned_by_type": { "sqlite": 412, "plist": 88, "txt": 780 },
  "files_with_matches": 37,
  "total_matches": 214,
  "elapsed": 3.42
}
```

- `bytes_*` are **uncompressed** (logical) sizes; `archive_bytes` is the on-disk
  archive size. `elapsed` is in seconds.
- Each skip is attributed to the rule responsible: the `--path` include filter,
  the media skip, the `--type` allowlist, or the specific `--not-path` glob.

## Manifest schema (`--manifest` / `export --from-manifest`)

```json
{
  "run": { "tool": "mf-scan", "pattern": "private_key", "archives": ["/cases/acquisition.zip"], "...": "..." },
  "total_size": 412300191,
  "file_count": 37,
  "files": [
    {
      "internal_path": "private/var/.../sms.db",
      "output_path": "sms.db_a3f2c1d0e5/sms.db",
      "size": 5242880,
      "compressed": false,
      "offsets": [5242880, 5300000]
    }
  ]
}
```

- `run` heads the manifest with the query, filters, and source archive paths, so
  it documents what produced the manifest. It is informational on re-ingestion: a
  manifest may be applied to a different archive (files absent there are skipped).
- `total_size` is the sum of `size` over all matched files — known *before* the
  export.
- `output_path` is the relative path the file will be written to under `--to`.
- `offsets` are the `file_offset`s of every match in that file.
- `export --from-manifest` reuses `output_path` and locates each file by
  `internal_path`; missing entries are reported as skipped.

## iOS app bundle-ID annotation

When searching an iOS acquisition, each match whose file path lies inside an iOS
app container is annotated with the owning app's **bundle ID** (e.g.
`com.apple.MobileSMS`, `com.whatsapp.WhatsApp`).

**How it works.** iOS stores a
`.com.apple.mobile_container_manager.metadata.plist` file in every container
directory (under `private/var/mobile/Containers/…`). On startup, mf-scan scans
the source once for these metadata plists, reads the `MCMMetadataIdentifier` key
from each, and builds a container-directory → bundle-ID map. Each match is then
resolved against this map by longest-prefix matching on `/`-segment boundaries,
so a file nested deep inside a container still resolves to the correct app.

The annotation appears as a `bundle_id` field in the json result object and as a
`[bundle: …]` suffix in the txt line (when the source has iOS containers). It is
entirely absent for non-iOS sources.

Missing or unreadable metadata plists are silently skipped — one absent annotation
does not prevent the rest of the scan from completing (degrade-don't-die).

## Export report (`export-report.json`)

Every export (`search --export DIR` or the `export` subcommand) writes
`DIR/export-report.json`: the `run` metadata plus one entry per written file —
its `internal_path`, `output_path` (relative to `DIR`), `size`, and `sha256`.
This records the integrity hash of each exported artefact (main files and
SQLite sidecars alike) beside the artefacts themselves.

```json
{
  "run": { "tool": "mf-scan", "...": "..." },
  "file_count": 2,
  "files": [
    {
      "internal_path": "private/var/.../sms.db",
      "output_path": "sms.db_a3f2c1d0e5/sms.db",
      "size": 5242880,
      "sha256": "2b8e1f9b…"
    }
  ]
}
```
