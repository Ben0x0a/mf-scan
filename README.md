# MobileForensic-Scan

Fast, forensic-aware **search, export, and diff** over mobile-acquisition archives
**and** folders — a `zipgrep` that also reads loose files and compares two
acquisitions, built for mobile-forensic images.

Mobile acquisitions are frequently delivered as large ZIP archives of a phone's
file system (or as extracted folders). Searching a ZIP with `zipgrep` is painfully
slow: it spawns a process per entry and copies every byte through pipes. mf-scan
memory-maps the archive and runs a SIMD regex engine straight over the bytes — and
because acquisition ZIPs usually store entries **uncompressed** (STORED), there is
nothing to decompress on the hot path. The same engine reads a folder of loose
files and (with `--archive-depth`) the archives nested inside it.

```
$ mf-scan grep 'IMSI' acquisition.zip
private/var/.../CellularUsage.db:0x1f4a:...IMSI 208...
```

- **~40–100× faster than `zipgrep`** on STORED archives (memory-mapped, no
  per-file process spawn, SIMD search).
- **Archives *and* folders** — point at a `.zip` or a directory; with
  `--archive-depth` mf-scan opens nested `.zip` files found inside a folder and
  searches the files within them.
- **Tells you *where*, always** — every match reports the file path plus byte
  offsets (see [Offsets](#offsets)).
- **STORED + DEFLATE**: uncompressed entries are searched in place; DEFLATE
  entries are decompressed on demand; loose files are read from disk.
- **Diff two sources** (`mf-scan diff`): which files were added / removed /
  modified between two archives or folders, and — with `--inspect` — *what changed
  inside* recognised formats (SQLite table row-counts, plist/JSON keys, text lines).
- **Deep inspection** (`--inspect`): for recognised formats, resolves a match to
  a meaningful location — a SQLite `table/column [TYPE]/rowid` (plus the embedded
  format when the cell is a BLOB), a JSON/plist key path (including NSKeyedArchiver
  logical paths), an XML element path, a CSV row/column, …
- **iOS app bundle-ID annotation**: matches inside iOS container directories are
  annotated with the owning app's bundle ID (e.g. `com.apple.MobileSMS`), read from
  the `.com.apple.mobile_container_manager.metadata.plist` files that iOS places in
  every container. Missing or unreadable metadata files are silently skipped.
- **Locate & export an app's data** (`mf-scan app`): given a bundle id / package,
  find **every** place an app's data lives — its own container, its
  extension/**widget** containers, and its shared **App Groups** — and export the
  lot, one tidy subfolder per container. Works on iOS full-file-system, iOS backups,
  and Android. App Groups are attributed **authoritatively** from the app binary's
  code-signature entitlements (with a vendor-token heuristic fallback). See
  [`app`](#app).
- **Filter by file type** (`--type`) and **by path** (`--path`/`--not-path`),
  recognised by content **header first**, then extension.
- **Find base64-encoded values** (`--base64`), **find files by path**
  (`--match-path`), **decrypt app databases** (`--keyfile`).
- **Transparent coverage**: every run logs what it skipped and why, prints a
  scanned/skipped summary, and writes a scan-report sidecar.
- **Export matched (or changed) files out** with a re-ingestable manifest and a
  size cap — `grep` and `diff` share one export pipeline.
- **Multi-threaded**, with a live progress hint on a terminal.

> Additional inspectors (ABX, SEGB) are planned for a future version; see
> [docs/inspectors.md](docs/inspectors.md).

---

## Install

Requires a Rust toolchain (2024 edition, e.g. Rust 1.95+).

```
cargo build --release
# binary at: target/release/mf-scan
```

---

## Quick start

```
# Find a string in an archive and show where it is (path:0x<offset-in-file>:line)
mf-scan grep 'secret' case.zip

# Search a folder of loose files; open nested zips one level deep
mf-scan grep 'secret' ./extracted --dir-mode --archive-depth 1

# Walk a directory tree and search every *.zip in it (one source per archive)
mf-scan grep 'secret' ./cases -r

# Restrict to certain files, and resolve matches inside them
mf-scan grep 'token' case.zip --path '*.sqlite' --path '*.plist' --inspect

# Machine-readable output to a file
mf-scan grep 'token' case.zip --format json -o hits.json

# Record matched files (with total size), review, then export them out
mf-scan grep 'token' case.zip --manifest hits.json
mf-scan export case.zip --from-manifest hits.json --to ./exported --max-size 500MB

# Diff two acquisitions: which files changed, and what changed inside them
mf-scan diff before.zip after.zip --exact --inspect

# List the installed apps in an acquisition (filter by name/id)
mf-scan app grep case.zip whatsapp

# Show every place one app's data lives (own data + widgets/extensions + groups)
mf-scan app paths case.zip com.whatsapp.WhatsApp

# Export all of an app's data out, one subfolder per container
mf-scan app export case.zip com.whatsapp.WhatsApp --to ./whatsapp_data
```

---

## Commands

mf-scan has four subcommands:

| Command | Purpose |
|---|---|
| `grep PATTERN SOURCE...` | Search one or more sources (archives and/or directories); print/record matches; optionally export files. |
| `export ARCHIVE --from-manifest FILE --to DIR` | Re-ingest a manifest (from `grep` or `diff`) and copy the listed files out (no search). |
| `diff A B` | Compare two sources (archives or folders): report added / removed / modified files, optionally what changed inside them, and optionally export the changed files. |
| `app {grep\|paths\|export}` | Locate and export an application's data (iOS FFS / iOS backup / Android) — by bundle id / package, including widgets/extensions and App Groups. |

### Sources, `--dir-mode`, and `-r`

A **file** operand is always opened as an archive. A **directory** operand needs one
of these two flags to say how to read it (there is no silent default — a directory
with neither is rejected; the two are mutually exclusive):

- `--dir-mode` — treat the directory as a **folder of interest**: scan the files
  inside it. A nested `.zip` is an opaque file at the default `--archive-depth 0`;
  raise the depth to open nested archives and list the files within them (`1` = one
  level, `N` = `N` levels of nesting).
- `-r`, `--recursive` — walk the directory tree and treat **every `*.zip`** found as
  its own archive source (each tagged by its path).

### `grep`

```
mf-scan grep PATTERN SOURCE... [options]
```

Grep-style: the **PATTERN comes first**, then the sources. `SOURCE` may be repeated.
With more than one source, each result is tagged with its origin (see
[Output](#output)). `--export`/`--manifest` require a single source.

| Flag | Meaning |
|---|---|
| `-i`, `--ignore-case` | Case-insensitive matching. |
| `-l`, `--literal-string` | Treat PATTERN as a literal string, not a regex (alias: `--fixed-strings`). |
| `-E`, `--extended-regexp` | Accepted for grep muscle memory; no-op (the engine is already ERE-like). |
| `--dir-mode` | Treat a directory operand as a folder of interest: scan its files. Mutually exclusive with `-r`. |
| `--archive-depth N` | Open nested `.zip` files (found while scanning a `--dir-mode` folder) up to `N` levels deep. Default `0` (nested zips are opaque). |
| `-r`, `--recursive` | Walk a directory operand for `*.zip` files, each its own source. |
| `--path GLOB` | Only handle files whose internal path matches the wildcard. Repeatable. |
| `--not-path GLOB` | Skip files matching the wildcard (takes precedence over `--path`). Repeatable. |
| `-t`, `--type TYPE` | Only handle files of a format (`sqlite`, `jpeg`, …) or category (`media`, `database`, `structured`, `text`). Header-first, then extension. Repeatable. |
| `--match-path` | Match the PATTERN against each file's internal path instead of its content. |
| `--base64` / `--base64-urlsafe` | Also search for the base64 encoding of the pattern (any alignment). Requires `-l`; not with `--match-path`. |
| `--exclude-media` | Skip image/video/audio files (searched by default). |
| `--fast` | Speed preset: exclude media + a customisable exclude list. |
| `--inspect` | Resolve matches inside recognised formats (see [Inspection](#deep-inspection)). |
| `-c`, `--count` | Print only the match count per file. |
| `-f`, `--format txt\|json\|csv` | Output format (default `txt`). |
| `-o`, `--output FILE` | Write results to a file instead of stdout. |
| `--colour[=auto\|always\|never]` | Highlight matches (txt to a terminal). `--color` also accepted. |
| `-j`, `--threads N` | Search threads (default: one per CPU core). |
| `--manifest FILE` / `--export DIR` | Write a re-ingestable manifest / also copy matched files out. `--export` writes `DIR/export-report.json` (run metadata + per-file integrity, see [Export integrity](#export-integrity)). |
| `--max-size SIZE` | Refuse to export if the matched total exceeds SIZE (e.g. `200MB`, `1G`). Default `1G`. |
| `--max-path-len N` | Path-length guard for the export (default `260`, Windows `MAX_PATH`). On Windows an over-limit path is skipped+recorded; elsewhere it is exported but flagged non-portable. `0` disables. See [`app`](#app). |
| `--verify` | SHA-256 the archive before and after the run; report whether it changed (archive sources only). |
| `--io-mode auto\|mmap\|ranged` | How to read an archive: `auto` (default) memory-maps a local archive but uses **positioned reads** for a remote SMB/NFS source; `ranged` forces positioned reads, `mmap` forces mapping. See [Remote / network sources](#remote--network-sources). |
| `--report FILE` / `--no-report` | Where to write / suppress the scan-report sidecar. Default: beside `-o`, else `mf-scan-report.json`. |
| `--keyfile FILE` | Decrypt profile-matched databases using keys from this keychain/keystore dump (repeatable). See [Decryption](#decryption). |
| `--platform ios\|android` | Limit decryption profiles to one platform. |
| `--no-decrypt` | Disable decryption entirely (on by default when a keyfile dump is found beside the source). |
| `--backup-password PASSWORD` | Password to unlock an **encrypted iOS backup** (or set `MFSCAN_BACKUP_PASSWORD`). See [iOS backups](#ios-backups). |

### `export`

```
mf-scan export ARCHIVE --from-manifest FILE --to DIR [--max-size SIZE] [--max-path-len N]
```

Re-ingests a manifest written by `grep --manifest` (or `diff --manifest`) and copies
the listed files out of the archive — **without searching again**. Honours
`--max-size` and the `--max-path-len` guard (see [`app`](#app)).

> **Vocabulary:** *export* = copy files out; *extract* is reserved for extracting
> *meaning* (the `--inspect` analysis).

### `diff`

```
mf-scan diff A B [options]
```

Compares two sources file-by-file (paired by internal path) and reports each file as
**added** (only in B), **removed** (only in A), **modified**, or unchanged. Each side
may be an archive or a `--dir-mode` directory.

| Flag | Meaning |
|---|---|
| `--exact` | Compare file **content** with SHA-256 instead of the default mtime+size check (catches edits that preserve the timestamp). |
| `--inspect` | For a modified file of a recognised format, also report **what changed inside** it (SQLite table row-counts, plist/JSON key paths, text line counts). |
| `--path` / `--not-path` | Restrict which files are compared. |
| `--manifest FILE` / `--export DIR` | Write a manifest of / export the added+modified files from side B, through the same pipeline as `grep` — so `mf-scan export` can re-ingest a diff. |
| `--archive-depth N` / `--dir-mode` | As for `grep`, applied to each side. |
| `-f`, `--format` / `-o`, `--output` | Output format / sink. |

By default `diff` uses **mtime + size** (fast); add `--exact` when a content-preserving
timestamp could hide a change. See [docs/diff.md](docs/diff.md) for the full report
schema and the comparison rules.

### `app`

Locate and export an application's data, by bundle id (iOS) or package name
(Android). mf-scan auto-detects the acquisition layout — iOS full-file-system, iOS
backup, or Android — and resolves an app to **all** of its containers: its own data,
its extension/**widget** containers, and its shared **App Groups**.

```
mf-scan app grep   SOURCE [PATTERN] [options]     # search the installed-app inventory
mf-scan app paths  SOURCE BUNDLE_ID [options]     # list every data location of one app
mf-scan app export SOURCE BUNDLE_ID --to DIR [options]   # copy one app's data out
```

> The **SOURCE comes first** in every `app` verb (the optional `PATTERN` on `grep`
> forces it). Open a directory source with `--dir-mode`; unlock an encrypted iOS
> backup with `--backup-password` (or `MFSCAN_BACKUP_PASSWORD`).

| Verb | What it does |
|---|---|
| `grep` | Lists one line per installed app: bundle id, display name, container count, total size. An optional `PATTERN` filters by a substring of the id/name. |
| `paths` | Lists every container the app or its dependencies can write to, tagged by kind (`AppData` / `Extension` / `AppGroup` / `Bundle`, or the Android storage root) and — for groups — by how it was attributed (`Entitlement` vs `VendorHeuristic`). |
| `export` | Copies all of the app's data out, **one subfolder per container** with the on-device tree preserved (`<id>/<Kind>_<guid>/…`, groups under their own id, a backup under its domain), and writes `export-report.json` with per-file integrity. Excludes the `.app` bundle (binary, not data). |

Common `app` flags: `--dir-mode`, `--archive-depth N`, `--io-mode`,
`--backup-password`, `-f/--format txt|json`, `-o/--output FILE`; for `paths`/`export`
also `--no-groups`; for `export` also `--to DIR`, `--max-size SIZE`,
`--max-path-len N`, `--verify`.

**App Group attribution.** An app's App Groups are read **authoritatively** from the
app binary's code-signature entitlements (`com.apple.security.application-groups`) —
so a cross-brand shared group (e.g. `group.com.facebook.family` used by Instagram) is
found even though its name shares no token with the app. When the binary can't be
read (always for a backup, which ships no executable), mf-scan falls back to a
reverse-DNS **vendor-token heuristic** and tags every such inclusion
`VendorHeuristic` in the output and report so it can be audited. Use `--no-groups` to
exclude shared containers entirely.

**Path-length guard (`--max-path-len`, default 260).** Deep on-device trees can
produce paths longer than Windows' `MAX_PATH`. On Windows an over-limit path cannot
be written, so the file is **skipped and recorded** (`skipped_too_long` in the
report). On macOS/Linux the file **is** exported, but if its path is too long to
survive a move to Windows it is flagged as a **portability warning**
(`portability_warnings`). `--max-path-len 0` disables the guard. The same flag
applies to `grep`/`diff` `--export` and to the `export` subcommand.

---

## Output

One line per match; binary file content is **never** raw-dumped. Default txt:

```
path:0x<file_offset>[:line]
```

The offset is hex (like a hex editor). The matched `line` is shown only for
**textual** files; binary files (SQLite, bplist, …) show just `path:0x<offset>`.
`--inspect` appends a labelled tag; `--count` prints `path:count` per file. For a
folder source, the path reads like `backup.zip/messages.db` once nested archives are
opened.

`json` emits a `{ run, stats, results }` object; `csv` emits a header row plus one row
per match. Offsets are `0x…` hex in every format. See
[docs/output-and-offsets.md](docs/output-and-offsets.md) for the full schema.

### Offsets

Every match answers "where":

| Field | Meaning |
|---|---|
| `path` | File name and path inside the source. |
| `file_start` | Where the matching file's data begins in the archive (`0` for a loose file). |
| `file_offset` | The match position **inside the file**. |
| `archive_offset` | The match's **absolute** byte position in the archive (`= file_start + file_offset` for STORED). |

`archive_offset` is **omitted** (json/csv) when there is no single archive byte: a
**loose file** in a folder, a file inside an **opened nested archive**, a **DEFLATE**
entry (compressed blob start, flagged `compressed: true`), or **decrypted** content.
txt shows only the in-file offset.

---

## Deep inspection (`--inspect`)

When a matching file's format is recognised (by content header first, file extension
as fallback), mf-scan resolves the match to a meaningful location: `[format summary]`
in txt, a nested `context` object in json.

| Format | Resolves a match to |
|---|---|
| TXT | line and column |
| JSON | key path + line, e.g. `$.users[3].token` |
| XML | element path + line |
| CSV | row, column, and header name |
| plist (XML & binary `bplist`) | dict-key / array-index path, e.g. `$.Account.Servers[1]` |
| plist (NSKeyedArchiver `bplist`) | logical path through the `$objects`/UID graph, e.g. `$.root.prefs.token`; resolves wrapped scalars (NSMutableString, NSData), array indices, and dict key-name hits; reports the Foundation class of the containing object |
| SQLite | `table`, `column [TYPE]`, `row`, and the decoded cell value; else `page` + offset |

The same inspectors power `diff --inspect`'s intra-file comparison. See
[docs/inspectors.md](docs/inspectors.md).

---

## Decryption

Encrypted app databases inside an acquisition can be decrypted using keys from a
keychain/keystore dump, then searched and `--inspect`ed as plaintext. By default, when
a `keychain`-named dump is found **beside the source** (e.g. `case.zip` next to
`keychain.plist`), profile-matched databases are decrypted automatically; or point at
one with `--keyfile FILE` (iOS keychain or Android keystore). Use `--no-decrypt` to
turn it off.

```bash
mf-scan grep "needle" case.zip                          # auto-detect keyfile beside it
mf-scan grep "token" case.zip --keyfile keychain.plist --platform ios
```

Per-app **profiles** (`profiles/{ios,android}/*.yml`) say which database to decrypt,
how to find its key, and the cipher. Supported ciphers: **SQLCipher** (Signal, Wickr,
…) and **WhatsApp crypt12/14**. Every decryption is recorded in the scan report with
the key's provenance and the SHA-256 of the ciphertext and plaintext.

> **Scope:** only works on acquisitions whose keychain was *already decrypted* by the
> acquisition tool (a raw `keychain-2.db` cannot be decrypted offline).
>
> **⚠ Validation:** the ciphers are assembled from documented formats and
> round-trip-tested, but **not yet validated against real `sqlcipher`/WhatsApp
> output** — see [docs/decryption.md](docs/decryption.md) before relying on a
> decryption forensically.

---

## iOS backups

An **iTunes/Finder backup** (a folder, or a `.zip` of one, containing `Manifest.plist`
+ `Manifest.db`) is recognised automatically and presented at each file's **logical
`domain/relativePath`** instead of its opaque `fileID` — so matches read like
`HomeDomain/Library/SMS/sms.db` and exports keep the real filename. Encrypted and
unencrypted backups are both handled.

```bash
# Unencrypted backup — nothing extra needed
mf-scan grep "icloud" /path/to/00008120-… --dir-mode

# Encrypted backup — supply the password (or set MFSCAN_BACKUP_PASSWORD)
mf-scan grep "token" /path/to/00008030-… --dir-mode --backup-password 'hunter2'
export MFSCAN_BACKUP_PASSWORD='hunter2'   # keeps it out of shell history / ps
mf-scan grep "token" backup.zip
```

Work is **lazy**: only files that survive the `--path`/`--type`/media filters are ever
read (and, for an encrypted backup, decrypted), so a targeted search over a backup
where *every* file is individually encrypted stays fast. The provenance (encrypted vs
not, how the password resolved, how many files were mapped) is recorded in the scan
report and printed on stderr.

For an **encrypted** backup the crypto layer recovers the per-class keys from the
`Manifest.plist` keybag via the backup-password KDF (single or iOS 10.2+ double
PBKDF2), unwraps each file's key (RFC 3394), and AES-256-CBC-decrypts it. Both flavours
are **validated end-to-end against real backups**: every file's on-disk blob is checked
against the SHA-1 `Digest` in `Manifest.db` on export — the SHA-1 of the *ciphertext*
for an encrypted backup, of the *file content* for an unencrypted one (see
[Export integrity](#export-integrity)).

---

## Export integrity

`--export` writes `DIR/export-report.json` with an `integrity` summary and, per file,
**two independent SHA-256 hashes** plus any source-recorded digest check:

| Field | Meaning |
|---|---|
| `source_sha256` | SHA-256 of the bytes read **out of the source**. |
| `sha256` | SHA-256 of the bytes **read back from the written file** on disk. |
| `copy_verified` | `true` when the two match — catches a **silent copy error** (a bad/truncated write). |
| `stored_integrity` | The source's own digest check, when it records one (see below): `verified`, `mismatch`, or `unrecorded`. |

The `stored_integrity` check attests the **original evidence** independently of anything
mf-scan computed:

- **ZIP entry** → the **CRC-32** the archive's central directory records for the
  (uncompressed) data, recomputed from the bytes on disk — STORED and DEFLATE alike.
- **iOS backup** → the **SHA-1** recorded in `Manifest.db`, recomputed from the on-disk
  blob: the ciphertext for an encrypted backup (attesting it was read intact *before*
  decryption), the file content for an unencrypted one. Files with no recorded `Digest`
  report `unrecorded`.

Any failure (a copy mismatch, or a stored-digest mismatch indicating corrupt original
evidence) is written to the report **and** printed loudly on stderr, one line per
offending file.

---

## Remote / network sources

A full-file-system acquisition on an SMB/NFS share can be ~1 TB. Memory-mapping it
would turn each search into a storm of single-page faults pulled over the network, so
mf-scan reads a remote archive with **positioned reads** instead:

- **Listing is cheap** — only the archive tail (the End-Of-Central-Directory record and
  the central directory) is read; entry data offsets are resolved lazily, per file, so
  listing never touches every header.
- **Only what you search is fetched** — each searched entry's byte range is read on
  demand (in 256 MiB chunks for the rare huge file). Combined with **header-first
  classification**, a file excluded by `--type`/`--exclude-media`/`--fast` is skipped
  after a small header read, never fetched whole — so a targeted search over a remote
  FFS pulls only the files it needs.

```bash
# Auto-detected: a source on a network mount uses positioned reads automatically.
mf-scan grep "imessage" /Volumes/share/EXTRACTION_FFS.zip --type sqlite

# Force it either way:
mf-scan grep "needle" big.zip --io-mode ranged   # positioned reads
mf-scan grep "needle" big.zip --io-mode mmap      # memory-map
```

`--io-mode auto` (the default) detects an SMB/NFS/WebDAV mount via `statfs`; pass
`--io-mode ranged` to force it (e.g. for a mount it can't classify). Scoping with
`--path` is the cheapest remote filter — non-matching files are skipped before any
byte is read. Ranged mode reports in-file match offsets but no absolute archive offset
(the data offset is not resolved at listing time), consistent with the other
no-single-archive-byte cases; CRC-32 export integrity still applies.

> **Note:** the ranged path is validated locally (parity with the mmap source,
> including ZIP64) but has **not yet been profiled against a real ~1 TB SMB share** —
> see the roadmap before relying on its performance at that scale.

---

## Documentation

- [docs/architecture.md](docs/architecture.md) — modules, data flow, design decisions.
- [docs/workflow.md](docs/workflow.md) — forensic workflows end to end.
- [docs/diff.md](docs/diff.md) — the `diff` command: comparison rules, report schema, intra-file diff.
- [docs/output-and-offsets.md](docs/output-and-offsets.md) — output formats, offsets, inspection schema.
- [docs/inspectors.md](docs/inspectors.md) — supported formats, detection, adding one.
- [docs/decryption.md](docs/decryption.md) — decrypting databases: architecture, formats, profiles, caveats.
- [docs/adr/](docs/adr/) — architecture decision records (decryption; the source/container abstraction).
- [benchmark/README.md](benchmark/README.md) — I/O-mode benchmark (`mmap` vs `ranged`) and performance findings.
- Contributing: see [Local checks](docs/architecture.md#local-checks-run-before-pushing-a-tag) and [Releasing](docs/architecture.md#releasing) in the architecture doc — run `./scripts/check.sh` before pushing a tag.

---

## Forensic notes

- The archive is opened **read-only** — memory-mapped locally, or read with positioned
  reads for a remote source (see [Remote / network sources](#remote--network-sources));
  mf-scan never writes to it. Loose files are read read-only. `--verify` adds a SHA-256
  attestation (mmap archive sources only); the hash matches the system `shasum -a 256`.
- Offsets are **byte-accurate** for STORED entries (verifiable with `dd`/a hex editor).
- On `--export`, every copied file is **hashed at the source and re-hashed off disk** and
  the two are compared (silent-copy-error check); ZIP entries are additionally checked
  against their central-directory CRC-32 and encrypted-backup files against their
  `Manifest.db` SHA-1. See [Export integrity](#export-integrity).
- Search is case-sensitive unless `-i`; `--path`/`--not-path` matching is case-sensitive.
- **All files are searched by default**, including media — completeness is the forensic
  default, so nothing is silently skipped. `--exclude-media` (or `--fast`) skips
  image/video/audio for speed when text content is the only target.

---

## Development & AI use

Generative AI was used in this project mainly to assist during the coding phase. The
original ideas and the overall structure are the owner's, and all core logic has been
reviewed. Even so, mistakes or bugs may have slipped past proof-reading — please report
anything unexpected.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
