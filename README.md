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

A Cellebrite `.ufdr` report is read as the zip it is (`-r` picks it up too). Its files keep the names the
report gives them (`files/Database/…`), not device paths, and the databases Cellebrite
decrypted are already there as `*.decrypted`, plain SQLite. A key dump inside it
(`files/Configuration/<udid>_keychain.plist`) is found and used like one beside it.

```
$ mf-scan grep 'IMSI' acquisition.zip
private/var/.../CellularUsage.db:0x1f4a:...IMSI 208...
```

- **~40–100× faster than `zipgrep`** on STORED archives (memory-mapped, no
  per-file process spawn, SIMD search).
- **Archives *and* folders** — point at a `.zip`, a `.tar`/`.tar.gz`/`.tgz`, or a
  directory; with `--archive-depth` mf-scan opens nested `.zip` files found inside a
  folder and searches the files within them. (A plain `.tar` is memory-mapped and
  reports true archive offsets; a `.tar.gz` is decompressed in memory.)
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
  and Android. App Groups are attributed **authoritatively** from the entitlements
  MobileContainerManager recorded for the app (with a vendor-token heuristic
  fallback where those are unavailable, such as on a backup). See [`app`](#app).
- **Rebuild a backup into one `.zip`** (`mf-scan backup rebuild`): turn an iOS
  iTunes/Finder backup or an Android `adb backup` (`.ab`) back into the device's
  directory tree (`HomeDomain/Library/SMS/sms.db` →
  `private/var/mobile/Library/SMS/sms.db`), decrypting on the way when the password is
  known. The output is always a ZIP, so long device paths work on Windows, and it keeps
  the device's timestamps. Paths that had to be invented and domains with no known mount
  point are reported, never disguised. See [`backup`](docs/backup.md).
- **List files like `find`** (`mf-scan find`): by name, path, size, date and detected
  type, with `find`'s own spellings accepted. See [`find`](#find).
- **Filter by file type** (`--type`) and **by path** (`--path`/`--not-path`),
  recognised by content **header first**, then extension.
- **Find a term in every encoding at once** (`--all-encodings`: UTF-8, UTF-16, JSON
  escapes, URL encoding, Java's CESU-8, both Unicode forms, base64), **decrypt app databases** (`--keyfile`,
  or a dump found beside the source). `--export` writes each decrypted database beside
  its original in the export zip, and `mf-scan decrypt --to OUT.zip` writes the whole acquisition with
  the decrypted copies added. See [Decryption](#decryption).
- **Transparent coverage**: every run logs what it skipped and why, prints a
  scanned/skipped summary, and writes a scan-report sidecar.
- **Export matched (or changed) files out** with a re-ingestable manifest and a
  size cap — `grep` and `diff` share one export pipeline.
- **Multi-threaded**, with a live progress hint on a terminal.

> SEGB (Biome), Realm, ABX, typedstream (iMessage text), MMKV, keva (single values),
> LevelDB (logs and tables) and unified-log `uuidtext` are inspected; KTX snapshots, `.tracev3` and about 25 other
> formats are identified by their header. See [docs/inspectors.md](docs/inspectors.md).

---

## Install

Requires a Rust toolchain, Rust 1.98 or newer.

```
cargo build --release
# binary at: target/release/mf-scan
```

On Windows, build with the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`,
with the Visual Studio C++ Build Tools): the GNU one fails with "dlltool not found" unless
MinGW-w64's binutils are installed. Ready-made binaries are on the Releases page.

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
mf-scan grep 'token' case.zip --format json --output hits.json

# Record matched files (with total size), review, then export them out
mf-scan grep 'token' case.zip --manifest hits.json
mf-scan export case.zip --from-manifest hits.json --to ./exported --max-size 500MB

# Diff two acquisitions: which files changed, and what changed inside them
mf-scan diff before.zip after.zip --exact --inspect

# List the installed apps in an acquisition (filter by name/id)
mf-scan app list whatsapp case.zip

# Show every place one app's data lives (own data + widgets/extensions + groups)
mf-scan app paths com.whatsapp.WhatsApp case.zip

# Export all of an app's data out, one subfolder per container
mf-scan app export com.whatsapp.WhatsApp case.zip --to ./whatsapp_data

# Find a name in file contents AND file paths, in one pass
mf-scan grep --and-paths -i 'banking' case.zip

# List files by name and size, as with find
mf-scan find case.zip -name '*.db' -size +1M

# Rebuild an iOS or Android backup into one .zip of the device's tree
mf-scan backup rebuild phone.ab --to device.zip
```

---

## Commands

mf-scan has six subcommands. Each one's `-h` lists every option on one line and ends
with worked examples:

| Command | Purpose |
|---|---|
| `grep PATTERN [SOURCE]...` | Search archives, files, folders, backups or standard input; print/record matches; optionally export files. |
| `find SOURCE... [tests]` | List files by name, path, size, date and type; optionally export them. |
| `export ARCHIVE --from-manifest FILE --to DIR` | Re-ingest a manifest (from `grep`, `find` or `diff`) and export the listed files into a zip in `DIR` (no search). |
| `diff A B` | Compare two sources (archives or folders): report added / removed / modified files, optionally what changed inside them, and optionally export the changed files. |
| `app {grep\|paths\|export}` | Locate and export an application's data (iOS FFS / iOS backup / Android) — by bundle id / package, including widgets/extensions and App Groups. |
| `backup {info\|rebuild}` | Inspect an iOS or Android backup, or rebuild it into one `.zip` of the device's directory tree. |
| `decrypt SOURCE [--to OUT.zip]` | Decrypt app databases with a keychain/keystore dump; list them, or write the source plus each decrypted copy beside its original as one `.zip`. |

### Coming from grep

Most habits carry over. These are the differences:

| In grep | In `mf-scan grep` |
|---|---|
| `-r` reads every file under a directory | `-r` searches the **archives** under it and reports how many loose files it skipped. `--dir-mode` reads a directory's files. |
| `path:text` | `path:0x<byte offset>:text`, because the byte offset is what locates evidence. |
| `-n` gives `path:line:text` | `-n` gives `path:line:0x<byte offset>:text`. |
| `-o` prints only the match | `-o` also keeps the location: `path:0x<byte offset>:match`. |
| `-c` counts matching lines | `-c` counts matches, and lists only files with a match. |
| `hel\+o` (basic regex) | `hel+o`: the syntax is always extended, and `-E` is accepted but has no effect. |
| `-f FILE` reads patterns from a file | `-f` is `--format`. |

`-i`, `-F`, `-l`, `-w`, `-e`, `-q` and `^`/`$` at each line work as in grep, and with no
source, or `-`, it reads standard input. `\A` and `\z` anchor to the start and end of the
whole file. `-q` runs the whole search rather than stopping at the first match. `-v` and
`-A`/`-B`/`-C` are not available.

**Exit status:** `0` a match was found, `1` no match, `2` an error, or some files could
not be read or decrypted (with `-q`, a match still gives `0`, as in grep). `find` exits
`0` with or without results, as `find` does. `diff`, `app`, `export` and `backup` exit `0`
on success. All exit `2` on error.

**Results go to stdout; everything else goes to stderr**, so pipes stay clean. Add
`--no-stats` to skip the coverage summary and `--no-report` to skip the report file.

### Sources, `--dir-mode`, and `-r`

A **file** operand is identified by its content, then its name: a ZIP, a tar, or an
Android backup is opened as one, and anything else is searched as one file. A damaged
file named `.zip` or `.tar` fails rather than being searched as an opaque blob.

A **directory** operand needs one of these two flags to say how to read it (there is no
silent default — a directory with neither is rejected; the two are mutually exclusive):

- `--dir-mode` — treat the directory as a **folder of interest**: scan the files
  inside it. A nested `.zip` is an opaque file at the default `--archive-depth 0`;
  raise the depth to open nested archives and list the files within them (`1` = one
  level, `N` = `N` levels of nesting).
- `-r`, `--recursive` — walk the directory tree and treat **every archive** found
  (`.zip`, `.tar`, `.tar.gz`, `.tgz`, `.ab`) as its own source, tagged by its path. Loose
  files are not searched; how many were skipped is reported on stderr and in the scan
  report.

### `grep`

```
mf-scan grep [options] PATTERN [SOURCE]...
mf-scan grep [options] -e PATTERN... [SOURCE]...
```

Grep-style: the **PATTERN comes first**, then the sources. `SOURCE` may be repeated.
With more than one source, each result is tagged with its origin (see
[Output](#output)). `--export`/`--manifest` require a single source.

| Flag | Meaning |
|---|---|
| `-e`, `--regexp PATTERN` | Search for this pattern too. Repeatable; each keeps its own inline flags. |
| `-i`, `--ignore-case` | Case-insensitive matching. |
| `-F`, `--fixed-strings` | Treat patterns as literal strings, not regexes (alias: `--literal-string`). |
| `-w`, `--word-regexp` | Match whole words only: the characters either side of a match must not be word characters. Works around punctuation (`-w -F '+33'`). |
| `-l`, `--files-with-matches` | List only the files with a match, one per line. Can be combined with `--export`/`--manifest`. |
| `-o`, `--only-matching` | Show only the matched text (`path:0x<offset>:<match>`), including readable matches inside binary files, up to the 200-byte preview limit. Text output only. |
| `-n`, `--line-number` | Show each match's 1-based line number before its offset. Also in JSON, and as the last CSV column. |
| `-q`, `--quiet` | Print nothing and write no report (unless `--report` names one); the exit status is the answer. Files that could not be searched are still reported. |
| `-E`, `--extended-regexp` | Accepted for grep muscle memory; no-op (the engine is already ERE-like). |
| `--dir-mode` | Treat a directory operand as a folder of interest: scan its files. Mutually exclusive with `-r`. |
| `--archive-depth N` | Open nested `.zip` files (found while scanning a `--dir-mode` folder) up to `N` levels deep. Default `0` (nested zips are opaque). |
| `-r`, `--recursive` | Walk a directory operand for archives (`.zip`, `.tar`, `.tar.gz`, `.tgz`, `.ab`), each its own source. Skipped loose files are counted and reported. |
| `--path GLOB` | Only handle files whose whole internal path matches the wildcard: `*` any run of characters, `/` included; `?` one byte; case-sensitive. Repeatable. |
| `--app ID` | Only this app's data: its data container, extensions and widgets, bundle and App Groups (as `app paths` lists them), on an iOS file system, an iOS backup or Android. App Groups come from the entitlements of the app and its extensions where the iOS file system records them, else by name (a guess, named in the output). On Android: every user (`/data/user/<n>`) and every mount alias a capture holds (`/data_mirror`, `/mnt/…`), also below an extraction folder (`Dump/`). What each id resolved to is printed; an id with no data is reported and adds nothing. Apple apps also keep data outside their containers (Messages in `Library/SMS`): use `--path` for it. Repeatable; combines with `--path`. |
| `--not-path GLOB` | Skip files matching the wildcard (takes precedence over `--path`). Repeatable. |
| `-t`, `--type TYPE` | Only handle files of a format (`sqlite`, `jpeg`, …) or category (`media`, `database`, `structured`, `text`). Header-first, then extension. Repeatable. |
| `--match-path` | Match the PATTERN against each file's internal path instead of its content. |
| `--and-paths` | Match the PATTERN against contents **and** paths in one pass (grep + find). A path hit prints as the bare path (JSON/CSV: `path_match: true`); a file can have both. |
| `--encoding <ENC>` | Also search the literal in another encoding (repeatable): `utf16le`, `utf16be`, `utf16` (both), `json` (`\u00e9`, `\ud83d\ude02`), `url` (`%C3%A9`, space as `+`), `cesu8` (Java's modified UTF-8: an emoji as two surrogates), `nfd` (the other Unicode normal form: `é` as one character or `e` + accent), `base64`, `base64url` (any alignment), or `all`. An encoding whose form of the literal is its plain form is skipped. Requires `-F`; not with `--match-path` or `-w`. `-i` covers every encoding but base64. |
| `--all-encodings` | Shorthand for `--encoding all`: every encoding above in one pass. |
| `--exclude-media` | Skip image/video/audio files (searched by default). |
| `--fast` | Speed preset: exclude media + a customisable exclude list. |
| `--inspect` | Resolve matches inside recognised formats (see [Inspection](#deep-inspection)). |
| `-c`, `--count` | Print only the match count per file. |
| `--long` | With `-l` or `-c`: each file also shows its type, size and modified time (UTC), like `ls -l` and `find --long` (`f  8196096  2025-12-22T15:43:39Z  path`). In JSON/CSV it adds `size` and `modified_utc`. |
| `-f`, `--format txt\|json\|csv` | Output format (default `txt`). |
| `--output FILE` | Write results to a file instead of stdout. |
| `--colour[=auto\|always\|never]` | Highlight matches (txt to a terminal). `--color` also accepted. |
| `-j`, `--threads N` | Search threads (default: one per CPU core). |
| `--manifest FILE` / `--export DIR` | Write a re-ingestable manifest (a new file: an existing one is never replaced) / also export the matched files as **one zip** in `DIR`: `mf-scan-<UTC time>-export-<pattern>.zip`, read-only, with `export-report.json` inside (run metadata + per-file integrity) and a `.sha256` sidecar beside it. See [Export integrity](#export-integrity). |
| `--max-size SIZE` | Refuse to export if the matched total exceeds SIZE (e.g. `200MB`, `1G`). Default `1G`. |
| `--verify` | SHA-256 the archive before and after the run; report whether it changed (archive sources only). |
| `--io-mode auto\|mmap\|ranged` | How to read an archive: `auto` (default) memory-maps a local archive but uses **positioned reads** for a remote SMB/NFS source; `ranged` forces positioned reads, `mmap` forces mapping. See [Remote / network sources](#remote--network-sources). |
| `--report FILE` / `--no-report` | Where to write / suppress the scan-report sidecar. Default: a new timestamped file on every run, beside `--output`, else `mf-scan-report-<UTC time>.json` in the current directory. |
| `--no-stats` | Skip the end-of-run coverage summary. Files that could not be searched are still reported. |
| `--keyfile FILE` | Decrypt profile-matched databases using keys from this keychain/keystore dump (repeatable). See [Decryption](#decryption). |
| `--platform ios\|android` | Limit decryption profiles to one platform. |
| `--no-decrypt` | Disable decryption entirely (on by default when a keyfile dump is found beside the source). |
| `--backup-password PASSWORD` | Password to unlock an **encrypted iOS or Android backup** (or set `MFSCAN_BACKUP_PASSWORD`). See [iOS backups](#ios-backups). |

**Encoded matches.** Each match is one byte span in one encoding, so searching
several encodings never duplicates a match: a match that is not plain UTF-8 is
tagged with its encoding and decoded text (`[utf16be → "😂"]`, `"encoding"` in
JSON/CSV). `-l` still lists each file once; `-c` adds the count per encoding
(`ids.db:4  [utf16be 4]`); an export copies each file once, its manifest entry
giving the count per encoding. Why it matters: binary plists store non-ASCII text
as UTF-16, so on one test iPhone an emoji was in 174 files as UTF-8 and in 182 as
UTF-16. Measured on test devices, the other encodings each hold what UTF-8 misses: a
decomposed `é` in about 300 files per phone, an emoji as CESU-8 in 16 Android files,
JSON-escaped in 13 iPhone files, percent-encoded in 6.

Two rules keep these honest. A base64 match counts only when the base64 around it
decodes to the term (a fragment of the encoding alone proves nothing); under 4 bytes,
chance base64 text decodes to a term too, so `--all-encodings` leaves base64 out (with
a note), as it does for several patterns. And Latin-range text in UTF-16, surrounded by
the same, reads as little- and big-endian one byte apart: the byte order cannot be
told from the text, so it is one match tagged `utf16`.

### `find`

```
mf-scan find SOURCE... [tests] [options]
```

Lists a source's files and directories without reading their contents, as the `find`
command lists a directory. A folder needs no flag: walking it is what `find` does. `find`'s
own spellings work as typed (`-name`, `-iname`, `-path`, `-ipath`, `-regex`, `-iregex`,
`-type`, `-size`, `-newermt`, `-maxdepth`, `! -name`, `! -path`, `-ls`, `-print`).

```
mf-scan find case.zip -name '*.db'
mf-scan find case.zip --iname 'sms*' --type f --long
mf-scan find case.zip --type sqlite --size +1M --not-path '*/Caches/*'
mf-scan find ./extracted --newer 2026-01-01 --older 2026-02-01
mf-scan find case.zip --app com.whatsapp --export ./out --max-size 5G
```

| Test | Meaning |
|---|---|
| `--name GLOB` / `--iname GLOB` | The file name matches this wildcard (`*`, `?`); `i` ignores case. |
| `--path GLOB` / `--ipath GLOB` | The whole path matches, where `*` also crosses `/`. |
| `--app ID` | Only this app's containers, as for `grep`. |
| `--regex RE` / `--iregex RE` | The whole path matches this regex, anchored at both ends as in `find`. |
| `--not-name GLOB` / `--not-path GLOB` | The file name or path does not match. |
| `--type TYPE` | `f`, `d`, or a detected format or category (`sqlite`, `media`, ...). Only a format reads a file, and then only its header. |
| `--size SIZE` | `+10M` over, `-1k` under, `4096` exactly. `k`, `M`, `G` are 1024-based; a bare number is **bytes**, not `find`'s 512-byte blocks. |
| `--newer DATE` / `--older DATE` | Modified after or before this UTC time: `2026-01-31` or `2026-01-31T12:00`. |
| `--maxdepth N` | Descend at most N levels; top-level names are level 1. |

Different tests must all hold. Repeating a test means either, since there is no `-o`.

A ZIP's ordinary timestamp has no time zone, so date tests read it as UTC; an archive with
extended timestamps, such as one `backup rebuild` wrote, is exact. Entries with no recorded
time are excluded by a date test, and how many is reported. Directories are listed whether
the source records them or they are only implied by their files' paths, which have no time.

`--long` prints type, size, modified time and path, tab-separated. `-f json` and `-f csv`
give the same fields. `--export` and `--manifest` work as for `grep`, on files only. There
is no summary and no scan report. It exits `0` with or without results, as `find` does, and
`2` on error, including when a file could not be read to test `--type`.

### `export`

```
mf-scan export ARCHIVE --from-manifest FILE --to DIR [--max-size SIZE]
```

Re-ingests a manifest written by `grep`, `find` or `diff --manifest` and exports
the listed files into a zip in `DIR`, named after the manifest — **without searching
again**. Honours `--max-size`.

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
| `--app ID` | Compare only the app's containers, on either side (a reinstall shows its old files removed and its new ones added). |
| `--manifest FILE` / `--export DIR` | Write a manifest of / export the added+modified files from side B, through the same pipeline as `grep` — so `mf-scan export` can re-ingest a diff. |
| `--archive-depth N` / `--dir-mode` | As for `grep`, applied to each side. |
| `-f`, `--format` / `--output FILE` | Output format / sink. |

By default `diff` uses **mtime + size** (fast); add `--exact` when a content-preserving
timestamp could hide a change. See [docs/diff.md](docs/diff.md) for the full report
schema and the comparison rules.

### `app`

Locate and export an application's data, by bundle id (iOS) or package name
(Android). mf-scan auto-detects the acquisition layout — iOS full-file-system, iOS
backup, or Android — and resolves an app to **all** of its containers: its own data,
its extension/**widget** containers, and its shared **App Groups**.

```
mf-scan app list   [PATTERN] SOURCE [options]     # the installed-app inventory
mf-scan app paths  BUNDLE_ID SOURCE [options]     # list every data location of one app
mf-scan app export BUNDLE_ID SOURCE --to DIR [options]   # one app's data, as a zip
```

> As with `grep`, the app comes first and the **SOURCE last**. Open a directory
> source with `--dir-mode`; unlock an encrypted iOS backup with `--backup-password`
> (or `MFSCAN_BACKUP_PASSWORD`).

| Verb | What it does |
|---|---|
| `list` | Lists one line per app with a container of its own: bundle id, display name, size of its own data container (`-` when it has none here, e.g. Photos, whose data is in `Media/`), signing team (extensions and groups: see `paths`). An optional `PATTERN` filters by a substring of the id/name. `--format json` adds the full signing record (team, signer identity/organisation, App Groups, keychain groups). |
| `paths` | Lists every container the app or its dependencies can write to, tagged by kind (`AppData` / `Extension` / `AppGroup` / `Bundle`, or the Android storage root) and — for groups — by how it was attributed (`ContainerManager` vs `VendorHeuristic`). |
| `export` | Exports all of the app's data as one zip in `DIR` (`mf-scan-<UTC time>-export-<id>.zip`), **one folder per container** with the on-device tree preserved (`<id>/<Kind>_<guid>/…`, groups under their own id, a backup under its domain, an Android container under its kind and user: `<pkg>/data_u10/…`, a mount alias tagged `data_u0~mirror`, so two users or two copies never merge), with `export-report.json` (per-file integrity) inside. Excludes the `.app` bundle (binary, not data). |

Common `app` flags: `--dir-mode`, `--archive-depth N`, `--io-mode`,
`--backup-password`, `-f/--format txt|json`, `--output FILE`; for `paths`/`export`
also `--no-groups`; for `export` also `--to DIR`, `--max-size SIZE`, `--verify`.

**App Group attribution.** On an iOS full-file-system extraction, an app's App
Groups are read **authoritatively** from the entitlements iOS itself recorded when
it provisioned the app's containers, in
`/private/var/mobile/Library/MobileContainerManager/references.sqlite3`
(`com.apple.security.application-groups`), the app's own and its extensions' (a widget may be entitled to a group the app is not). A cross-brand shared group — e.g.
`group.com.facebook.family` used by Instagram — is therefore found even though its
name shares no token with the app, and an app that was provisioned with **no** App
Groups is reported as having none rather than being guessed at. Such inclusions are
tagged `ContainerManager`.

Where that database is unavailable — **always on an iOS backup**, which does not
contain it — mf-scan falls back to a reverse-DNS **vendor-token heuristic** and tags
every such inclusion `VendorHeuristic` in the output and report so it can be
audited. The heuristic finds same-vendor groups (`group.net.whatsapp.WhatsApp.shared`
for WhatsApp) but cannot find cross-brand ones, and is imprecise for apps whose
vendor token is shared by many groups. Use `--no-groups` to exclude shared containers
entirely.

Two details worth knowing when reconciling against another tool:

- mf-scan **replays** `references.sqlite3-wal` before reading, so it reports the
  committed database state rather than the possibly stale main file, and says so on
  stderr when it does. On one test device the log added 12 app records and
  superseded 8 — including replacing a placeholder stub for an installed messaging
  app with its real record and its App Group.
- **Extensions and widgets** are attributed to the app their container metadata
  names (`com.apple.MobileInstallation.ParentBundleID`), not to whichever installed
  app their bundle id happens to start with. `com.apple.siri` and
  `com.apple.siri.SiriGeo` are separate apps, and only the latter owns
  `com.apple.siri.SiriGeo.SiriGeoIntentExtension`.

**Why a zip.** Deep on-device trees produce paths longer than Windows' 260-character
`MAX_PATH`, which a folder on disk cannot hold for tools that do not handle long
paths. Inside a zip a path is only a member name, so **every file is exported, under
its exact name, on every platform**; the zip is written member by member, never as a
folder zipped afterwards. A member whose path would be too long to extract on Windows
is still exported, and listed as a **portability warning** (`portability_warnings` in
the report, and on stderr). The same applies to `grep`/`find`/`diff --export` and to
the `export` subcommand.

---

## Output

One line per match; binary file content is **never** raw-dumped. Default txt:

```
path:0x<file_offset>[:line]
```

The offset is hex (like a hex editor). The matched `line` is shown only for
**textual** files; binary files (SQLite, bplist, …) show just `path:0x<offset>`.
`--inspect` appends a labelled tag; `--count` prints `path:count` per file; `-l` prints
just the path; `-o` prints the matched text in place of the line. For a
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
in txt, a nested `context` object in json. A matched file nothing claims gets one more
try: if its whole content is JSON or a protobuf message, that inspector resolves the
match, marked "(by structure)" (`"detection": "structure"` in JSON): inferred, not certain.

| Format | Resolves a match to |
|---|---|
| TXT | line and column |
| JSON | key path + line, e.g. `$.users[3].token` |
| XML | element path with sibling indices, e.g. `/map[1]/string[4]/@name`, the attribute's value or the text, and the line |
| CSV | row, column, and header name |
| plist (XML & binary `bplist`) | dict-key / array-index path, e.g. `$.Account.Servers[1]` |
| plist (NSKeyedArchiver `bplist`) | logical path through the `$objects`/UID graph, e.g. `$.root.prefs.token`; resolves wrapped scalars (NSMutableString, NSData), array indices, and dict key-name hits; reports the Foundation class of the containing object |
| protobuf (by structure: the whole file or BLOB parses) | field path with no `.proto`, e.g. `4.4.2.1`, wire type and value (string, number, bytes, nested message); a value that is both valid text and a valid message is flagged as ambiguous |
| LevelDB logs (`*.log`) and manifests (`MANIFEST-*`) | record, sequence number, put or delete, key and value; manifest: the version edit field (comparator, new file and its key range, …) |
| LevelDB tables (`*.ldb`, `*.sst`) | data block, sequence number, put or delete, key and value, Snappy-compressed blocks included; an index entry's key and its data block; filter block, footer |
| uuidtext (unified logs) | the format string, its offset in the binary's string space (as `.tracev3` refers to it), and the binary's path |
| typedstream (`NSArchiver`: iMessage `attributedBody`, also inside a SQLite BLOB) | the chain of objects holding the string, e.g. `NSMutableAttributedString / NSMutableString`, and the text |
| keva (ByteDance: TikTok, Lemon8) | single-value files (`.sgv`): the value, or the element of a string array; the key is the file's name; other keva files are named, not decoded |
| MMKV (by structure: no signature) | key, value (string or number), entry number, and the later entry that supersedes it |
| ABX (Android Binary XML: `packages.xml`, permissions, settings) | element path with sibling indices, e.g. `/packages[1]/package[37]/@name`, and the attribute's typed value or the text |
| Realm (file format 10+) | class, property (type), object key and value for a string or binary property; else the schema, the property's data, Realm structure, or free space from an earlier version |
| SEGB (Biome streams, v1 and v2) | entry number, state (`written`/`deleted`), UTC time, CRC check, and the entry's data (usually protobuf, by structure) |
| SQLite | `table`, `column [TYPE]`, `row`, and the decoded cell value; else `page` + offset. A match in a `-wal` is resolved through the main database |
| SQLite BLOB cell | the format inside the cell: by signature (`bplist`, XML plist, SQLite, media…), else by structure (`blob: protobuf (by structure)`, `blob_detection` in JSON), as a lead to export and decode it properly |

**Identified only** (by a signature in the file, never by its name): a
match shows `[format]` with no position, so you know what the file is and which
tool opens it.

| Category | Formats |
|---|---|
| database | `lmdb`, `sqlite-wal`, `sqlite-shm`, `sqlite-journal` |
| log | `tracev3` (unified logs: LZ4-compressed entries), `dsc` (shared-cache strings) |
| structured | `binarycookies`, `bom` (`Assets.car`) |
| archive | `zip` (APK, IPA, DOCX…), `gzip`, `bzip2`, `xz`, `zstd`, `7z`, `tar`, `lz4`, `lzfse`, `aea` |
| executable | `elf`, `macho`, `dex`, `hermes` (React Native bytecode) |
| document | `pdf`, `ole` (legacy Office) |
| text (with line and column) | `vcard`, `icalendar`, `pem` |
| cache | `chromium-cache` (Chrome / WebView simple cache) |

Each name and category is also a `--type` value. A signature is looked for at the
start of the file, then (for LevelDB tables, whose magic is their last 8 bytes) at
its end; the end is read only when the start names nothing.

The same inspectors power `diff --inspect`'s intra-file comparison. See
[docs/inspectors.md](docs/inspectors.md).

---

## Decryption

Encrypted app databases inside an acquisition can be decrypted using keys from a
keychain/keystore dump, then searched and `--inspect`ed as plaintext. By default, when
a `*keychain*` or `*keystore*` dump (zipped or not) is found **beside the source** (e.g.
`case.zip` next to `keychain.plist`), profile-matched databases are decrypted
automatically; or point at one with `--keyfile FILE` (iOS keychain plist or Android
Keystore JSON). Use `--no-decrypt` to turn it off.

```bash
mf-scan grep "needle" case.zip                          # auto-detect keyfile beside it
mf-scan grep "token" case.zip --keyfile keychain.plist --platform ios
mf-scan find case.zip --path '*grdb/signal.sqlite' --export out/   # + signal.decrypted.sqlite
mf-scan decrypt case.zip --to case.decrypted.zip        # whole archive + decrypted copies
```

Per-app **profiles** (`profiles/{ios,android}/*.yml`) say which database to decrypt,
how to find its key, and the cipher. Supported ciphers: **SQLCipher** (Signal, Session,
Samsung system apps), the **page-level AES-OFB** of Apple's Find My daemons, and
**WhatsApp crypt14** (its key file is found inside the extraction). Every decryption is
recorded in the scan report with the key's
provenance and the SHA-256 of the ciphertext and plaintext.

> **Scope:** only works on acquisitions whose keychain was *already decrypted* by the
> acquisition tool (a raw `keychain-2.db` cannot be decrypted offline).
>
> **Validation:** every shipped cipher is validated on real extractions: SQLCipher
> (iPhone, Samsung), Find My (iPhone) and WhatsApp crypt14 (Pixel, Xiaomi). See
> [docs/decryption.md](docs/decryption.md) before relying on a decryption forensically.

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

An export is **one zip**, STORED (uncompressed, so `mf-scan` reads it back zero-copy
and any carving tool sees the original bytes), each member keeping its file's
modification time. The zip and its `.sha256` sidecar are **read-only**, and an export
**never replaces** an earlier one: each is named after its UTC time (`-2`, `-3`, … when
two land in the same second). It is written under a temporary name, read back with
mf-scan's own reader and only then moved into place, so a failed run leaves nothing
that looks finished. Two names that would be one file once extracted on Windows or
macOS (`Été.jpg` / `été.jpg`, or `é` composed / decomposed) never merge: the second is
written as `name~1` and listed under `renamed` in the report. `backup rebuild` and
`decrypt --to` archives are written the same way.

The zip holds `export-report.json` with an `integrity` summary and, per file,
**two independent SHA-256 hashes** plus any source-recorded digest check:

| Field | Meaning |
|---|---|
| `source_sha256` | SHA-256 of the bytes read **out of the source**. |
| `sha256` | SHA-256 of the bytes **read back from the zip** once written. |
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
- [docs/backup.md](docs/backup.md) — rebuilding iOS and Android backups: the archive, timestamps, the path tables.
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
- On `--export`, every exported file is **hashed at the source and re-hashed from the zip** and
  the two are compared (silent-copy-error check); ZIP entries are additionally checked
  against their central-directory CRC-32 and encrypted-backup files against their
  `Manifest.db` SHA-1. See [Export integrity](#export-integrity).
- **Every result says what it may leave out**: grep, find (at a terminal), diff and
  the `app` commands end with a `note: …; when in doubt, check by hand` line. mf-scan
  guides an examination; it does not close it. Other matches (formats, encodings or
  compression it does not read, encrypted data), files, changes, apps or containers
  may exist beyond what it reports.
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
