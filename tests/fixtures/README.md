# Test fixtures

Every fixture here is **synthetic**. None contains bytes from a real device or any
personal data — see the repository's no-evidence-data rule. This file records how
the non-obvious ones were produced, so a maintainer can regenerate or extend them
deliberately rather than by guesswork.

## `mcm_references.sqlite3`

A miniature of iOS's `/private/var/mobile/Library/MobileContainerManager/references.sqlite3`,
built on that database's real schema (`code_signing_info`, `code_signing_data`,
`child_bundles`). Read by `platform::ios::references` and `tests/apps.rs`.

Four identities, chosen to exercise the reader's failure modes:

| `code_signing_id_text` | row id | blob |
|---|---|---|
| `com.example.full` | 7 | full record: two App Groups (one cross-brand), keychain groups, team, signer |
| `com.example.nogroups` | 11 | entitlements dictionary present but naming no App Groups |
| `com.example.corrupt` | 23 | deliberately not a property list |
| `com.example.full.Widget` | 31 | an extension of `com.example.full` (`child_bundles`), entitled to `group.com.example.widgetonly`, which the app itself is not |

Two properties are load-bearing and must be preserved if it is regenerated:

- **Row ids are non-contiguous (7, 11, 23)** and the `code_signing_data` rows are
  inserted in a *different* order (blobs for 23, 7, 11). `code_signing_info.id` is
  an `INTEGER PRIMARY KEY`, so it is stored as the cell's row id and decodes to
  NULL; a reader that joined by row position, or by the data table's own row id,
  would pass on a naively ordered fixture and fail here.
- **`com.example.full`'s groups include `group.com.othervendor.crossbrand`**, which
  shares no name token with the app. It is the case the vendor-token heuristic
  provably cannot reach, so it is what proves the MCM path is doing the work.

Regenerate with `python3`'s `sqlite3` + `plistlib` (binary plists), then
`PRAGMA journal_mode=DELETE` so no sidecar is committed alongside.

## `wal_main.sqlite3` + `wal_main.sqlite3-wal`

A database captured **mid-write**, for `formats::sqlite::wal`. The main file holds
one committed row; three more exist only in the sidecar. Reading the main file
alone therefore returns a genuinely stale answer — which is the point: it is what a
live acquisition captures, and what the replay has to fix.

Produced by opening a WAL-mode database with `PRAGMA wal_autocheckpoint=0`,
checkpointing once (so the main file is not empty), inserting more rows, and
copying **both files while the connection is still open** — SQLite checkpoints on
close, which would fold the sidecar away and destroy the fixture.

## `messages.sqlite`, `blob.sqlite`

Small hand-made databases for the SQLite inspector and row reader:
`messages(id INTEGER PRIMARY KEY, sender, body)` with a searchable needle, and
`items(id, name, payload)` whose `payload` BLOB holds a binary plist.

## `sample.plist`, `sample.bplist`, `nskeyed*.bplist`

Property lists for the plist and NSKeyedArchiver inspectors, in XML and binary
form, including archived arrays, wrapped values and dictionary keys.

## `backup/`

A minimal iTunes/Finder backup layout (`Manifest.db` plus hashed blob files) for
the backup source reader.

## `compressed/`

`note.tar`, a ustar archive holding `evidence/note.txt` ("needle in a compressed tar"),
written by Python's `tarfile` (`USTAR_FORMAT`, mtime 1700000000, uid/gid 0, `root`),
and the same tar compressed by the reference tools, for `core::source::compressed`
and `tests/compressed_tar.rs`. The tar is cut in two at half its length and each half
compressed on its own, then the two concatenated, so each fixture holds two gzip or
bzip2 members, two xz streams or two zstd frames: a reader that stops after the first
decodes half a tar. The zstd file also starts with a skippable frame (magic
`0x184D2A50`, length 4, `skip`).

| file | command per half |
|---|---|
| `note.tar.gz` | `gzip -n -9 -c` |
| `note.tar.bz2` | `bzip2 -9 -c` |
| `note.tar.xz` | `xz -6 -c --check=crc64` |
| `note.tar.zst` | `zstd -19 -q -c --check` |

Each was checked to decode back to `note.tar` with the same tool (`gzip -dc`,
`bzip2 -dc`, `xz -dc`, `zstd -dcq`).

## `sevenz/`

7z archives of one synthetic tree, for `core::source::sevenz` and `tests/sevenz.rs`,
made by 7-Zip 26.06 (`7zz`). The tree, under `evidence/`: `note.txt` ("needle in a
7z"), `filler.txt` (2000 lines `line N of filler text`, 48,890 bytes, so the solid
block holds two members with data), an empty `empty.txt` and an empty directory
`empty-dir`. Every time set with `TZ=UTC touch -h -t 202311142213.20` (Unix
1700000000). Each archive is solid, one block. The password, `fixture-password`, is
made up.

| file | command (from the tree's parent) |
|---|---|
| `note.7z` | `7zz a -ms=on -m0=LZMA2 note.7z evidence` |
| `note.ppmd.7z` | `7zz a -ms=on -m0=PPMd note.ppmd.7z evidence` |
| `note.bzip2.7z` | `7zz a -ms=on -m0=BZip2 note.bzip2.7z evidence` |
| `note.aes.7z` | `7zz a -ms=on -pfixture-password -mhe=off note.aes.7z evidence` (data encrypted) |
| `note.aes-header.7z` | `7zz a -ms=on -pfixture-password -mhe=on note.aes-header.7z evidence` (list of files too) |
| `note.deflate.7z` | `7zz a -m0=Deflate note.deflate.7z evidence` (a method this build does not decode) |

## `encrypted_zip/`

ZIP archives of one synthetic tree, for `tests/encrypted_zip.rs` and the ZIP reader:
`evidence/note.txt` ("needle in a zip"), `evidence/filler.txt` (2000 lines `line N of
filler text`, 48,890 bytes) and, for `mixed.zip` only, `plain.txt` ("plain needle
beside encrypted files"). Every time set with `TZ=UTC touch -h -t 202311142213.20`.
The password, `fixture-password`, is made up. Made by 7-Zip 26.06 (`7zz`) and by
Info-ZIP Zip 3.0 (macOS `/usr/bin/zip`), from the tree's parent; each was checked with
Python's `zipfile` for the flags, method and AES field below.

| file | command | what it holds |
|---|---|---|
| `note.aes256.zip` | `7zz a -tzip -mem=AES256 -p… note.aes256.zip evidence` | AE-2, AES-256; `note.txt` Stored, `filler.txt` Deflate |
| `note.aes192.zip` | `… -mem=AES192 …` | AE-2, AES-192 |
| `note.aes128.zip` | `… -mem=AES128 …` | AE-2, AES-128 |
| `note.aes256-stored.zip` | `… -mx0 -mem=AES256 …` | AE-2, AES-256, both Stored |
| `note.zipcrypto.zip` | `7zz a -tzip -mem=ZipCrypto -p… note.zipcrypto.zip evidence` | ZipCrypto, flags `0x0001` (check byte from the CRC) |
| `note.infozip.zip` | `zip -q -r -e -P … note.infozip.zip evidence` | ZipCrypto, flags `0x0009` (data descriptor: check byte from the DOS time) |
| `mixed.zip` | `7zz a -tzip mixed.zip plain.txt`, then `7zz a -tzip -mem=AES256 -p… mixed.zip evidence` | one plain file beside AES ones |
| `note.bzip2.zip` | `7zz a -tzip -mm=BZip2 note.bzip2.zip evidence` | `filler.txt` method 12; `note.txt` Stored by 7-Zip |
| `note.lzma.zip` | `7zz a -tzip -mm=LZMA note.lzma.zip evidence` | `filler.txt` method 14; `note.txt` Stored |
