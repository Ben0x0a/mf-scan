# Test fixtures

Every fixture here is **synthetic**. None contains bytes from a real device or any
personal data — see the repository's no-evidence-data rule. This file records how
the non-obvious ones were produced, so a maintainer can regenerate or extend them
deliberately rather than by guesswork.

## `mcm_references.sqlite3`

A miniature of iOS's `/private/var/mobile/Library/MobileContainerManager/references.sqlite3`,
built on that database's real schema (`code_signing_info`, `code_signing_data`,
`child_bundles`). Read by `platform::ios::references` and `tests/apps.rs`.

Three identities, chosen to exercise the reader's failure modes:

| `code_signing_id_text` | row id | blob |
|---|---|---|
| `com.example.full` | 7 | full record: two App Groups (one cross-brand), keychain groups, team, signer |
| `com.example.nogroups` | 11 | entitlements dictionary present but naming no App Groups |
| `com.example.corrupt` | 23 | deliberately not a property list |

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
