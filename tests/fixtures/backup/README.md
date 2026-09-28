# iOS backup test fixtures

Tiny, fully-synthetic iTunes/Finder backups used by [`tests/backup.rs`](../../backup.rs).
**No personal data** — every file holds a few bytes of dummy text; the keys, salts,
and `fileID`s are fixed so the output is byte-for-byte reproducible.

| Dir | `IsEncrypted` | Password | What it exercises |
|---|---|---|---|
| `unencrypted/` | `false` | — | profile detection, logical `domain/relativePath` naming, plain blob reads, `Digest = SHA-1(content)`, missing-on-disk count |
| `encrypted/` | `true` | `1234` | the keybag KDF (double PBKDF2) + class-key unwrap + per-file AES-256-CBC decrypt, `Digest = SHA-1(ciphertext)`, wrong-password rejection |

Each backup contains the same logical set: three regular files (one with a search
token, one without a recorded `Digest`), one directory row (`flags = 2`, exposed
through `BackupSource::structure()` rather than `entries()`), and one file listed
in `Manifest.db` but **absent on disk** (counted as missing).

### The directory row must actually carry `flags = 2`

Until 2026-09 it did not. The generator's `DIR_ROW` was a 4-tuple ordered
`(domain, relativePath, content, flags)` but was unpacked as `d, r, fl, b`, so the
empty *content* was written into the `flags` column and the value `2` into the blob
column. The row therefore had `flags` = empty blob, and every code path that
handles directory records was silently untested.

If the generator is ever reconstructed, verify with:

```sh
sqlite3 unencrypted/Manifest.db \
  "SELECT relativePath, typeof(flags), flags FROM Files WHERE flags = 2;"
```

It must return `Library|integer|2`. `tests/backup.rs::directory_records_are_separate_from_entries`
asserts the fixture has at least one directory row, so a regression fails the suite
rather than passing vacuously.

## Committed directly — the tests need no Python

These fixtures are checked in as plain files, so `cargo test` runs against them with
no external tooling. They were produced by a one-off generator (`generate.py`) that
is **kept out of version control** (`.gitignore`d) precisely so the test suite does
not depend on Python or the `cryptography` package. Regenerating them — only needed
if the fixture shape changes — requires that local script plus
`pip install cryptography` (AES-CBC + RFC 3394 key wrap; PBKDF2 is stdlib); it is
deterministic, so it reproduces byte-identical output.

When regenerating, review the diff rather than accepting it: every change must trace
to the edit you intended. A useful check is that only the two `Manifest.db` files
differ and every blob and plist stays byte-identical — the encrypted `Manifest.db`
changes wholesale even for a one-row edit, because it is AES-CBC over the whole
SQLite file.
