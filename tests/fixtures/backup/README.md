# iOS backup test fixtures

Tiny, fully-synthetic iTunes/Finder backups used by [`tests/backup.rs`](../../backup.rs).
**No personal data** — every file holds a few bytes of dummy text; the keys, salts,
and `fileID`s are fixed so the output is byte-for-byte reproducible.

| Dir | `IsEncrypted` | Password | What it exercises |
|---|---|---|---|
| `unencrypted/` | `false` | — | profile detection, logical `domain/relativePath` naming, plain blob reads, `Digest = SHA-1(content)`, missing-on-disk count |
| `encrypted/` | `true` | `1234` | the keybag KDF (double PBKDF2) + class-key unwrap + per-file AES-256-CBC decrypt, `Digest = SHA-1(ciphertext)`, wrong-password rejection |

Each backup contains the same logical set: three regular files (one with a search
token, one without a recorded `Digest`), one directory row (skipped), and one file
listed in `Manifest.db` but **absent on disk** (counted as missing).

## Committed directly — the tests need no Python

These fixtures are checked in as plain files, so `cargo test` runs against them with
no external tooling. They were produced by a one-off generator (`generate.py`) that
is **kept out of version control** (`.gitignore`d) precisely so the test suite does
not depend on Python or the `cryptography` package. Regenerating them — only needed
if the fixture shape changes — requires that local script plus
`pip install cryptography` (AES-CBC + RFC 3394 key wrap; PBKDF2 is stdlib); it is
deterministic, so it reproduces byte-identical output.
