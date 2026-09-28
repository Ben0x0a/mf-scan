# `ios-backup` — inspect and rebuild an iOS backup

An iTunes/Finder backup is a flat store of SHA-1-named blobs plus `Manifest.db`,
which records each file's `domain` and `relativePath`. `mf-scan` reads that as a
logical view for `grep`, `diff` and `app`; the `ios-backup` verbs report on it and
turn it back into a directory tree.

```text
mf-scan ios-backup info    SOURCE [--dir-mode] [--backup-password PW]
mf-scan ios-backup rebuild SOURCE --to DIR [options]
```

## `info`

Reports what the backup is without writing anything: encrypted or not, how it was
unlocked, how many files it maps, and how many `Manifest.db` lists but the backup
does not hold.

```bash
mf-scan ios-backup info ./MyBackup --dir-mode
```

```text
backup: unencrypted; 3 file(s) mapped to logical paths via Manifest.db
⚠ backup: 1 file(s) listed in Manifest.db are MISSING on disk (incomplete or modified acquisition)
```

## `rebuild`

Writes every file the backup holds to the path it occupied on the device.

```bash
mf-scan ios-backup rebuild ./MyBackup --dir-mode --to ./rebuilt
```

```text
HomeDomain/Library/SMS/sms.db  ->  private/var/mobile/Library/SMS/sms.db
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--to DIR` | — | Destination directory (required) |
| `--dry-run` | off | Report the plan and write nothing |
| `--backup-password PW` | — | Else `MFSCAN_BACKUP_PASSWORD`, else the acquisition defaults |
| `--max-size SIZE` | no cap | Refuse the rebuild if the tree would exceed this |
| `--max-path-len N` | 260 | Skip destinations longer than this; `0` disables |
| `--manifest FILE` | — | Also write a re-ingestable JSON manifest |
| `--verify` | off | SHA-256 the source archive before and after reading |
| `--dir-mode` | off | Required when SOURCE is a directory |

Unlike `app export`, `--max-size` has **no default cap**: a 1G default would
refuse essentially every real backup and write nothing.

### Three things it tells you, and why

**Synthetic paths.** A backup records no container GUIDs, so an app's real
`…/Containers/Data/Application/<GUID>/` path cannot be reconstructed. The bundle
identifier is substituted and every affected domain is listed:

```text
⚠ 1 domain(s) map to a SYNTHETIC path: a backup records no container GUIDs, so the
  bundle identifier is substituted. These paths are not ground truth:
    AppDomain-com.test.app
```

Treat those paths as a convenience, not as evidence of where the data lived.

**Unmapped domains.** A domain with no known mount point is written under
`_unmapped_domains/<domain>/` and reported. Nothing is dropped, and nothing
unrecognised is given a device-looking path.

**Missing files.** A file `Manifest.db` lists but the backup does not hold is
reported and skipped; the rebuild continues. That is a property of the
acquisition, not of the rebuild.

### What it writes

```text
rebuilt/
├── export-report.json                     per-file SHA-256 and stored-digest attestation
├── private/var/mobile/Library/SMS/sms.db
└── private/var/mobile/Containers/Data/Application/com.test.app/…
```

`export-report.json` records, per file, the SHA-256 of what was read and of what
was written (`copy_verified`), plus `stored_integrity` — the SHA-1 the backup's
`Manifest.db` recorded for the blob as stored. For an encrypted backup that digest
covers the *ciphertext*, so it attests the evidence was read intact before
decryption.

### Directories and symlinks

Directory records (`flags == 2`) are recreated, including empty ones — an empty
`Library/Caches` is itself evidence. Symlink records are reported but not
recreated: the target is not recorded in a resolvable form, and writing a link
into an export is a way to escape it.

## Where the mapping comes from

The domain → path table is compiled in, at `src/platform/ios/domains.rs`, rather
than living in an editable data file. Three reasons:

- The mapping does not drift — `HomeDomain` has mounted at `/private/var/mobile`
  since iOS 5. That is the opposite of the decryption profiles, which are data
  precisely because app cipher parameters change constantly.
- A typo in a data file fails silently at run time on an operator's machine; a
  wrong enum variant fails at build time.
- The destination is built with `Path::join`, which discards its base for an
  absolute path. An editable map written with the natural `/private/var/mobile`
  would have written to the real filesystem root.

The table was validated against 2,638 rows of a real iPhone reconstruction, which
found and fixed a segment-doubling defect in `CameraRollDomain` and `MediaDomain`.
`src/platform/ios/domains.rs` is the single definition the app catalogue and the
full-filesystem classifier also consume, so a rebuilt tree and the classifier that
reads one back cannot disagree.
