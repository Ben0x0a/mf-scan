# `backup` — inspect and rebuild a mobile backup

A backup does not hold a device's file tree. An iOS iTunes/Finder backup is a flat store
of SHA-1-named blobs plus `Manifest.db`, which records each file's `domain` and
`relativePath`. An Android `adb backup` (`.ab`) is a compressed, optionally encrypted tar
whose member names (`apps/<package>/<token>/...`) stand in for device paths. `mf-scan`
reads both as a logical view for `grep`, `find`, `diff` and `app`; the `backup` verbs
report on one and turn it back into the device's tree.

```text
mf-scan backup info    SOURCE [--backup-password]
mf-scan backup rebuild SOURCE --to FILE.zip [options]
```

`SOURCE` is an iOS backup folder, an archive of one, or an `.ab` file. An `.ab` is
recognised by its header, never its name. A folder needs no flag.

`rebuild` decrypts as it goes. There is no mode that decrypts a backup but keeps its own
flat layout: the rebuilt archive, with `Manifest.db` at its root, holds the same evidence.

## `info`

Reports what the backup is without writing anything: its platform, whether it is
encrypted, how it was unlocked, and how many files it holds.

```bash
mf-scan backup info ./MyBackup
```

```text
source: ./MyBackup
platform: iOS
backup: unencrypted; 3 file(s) mapped to logical paths via Manifest.db
⚠ backup: 1 file(s) listed in Manifest.db are MISSING on disk (incomplete or modified acquisition)
```

## `rebuild`

Writes every file the backup holds, at the path it occupied on the device, into one ZIP.

```bash
mf-scan backup rebuild ./MyBackup --to device.zip
mf-scan backup rebuild phone.ab --to device.zip
```

```text
HomeDomain/Library/SMS/sms.db  ->  private/var/mobile/Library/SMS/sms.db
apps/com.app/db/data.db        ->  data/data/com.app/databases/data.db
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--to FILE.zip` | — | The archive to write (required). `.zip` is added if missing |
| `--force` | off | Replace the archive if it already exists |
| `--dry-run` | off | Report the plan and write nothing |
| `--continue-on-error` | off | Keep what can be read of a damaged backup, recording the rest |
| `--backup-password` | — | Ask for the password (no echo) if no acquisition default opens the backup; else `MFSCAN_BACKUP_PASSWORD` |
| `--archive-password` | — | Ask for the password of an encrypted 7z or ZIP holding the backup; else `MFSCAN_ARCHIVE_PASSWORD` |
| `--max-size SIZE` | no cap | Refuse the rebuild if the files would exceed this |
| `--verify` | off | SHA-256 the source file before and after reading |

`--max-size` has **no default cap**: a 1G default would refuse essentially every real
backup and write nothing.

### Why only a ZIP

A rebuilt device path is long before your destination is added. As a tree on disk it can
cross Windows' 260-character limit, which many tools cannot read. Inside a ZIP, a path is
only a member name, so the output is complete on every platform, and it is the shape a
full-filesystem acquisition is delivered in. `mf-scan` and other forensic tools then read
it like one.

A member that would exceed the limit if later *extracted* on Windows is still written,
and is listed under `portability_warnings` in the traceability record.

### Timestamps

Each file and directory keeps the modification time the backup recorded. It is stored
twice, because the two fields fail differently:

| Field | Holds | Read by |
| --- | --- | --- |
| DOS time | UTC, 2-second resolution, 1980–2107, no time zone | Every tool, including Windows Explorer |
| Extended timestamp (`0x5455`) | Exact UTC seconds | `unzip`, 7-Zip, `mf-scan` |

Copying or moving the archive changes neither, and tools that read the extended timestamp
restore the same time in every time zone. Tools that read only the DOS field, such as
Windows Explorer, show the UTC time without saying it is UTC.

An unknown time, or one before 1980, shows as 1980-01-01 in the DOS field. Android records
a modification time of 0 on each app's `_manifest`, so those members carry 1970-01-01 in
the extended timestamp, as the backup states. The member's time as recorded is also in the
traceability record, as `mtime_utc`.

The archive holds a member's modification time only: iOS also records birth and status
change times, and these are not carried.

### What it reports, and why

**Synthetic paths (iOS).** A backup records no container GUIDs, so an app's real
`…/Containers/Data/Application/<GUID>/` path cannot be reconstructed. The bundle
identifier is substituted and every affected domain is listed. Treat those paths as a
convenience, not as evidence of where the data lived.

**Unmapped domains (iOS).** A domain with no known mount point is written under
`unknown_backup_domains/<domain>/` and reported.

**No device location (Android).** Each app's `_manifest` and `_meta`, key/value records,
unknown tokens, and anything outside `apps/` and `shared/` go under `backup_only/`. An
APK's real directory is randomised on the device and not recorded, so `data/app/<package>`
is an approximation.

**Missing files (iOS).** A file `Manifest.db` lists but the backup does not hold is
reported and skipped. That is a property of the acquisition, not of the rebuild.

**Renamed files.** Two paths that differ only in case are distinct on a device but collide
on Windows and macOS, so the second gets a `~1` suffix and is reported.

**Links.** Link records are reported, not recreated: writing a link into an export is a way
to escape it.

### Damage

A truncated or corrupt `.ab` (bad AES padding, a compressed stream with no end, a broken
tar block) is reported, and `rebuild` refuses to write anything unless told
`--continue-on-error`, when the files read before the damage are kept and the record's
`stream_error` says what happened. Any file that cannot be read fails the run the same way.

The archive is written under a temporary name beside its destination and moved into place
only when complete and read back, so a failed run leaves nothing that looks finished.

### What it writes

```text
device.zip
├── Manifest.db                                   iOS: the database the rebuild walked
├── Manifest.mf-scan.zip-paths.csv                iOS: each of its rows' member in this zip
├── _traceability/mf-scan.rebuild.traceability.json
├── private/var/mobile/Library/SMS/sms.db
└── private/var/mobile/Containers/Data/Application/com.test.app/…
device.zip.sha256
```

**`Manifest.db`** is the backup's own index, byte for byte: decrypted for an encrypted
backup, as stored otherwise, and carrying the backup's timestamp. It is the only place the
backup records each file's metadata (sizes, times, protection class), so it is kept.

**`Manifest.mf-scan.zip-paths.csv`** lists every `Files` row, sorted by `fileID`, with the
member it became in this archive:

```text
fileID,domain,relativePath,flags,zipPath
3d0d7e5f…,HomeDomain,Library/SMS/sms.db,1,private/var/mobile/Library/SMS/sms.db
```

`zipPath` is empty for a row with no member (a file missing from the backup, a link), and a
directory's ends in `/`. `fileID` joins it to `Manifest.db`, for example in SQLite:

```sql
.import --csv Manifest.mf-scan.zip-paths.csv paths
SELECT f.domain, f.relativePath, p.zipPath FROM Files f JOIN paths p USING (fileID);
```

The Python reconstructor adds the same `zipPath` as a column on a copy of `Manifest.db`. The
values agree; a CSV is used here because writing SQLite would mean rewriting its b-trees and
pointer maps by hand, for something a join does as well. It is UTF-8 with a BOM, so Excel
decodes accented paths.

The traceability record holds the run metadata and, per file, the SHA-256 of what was read
and of what landed in the archive (`copy_verified`), its time, and `stored_integrity`: the
SHA-1 an iOS `Manifest.db` recorded for the blob as stored, which for an encrypted backup
covers the *ciphertext*, so it attests the evidence was read intact before decryption.

`device.zip.sha256` is in `sha256sum` format, so `shasum -a 256 -c device.zip.sha256`
verifies the archive. An archive cannot contain its own digest, hence the separate file.

Members are STORED, not compressed: their bytes sit in the archive unchanged, so `mf-scan`
reads it zero-copy with exact offsets. The archive is therefore about the size of the
backup's decoded content, which for an `.ab` is larger than the `.ab` itself.

## Android backups

The format is defined by AOSP: `PerformAdbBackupTask.java` writes it and
`PerformAdbRestoreTask.java` reads it. A text header gives the version (1–5), whether the
payload is zlib-compressed, and the encryption; the payload is a tar.

| Token | Device directory (user 0) |
| --- | --- |
| `r` | `data/data/<package>` |
| `f`, `db`, `sp`, `c`, `nb` | `files`, `databases`, `shared_prefs`, `cache`, `no_backup` under it |
| `d_r`, `d_f`, `d_db`, `d_sp`, `d_c`, `d_nb` | The same, under `data/user_de/0/<package>` |
| `ef` | `storage/emulated/0/Android/data/<package>/files` |
| `obb` | `storage/emulated/0/Android/obb/<package>` |
| `a` | `data/app/<package>` (approximate) |
| `k` | Key/value records: `backup_only/apps/<package>/k` |

`shared/0/` is `storage/emulated/0`.

`adb backup` includes only apps that allow backup, an app can exclude files from it, and it
is deprecated on recent Android versions. A small package list is a property of the backup,
not a rebuild failure.

**Encryption.** The password unlocks an AES-256 key held in the header, verified by a
checksum before anything is decoded, so a wrong password fails immediately. As for an iOS
backup, the acquisition defaults (`1234`, `12345`, `123456`, `password`, `Password`) are
tried first, then the password supplied (`MFSCAN_BACKUP_PASSWORD`) or asked for
(`--backup-password`, asked only when no default worked); which one worked is reported
loudly and recorded. A supplied password equal to a default is recorded as supplied.

**Memory.** A compressed or encrypted payload has to be decoded before it can be read at
random. Up to 64 MiB stays in memory. Beyond that it spills to an unnamed temporary file,
which the operating system deletes when the process ends. That file holds **decrypted
evidence** while the tool runs and needs free space for the decoded size, so point `TMPDIR`
(`TMP` on Windows) at an approved location if that matters.

## Where the mappings come from

The tables are compiled in, at `src/platform/ios/domains.rs` and
`src/platform/android/paths.rs`, rather than living in editable data files. Three reasons:

- They do not drift: `HomeDomain` has mounted at `/private/var/mobile` since iOS 5, and the
  Android tokens are AOSP constants. That is the opposite of the decryption profiles, which
  are data precisely because app cipher parameters change constantly.
- A typo in a data file fails silently at run time on an operator's machine; a wrong enum
  variant fails at build time.
- A path joined onto a destination with `Path::join` discards the destination if it is
  absolute, so an editable map written with the natural `/private/var/mobile` could write
  to the real filesystem root.

The iOS table was validated against a real iPhone backup and the Android table against real
`.ab` files, each compared member by member with the Python Mobile Backup Reconstructor.
