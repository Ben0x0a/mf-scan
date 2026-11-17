//! Decrypt one entry of a source: find its `-wal`, then run the decryption context.
//!
//! Defines: [`SourceDecryptor`], the pairing of a [`DecryptionContext`] with the
//! [`Source`] whose entries it decrypts, [`describe`] (the one-line provenance of a
//! decryption), and [`dumps_in_source`] (key dumps the source itself carries).
//! Used by: `ops::search::classify` (decrypt before searching), the exports (a
//! [`DerivedCopy`] that writes each decrypted database beside its original), and the
//! `decrypt` command (the archive with decrypted copies added).
//! Uses: `decrypt` (the context). Also defines [`DerivedCopy`] / [`Derived`], the hook
//! `report::export` and `report::decrypted_zip` call to make a derived copy.
//!
//! WHY a type of its own: the context knows profiles and keys but not the source, and
//! a database's `-wal` is another entry of that source. Every caller needs the same
//! lookup, so it lives here once instead of in each of them.

use crate::core::filter::matches;
use crate::core::models::Entry;
use crate::core::source::Source;
use crate::decrypt::profile::KEY_FILE_SOURCE;
use crate::decrypt::{
    Decryption, DecryptionContext, Secret, SecretStore, TryOutcome, load_if_dump,
};

/// A decryption context bound to the source whose entries it decrypts.
pub struct SourceDecryptor<'a> {
    ctx: &'a DecryptionContext,
    source: &'a dyn Source,
}

impl<'a> SourceDecryptor<'a> {
    pub fn new(ctx: &'a DecryptionContext, source: &'a dyn Source) -> Self {
        Self { ctx, source }
    }

    /// Whether a profile targets `entry`.
    pub fn targets(&self, entry: &Entry) -> bool {
        self.ctx.targets(&entry.name)
    }

    /// Decrypt `entry`, whose stored bytes are `content`. `None` when no profile
    /// targets it (or it is a plain database in a targeted folder).
    ///
    /// A targeted database's uncommitted changes live in its `-wal`, which is fetched
    /// from the source and replayed by the context. The lookup is a linear scan, but
    /// it runs only for the few entries a profile targets.
    pub fn decrypt(&self, entry: &Entry, content: &[u8]) -> Option<TryOutcome> {
        if !self.targets(entry) {
            return None;
        }
        let wal_name = format!("{}-wal", entry.name);
        let wal_entry = self.source.entries().iter().find(|e| e.name == wal_name);
        // A -wal that exists but cannot be read (a corrupt DEFLATE stream) is not the
        // same as no -wal: its changes are missing, and the record must say so.
        let (wal, wal_error) = match wal_entry.map(|e| self.source.content(e)) {
            None => (None, None),
            Some(Ok(wal)) => (Some(wal), None),
            Some(Err(err)) => (None, Some(format!("cannot read {wal_name}: {err:#}"))),
        };
        let mut outcome = self.ctx.try_decrypt(&entry.name, content, wal.as_deref())?;
        if let TryOutcome::Decrypted(d) = &mut outcome {
            d.wal_error = wal_error;
        }
        Some(outcome)
    }
}

/// Produces a file derived from an exported one, written beside it (a decrypted
/// copy of an encrypted database, for one).
///
/// WHY a trait, defined here: the report layer writes and attests files but does not
/// know how to decrypt, so the caller supplies the transform and the exporter names
/// the copy, writes it, hashes it and records it like any other file. It lives in
/// `ops`, beside its implementation, because `report` already depends on `ops`;
/// defining it in `report` would make the two layers depend on each other.
pub trait DerivedCopy: Sync {
    /// Whether `entry` may have a derived form. A cheap test on the entry alone, so a
    /// caller walking a whole archive reads only the files it applies to.
    fn wants(&self, entry: &Entry) -> bool;

    /// The derived bytes for `entry`, whose stored bytes are `content`: `None` when it
    /// has no derived form, `Some(Err(reason))` when it should have had one but could
    /// not be produced (a database whose key did not verify).
    fn derive(&self, entry: &Entry, content: &[u8])
    -> Option<std::result::Result<Derived, String>>;
}

/// One derived file: its bytes, and how they were produced (for the report).
pub struct Derived {
    pub bytes: Vec<u8>,
    pub note: String,
}

impl DerivedCopy for SourceDecryptor<'_> {
    fn wants(&self, entry: &Entry) -> bool {
        self.targets(entry)
    }

    /// The decrypted database, when `entry` decrypts, or why it did not.
    fn derive(&self, entry: &Entry, content: &[u8]) -> Option<Result<Derived, String>> {
        match self.decrypt(entry, content)? {
            TryOutcome::Decrypted(d) => Some(Ok(Derived {
                note: describe(&d),
                bytes: d.plaintext,
            })),
            TryOutcome::Failed {
                profile, reason, ..
            } => Some(Err(format!("profile {profile}: {reason}"))),
        }
    }
}

/// One line on how a database was decrypted, for an export or archive report.
pub fn describe(d: &Decryption) -> String {
    let mark = if d.verified { "verified" } else { "UNVERIFIED" };
    let wal = if d.wal_replayed {
        ", -wal replayed"
    } else {
        ""
    };
    format!(
        "decrypted by profile {} ({mark}{wal}; key svc={} acct={}, from {})",
        d.profile,
        d.secret_service.as_deref().unwrap_or("?"),
        d.secret_account.as_deref().unwrap_or("?"),
        d.secret_source,
    )
}

/// A key dump found inside a source.
pub struct FoundDump {
    /// Its path inside the source.
    pub path: String,
    pub secrets: SecretStore,
}

/// Words in a file name that mark it as a possible keychain/keystore dump.
const DUMP_NAME_HINTS: &[&str] = &["keychain", "keystore"];
/// The largest file read as a possible dump: no dump is that large, and a matching
/// name on a large file (an extraction named after its keychain) is not one.
pub const MAX_DUMP_LEN: u64 = 256 * 1024 * 1024;

/// Whether a file name marks a possible key dump. The one rule for a dump beside
/// the source and one inside it; content detection then decides.
pub fn is_dump_name(file_name: &str) -> bool {
    let name = file_name.to_ascii_lowercase();
    DUMP_NAME_HINTS.iter().any(|hint| name.contains(hint))
}

/// Key dumps the source itself carries: every file named `*keychain*` or `*keystore*`
/// whose content a dump provider recognises (a zip holding one included).
///
/// WHY: some deliveries put the dump inside the acquisition rather than beside it. A
/// Cellebrite `.ufdr` report holds `files/Configuration/<udid>_keychain.plist`, and
/// iLEAPP looks for one inside an extraction in the same way. The name test keeps
/// this cheap (a full-filesystem extraction has a few dozen such names, mostly system
/// binaries), and content detection then rejects every file that is not a dump.
pub fn dumps_in_source(source: &dyn Source) -> Vec<FoundDump> {
    source
        .entries()
        .iter()
        .filter(|e| !e.is_dir() && e.uncompressed_size <= MAX_DUMP_LEN)
        .filter(|e| {
            let name = e
                .name
                .rsplit('/')
                .next()
                .unwrap_or(&e.name)
                .to_ascii_lowercase();
            DUMP_NAME_HINTS.iter().any(|hint| name.contains(hint))
        })
        .filter_map(|e| {
            let content = source.content(e).ok()?;
            let secrets = load_if_dump(&content)?;
            (!secrets.is_empty()).then(|| FoundDump {
                path: e.name.clone(),
                secrets,
            })
        })
        .collect()
}

/// The key files the profiles in `ctx` name (`key: { file: <glob> }`), read from the
/// source as secrets: each one's path is its label, so a profile matches it by glob.
///
/// Read only for files no larger than [`MAX_DUMP_LEN`]; a key file is tiny (WhatsApp's
/// is 158 bytes).
pub fn key_files_in_source(source: &dyn Source, ctx: &DecryptionContext) -> SecretStore {
    let globs = ctx.key_file_globs();
    if globs.is_empty() {
        return SecretStore::default();
    }
    let items = source
        .entries()
        .iter()
        .filter(|e| !e.is_dir() && e.uncompressed_size <= MAX_DUMP_LEN)
        .filter(|e| globs.iter().any(|g| matches(g, &e.name)))
        .filter_map(|e| {
            let data = source.content(e).ok()?.to_vec();
            Some(Secret {
                account: None,
                service: None,
                access_group: None,
                label: Some(e.name.clone()),
                protection_class: None,
                data,
                source: KEY_FILE_SOURCE.to_string(),
            })
        })
        .collect();
    SecretStore::new(items)
}
