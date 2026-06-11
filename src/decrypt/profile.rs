//! Decryption profile registry: declarative app → key → cipher descriptions.
//!
//! Defines: the profile data model loaded from YAML files under `profiles/` —
//! [`Platform`], [`Profile`], [`DbBinding`], [`KeySpec`], [`KeychainMatch`],
//! [`KeyEncoding`]/[`KeyMaterial`], and [`CipherSpec`]/[`SqlCipherParams`] — plus
//! [`ProfileRegistry`], which scans the platform sub-directories and validates
//! each profile.
//! Used by: `decrypt::mod` (re-exports), the engine shim (matches an entry's path
//! to a profile, M4), and `decrypt::cipher` (consumes [`CipherSpec`]).
//! Uses: `serde`/`serde_yaml` for deserialisation (the same dependency the
//! behaviour presets use), `base64` + a hand-rolled hex decoder for
//! [`KeyEncoding::decode`], and `anyhow` for error context.
//!
//! Why external YAML: the set of supported apps and their cipher parameters drift
//! constantly (a new app, a new SQLCipher version). Keeping profiles as data —
//! editable in the field without recompiling — turns "add a target" into "add a
//! file". Platform is both a folder *and* an in-file field, validated to agree, so
//! a profile cannot be applied to the wrong acquisition type.
//!
//! Key acquisition is deliberately single-path: a profile's key is always located
//! in the supplied keychain/keystore dump by its [`KeychainMatch`] criteria. There
//! is no command-line key override — the examiner provides the dump, the profiles
//! handle the rest.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The mobile platform a profile targets.
///
/// Platform is authoritative for *which machinery applies* (iOS keychain +
/// SQLCipher vs. Android Keystore + app-specific ciphers), not mere labelling, so
/// it is a typed enum rather than a free string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    /// Lowercase tag, also the platform sub-directory name under `profiles/`.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }
}

/// How a profile selects the encrypted database file(s) inside the archive.
///
/// The agreed "db targeting" axis: a wildcard glob that auto-discovers every
/// matching entry, or one exact internal path. Modelled as an enum (not always a
/// glob) so a profile can pin a single known file when that is the intent.
///
/// Deserialised via [`DbBindingRaw`] (a `glob`/`path` map) rather than as a serde
/// enum: serde_yaml renders externally-tagged enums with `!Variant` YAML tags,
/// which would force an unfriendly `db: !glob "..."`. The intermediate keeps the
/// natural `db: { glob: "..." }` form and validates that exactly one is set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "DbBindingRaw")]
pub enum DbBinding {
    /// Wildcard glob (`*`/`?`, same flavour as `--path`) matched against an
    /// entry's internal path.
    Glob(String),
    /// One exact internal path.
    Path(String),
}

/// Wire form of [`DbBinding`]: a `glob`/`path` map, exactly one of which is set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DbBindingRaw {
    glob: Option<String>,
    path: Option<String>,
}

impl TryFrom<DbBindingRaw> for DbBinding {
    type Error = String;
    fn try_from(raw: DbBindingRaw) -> Result<Self, String> {
        match (raw.glob, raw.path) {
            (Some(g), None) => Ok(DbBinding::Glob(g)),
            (None, Some(p)) => Ok(DbBinding::Path(p)),
            (Some(_), Some(_)) => {
                Err("db must set exactly one of `glob` or `path`, not both".into())
            }
            (None, None) => Err("db must set one of `glob` or `path`".into()),
        }
    }
}

impl DbBinding {
    /// Whether an entry's internal `path` is the database this binding selects.
    ///
    /// A glob uses the same `*`/`?` semantics as `--path`/`--not-path` (one shared
    /// matcher); a path binding is an exact match.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            DbBinding::Glob(glob) => {
                crate::filter::wildcard_match(glob.as_bytes(), path.as_bytes())
            }
            DbBinding::Path(exact) => exact == path,
        }
    }
}

/// A hash used by SQLCipher for its KDF and/or its per-page HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// How the key material is encoded inside a secret's data bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyEncoding {
    /// The bytes are the derived key, used directly (no KDF).
    Raw,
    /// ASCII hex text that decodes to the derived key.
    Hex,
    /// Standard-alphabet base64 text that decodes to the derived key.
    Base64,
    /// The bytes are a passphrase; the decryptor runs the cipher's KDF over them.
    Passphrase,
}

/// Decoded key material handed to a decryptor.
///
/// The distinction matters to SQLCipher: a `Raw` key is used verbatim (the
/// `PRAGMA key = "x'...'"` form, no KDF), whereas a `Passphrase` is stretched
/// through PBKDF2 first. Carrying it as a typed enum keeps that decision explicit
/// rather than a boolean a decryptor might forget to honour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// A derived key, used directly without a KDF.
    Raw(Vec<u8>),
    /// A passphrase; the decryptor derives the key with its KDF.
    Passphrase(Vec<u8>),
}

impl KeyEncoding {
    /// Decode raw secret bytes into [`KeyMaterial`] per this encoding.
    pub fn decode(self, data: &[u8]) -> Result<KeyMaterial> {
        match self {
            KeyEncoding::Raw => Ok(KeyMaterial::Raw(data.to_vec())),
            KeyEncoding::Hex => Ok(KeyMaterial::Raw(decode_hex(data)?)),
            KeyEncoding::Base64 => {
                use base64::Engine;
                // Trim surrounding whitespace/newlines: dump formats often wrap a
                // base64 value, and the standard engine rejects stray whitespace.
                let trimmed = trim_ascii_ends(data);
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(trimmed)
                    .context("secret is not valid base64 for a base64-encoded key")?;
                Ok(KeyMaterial::Raw(bytes))
            }
            KeyEncoding::Passphrase => Ok(KeyMaterial::Passphrase(data.to_vec())),
        }
    }
}

/// Criteria for locating the key in a secret store.
///
/// Each field is optional; an unset field is a wildcard. A secret matches when
/// every *set* field equals the secret's corresponding field. Fields mirror the
/// iOS keychain attributes (`acct`, `svc`, `agrp`) plus a human `label` — the
/// common subset every dump format exposes (Android Keystore entries are mapped
/// onto the same shape by their loader).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KeychainMatch {
    /// Keychain account attribute (`acct`).
    pub account: Option<String>,
    /// Keychain service attribute (`svc`).
    pub service: Option<String>,
    /// Keychain access group (`agrp`).
    pub access_group: Option<String>,
    /// Human-readable label.
    pub label: Option<String>,
}

/// How a profile's key is located and decoded.
///
/// The key is always found in the supplied keychain/keystore dump by `keychain`'s
/// criteria; `encoding` says how to turn the located bytes into key material.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    /// How the located bytes are encoded.
    pub encoding: KeyEncoding,
    /// Keychain/keystore lookup criteria.
    pub keychain: KeychainMatch,
}

/// The cipher and its parameters.
///
/// Internally tagged on `algorithm` so a profile's `cipher` block names exactly
/// one scheme and supplies only that scheme's knobs. New schemes (WhatsApp
/// crypt14/15, …) are added as variants; the engine dispatches via
/// [`crate::decrypt::cipher::decrypt`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "algorithm", rename_all = "kebab-case")]
pub enum CipherSpec {
    /// SQLCipher (page-based AES-CBC + per-page HMAC). Covers Signal, Wickr, and
    /// most app databases keyed from the keychain.
    Sqlcipher(SqlCipherParams),
    /// WhatsApp crypt12/14 (AES-256-GCM over a zlib-compressed database, with the
    /// "backup encryption" key derivation and offset-guessed IV).
    WhatsappCrypt(WhatsappCryptParams),
}

/// WhatsApp crypt12/14 knobs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WhatsappCryptParams {
    /// Candidate IV offsets to try; the GCM tag confirms which is correct (the
    /// crypt14 header is a variable-length protobuf, so the IV offset is not fixed).
    #[serde(default = "default_iv_offsets")]
    pub iv_offsets: Vec<usize>,
    /// Whether the decrypted plaintext is zlib-compressed (true for crypt12/14).
    #[serde(default = "default_true")]
    pub zlib: bool,
}

/// Default candidate IV offsets for WhatsApp crypt files (the commonly observed
/// positions; the GCM tag rejects any wrong guess).
fn default_iv_offsets() -> Vec<usize> {
    vec![8, 51, 67, 191]
}

/// SQLCipher knobs that vary across apps and versions.
///
/// Defaults follow SQLCipher 4 (the current default, used by recent Signal
/// builds). Override per profile for SQLCipher 3 databases (`kdf_iter: 64000`,
/// `hmac`/`kdf: sha1`). `deny_unknown_fields` is intentionally **not** set: an
/// internally-tagged enum forwards the `algorithm` tag into this struct, which a
/// strict field check would wrongly reject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SqlCipherParams {
    /// Database page size in bytes (default 4096).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    /// PBKDF2 iteration count (default 256000 = SQLCipher 4).
    #[serde(default = "default_kdf_iter")]
    pub kdf_iter: u32,
    /// Per-page HMAC hash (default SHA-512 = SQLCipher 4).
    #[serde(default = "default_sha512")]
    pub hmac: HashAlgorithm,
    /// KDF PRF hash (default SHA-512 = SQLCipher 4).
    #[serde(default = "default_sha512")]
    pub kdf: HashAlgorithm,
    /// Whether pages carry an HMAC (default true). When false, no page auth.
    #[serde(default = "default_true")]
    pub use_hmac: bool,
    /// Bytes of cleartext header before the encrypted region; some apps prepend a
    /// custom header. 0 for a standard SQLCipher database.
    #[serde(default)]
    pub plaintext_header_size: usize,
}

fn default_page_size() -> usize {
    4096
}
fn default_kdf_iter() -> u32 {
    256_000
}
fn default_sha512() -> HashAlgorithm {
    HashAlgorithm::Sha512
}
fn default_true() -> bool {
    true
}

/// One decryption profile: an app's encrypted database, how to key it, and the
/// cipher to decrypt it with.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Stable identifier, also used in provenance (e.g. `"signal-ios"`).
    pub name: String,
    /// App display name (e.g. `"Signal"`).
    pub app: String,
    /// Platform this profile targets; must agree with its folder (validated on load).
    pub platform: Platform,
    /// One-line description, for help text and provenance.
    #[serde(default)]
    pub description: Option<String>,
    /// Which database file(s) the profile decrypts.
    pub db: DbBinding,
    /// How to locate and decode the key.
    pub key: KeySpec,
    /// The cipher and its parameters.
    pub cipher: CipherSpec,
}

impl Profile {
    /// Parse a single profile from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).context("invalid profile YAML")
    }
}

/// All profiles loaded from the `profiles/` directory.
#[derive(Debug, Default)]
pub struct ProfileRegistry {
    profiles: Vec<Profile>,
}

impl ProfileRegistry {
    /// Build a registry from an explicit list of profiles (used by tests).
    pub fn new(profiles: Vec<Profile>) -> Self {
        Self { profiles }
    }

    /// Load every profile under `dir/<platform>/*.yml`.
    ///
    /// HOW: walk one level of platform sub-directories (`ios/`, `android/`),
    /// parsing each `*.yml`/`*.yaml` whose name does not start with `_` (those are
    /// templates/examples). Top-level files (e.g. `profiles/_example.yml`) are not
    /// platforms and are skipped.
    ///
    /// WHY validate platform against the folder: a profile filed under the wrong
    /// platform folder would be applied to the wrong acquisition type, silently
    /// decrypting with the wrong machinery; we refuse it rather than guess.
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let mut profiles = Vec::new();
        for platform_entry in fs::read_dir(dir)
            .with_context(|| format!("cannot read profiles directory {}", dir.display()))?
        {
            let platform_path = platform_entry?.path();
            if !platform_path.is_dir() {
                continue;
            }
            let folder = platform_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            for file_entry in fs::read_dir(&platform_path)
                .with_context(|| format!("cannot read {}", platform_path.display()))?
            {
                let path = file_entry?.path();
                let is_yaml = path.extension().is_some_and(|e| {
                    e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml")
                });
                let is_template = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('_'));
                if !is_yaml || is_template {
                    continue;
                }
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("cannot read profile {}", path.display()))?;
                let profile = Profile::from_yaml(&text)
                    .with_context(|| format!("invalid profile {}", path.display()))?;
                if profile.platform.as_str() != folder {
                    bail!(
                        "profile {} declares platform '{}' but sits in the '{}/' folder",
                        path.display(),
                        profile.platform.as_str(),
                        folder
                    );
                }
                profiles.push(profile);
            }
        }
        Ok(Self { profiles })
    }

    /// Every loaded profile.
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Look up a profile by its `name`.
    pub fn by_name(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }
}

// --- Key decoding helpers ----------------------------------------------------

/// Decode ASCII hex (whitespace allowed) into bytes.
fn decode_hex(data: &[u8]) -> Result<Vec<u8>> {
    let digits: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    // An odd digit count cannot form whole bytes; refusing here turns a malformed
    // key into a clean error instead of a silently truncated one.
    if !digits.len().is_multiple_of(2) {
        bail!("hex key has an odd number of digits ({})", digits.len());
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Ok(out)
}

/// Value of one hex digit, or an error for a non-hex byte.
fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => bail!("invalid hex digit {:#04x} in key", other),
    }
}

/// Trim leading/trailing ASCII whitespace from a byte slice.
fn trim_ascii_ends(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|b| !b.is_ascii_whitespace());
    let end = data.iter().rposition(|b| !b.is_ascii_whitespace());
    match (start, end) {
        (Some(s), Some(e)) => &data[s..=e],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SIGNAL: &str = r#"
name: signal-ios
app: Signal
platform: ios
description: Signal iOS GRDB database.
db:
  glob: "*/grdb/signal.sqlite"
key:
  encoding: raw
  keychain:
    service: TSKeyChainService
    account: OWSDatabaseCipherKeySpec
cipher:
  algorithm: sqlcipher
  page_size: 4096
  kdf_iter: 256000
  hmac: sha512
"#;

    #[test]
    fn parses_a_full_profile() {
        let p = Profile::from_yaml(SIGNAL).unwrap();
        assert_eq!(p.name, "signal-ios");
        assert_eq!(p.platform, Platform::Ios);
        assert_eq!(p.db, DbBinding::Glob("*/grdb/signal.sqlite".into()));
        assert_eq!(p.key.encoding, KeyEncoding::Raw);
        assert_eq!(p.key.keychain.service.as_deref(), Some("TSKeyChainService"));
        assert_eq!(
            p.key.keychain.account.as_deref(),
            Some("OWSDatabaseCipherKeySpec")
        );
    }

    #[test]
    fn cipher_params_default_to_sqlcipher_v4() {
        // Only the algorithm given; every other knob takes its v4 default.
        let yaml = r#"
name: x
app: X
platform: android
db:
  path: a/b.db
key:
  encoding: passphrase
  keychain:
    service: svc
cipher:
  algorithm: sqlcipher
"#;
        let p = Profile::from_yaml(yaml).unwrap();
        assert_eq!(p.db, DbBinding::Path("a/b.db".into()));
        let CipherSpec::Sqlcipher(c) = &p.cipher else {
            unreachable!("this profile uses sqlcipher");
        };
        assert_eq!(c.page_size, 4096);
        assert_eq!(c.kdf_iter, 256_000);
        assert_eq!(c.hmac, HashAlgorithm::Sha512);
        assert_eq!(c.kdf, HashAlgorithm::Sha512);
        assert!(c.use_hmac);
        assert_eq!(c.plaintext_header_size, 0);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let yaml = r#"
name: x
app: X
platform: ios
db:
  path: a
key:
  encoding: raw
  keychain:
    service: svc
cipher:
  algorithm: sqlcipher
bogus: true
"#;
        assert!(Profile::from_yaml(yaml).is_err());
    }

    #[test]
    fn key_encoding_decodes_each_form() {
        assert_eq!(
            KeyEncoding::Raw.decode(&[1, 2, 3]).unwrap(),
            KeyMaterial::Raw(vec![1, 2, 3])
        );
        assert_eq!(
            KeyEncoding::Hex.decode(b"00ff 10").unwrap(),
            KeyMaterial::Raw(vec![0x00, 0xff, 0x10])
        );
        assert_eq!(
            KeyEncoding::Base64.decode(b"AAEC\n").unwrap(),
            KeyMaterial::Raw(vec![0, 1, 2])
        );
        assert_eq!(
            KeyEncoding::Passphrase.decode(b"hunter2").unwrap(),
            KeyMaterial::Passphrase(b"hunter2".to_vec())
        );
    }

    #[test]
    fn hex_rejects_odd_and_non_hex() {
        assert!(KeyEncoding::Hex.decode(b"abc").is_err()); // odd
        assert!(KeyEncoding::Hex.decode(b"zz").is_err()); // not hex
    }

    #[test]
    fn registry_loads_platform_folders_and_skips_templates() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("ios")).unwrap();
        fs::write(dir.path().join("ios/signal.yml"), SIGNAL).unwrap();
        // A template inside a platform folder is ignored.
        fs::write(dir.path().join("ios/_template.yml"), SIGNAL).unwrap();
        // A top-level file is not a platform folder and is ignored.
        fs::write(dir.path().join("_example.yml"), SIGNAL).unwrap();

        let reg = ProfileRegistry::from_dir(dir.path()).unwrap();
        assert_eq!(reg.profiles().len(), 1);
        assert!(reg.by_name("signal-ios").is_some());
    }

    #[test]
    fn registry_rejects_misfiled_platform() {
        let dir = tempdir().unwrap();
        // SIGNAL declares platform: ios but is placed under android/.
        fs::create_dir(dir.path().join("android")).unwrap();
        fs::write(dir.path().join("android/signal.yml"), SIGNAL).unwrap();
        assert!(ProfileRegistry::from_dir(dir.path()).is_err());
    }
}
