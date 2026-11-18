//! Worked examples shown at the end of each command's help.
//!
//! Defines: one text constant per help screen.
//! Used by: `cli` (the `after_help` attributes on `Cli` and `Command`).
//! Uses: nothing; the test below parses every example with the real `Cli`.
//!
//! WHY a test parses them: an example that no longer runs is worse than none, because
//! it is what a new user copies first. Any line starting with `mf-scan ` must parse, so
//! renaming a flag fails the tests until the help is updated.
//!
//! Keep these few and short: the option list above them already names every parameter,
//! so an example earns its line only by showing a useful combination.

/// Shown by `mf-scan -h`.
pub(crate) const TOP: &str = "\
Examples:
  mf-scan grep -i 'secret' case.zip                     # search inside an archive
  mf-scan find case.zip -name '*.db' -size +1M          # list files, as with find
  mf-scan app export case.zip com.whatsapp.WhatsApp --to ./out --max-size 5G
  mf-scan diff before.zip after.zip --exact --inspect   # what changed, and inside what
  mf-scan backup rebuild backup.ab --to device.zip      # iOS or Android backup to a .zip

Every command has its own -h, ending in examples.";

/// Shown by `mf-scan grep -h`.
pub(crate) const GREP: &str = "\
Examples:
  mf-scan grep -in 'secret' notes.txt                   # any file, with line numbers
  mf-scan grep -o 'https?://[^ ]+' case.zip             # only the matched text
  mf-scan grep -e 'imei' -e 'imsi' ./extracted --dir-mode
  mf-scan grep '07700900000' case.zip --type database --inspect --fast
  mf-scan grep -F 'a@b.com' case.zip --all-encodings --keyfile keychain.plist
  mf-scan grep 'token' case.zip --path '*com.whatsapp*' --export ./out --max-size 5G

^ and $ match at each line; \\A and \\z at the file's start and end. Results are
path:0xOFFSET:line. Exit status: 0 match, 1 no match, 2 error or some files unsearched.";

/// Shown by `mf-scan find -h`.
pub(crate) const FIND: &str = "\
Examples:
  mf-scan find case.zip -name '*.db'                    # find's own spellings work
  mf-scan find case.zip --iname 'sms*' --type f --long
  mf-scan find case.zip --type sqlite --size +1M --not-path '*/Caches/*'
  mf-scan find ./extracted --newer 2026-01-01 --older 2026-02-01
  mf-scan find case.zip --path '*com.whatsapp*' --export ./out --max-size 5G

Different tests must all hold; repeating one means either. Only --type with a format
reads file contents. Exit status: 0 even with no results, as find; 2 on error.";

/// Shown by `mf-scan export -h`.
pub(crate) const EXPORT: &str = "\
Examples:
  mf-scan grep 'token' case.zip --manifest hits.json    # review the list first
  mf-scan export case.zip --from-manifest hits.json --to ./out --max-size 5G --verify";

/// Shown by `mf-scan diff -h`.
pub(crate) const DIFF: &str = "\
Examples:
  mf-scan diff before.zip after.zip                     # fast: size and time
  mf-scan diff before.zip after.zip --exact --inspect   # content, and what changed inside
  mf-scan diff ./before ./after --dir-mode --exact --export ./changed";

/// Shown by `mf-scan app -h`.
pub(crate) const APP: &str = "\
Examples:
  mf-scan app list whatsapp case.zip                    # list apps, optionally filtered
  mf-scan app paths com.whatsapp.WhatsApp case.zip      # everywhere it keeps data
  mf-scan app export com.whatsapp.WhatsApp case.zip --to ./out --max-size 5G";

/// Shown by `mf-scan backup -h`.
pub(crate) const BACKUP: &str = "\
Examples:
  mf-scan backup info ./iphone-backup                   # what is it? writes nothing
  mf-scan backup rebuild ./iphone-backup --to device.zip
  mf-scan backup rebuild phone.ab --to device.zip --backup-password 'secret'

Output is always one .zip, so long device paths work on Windows too. It keeps the
device's timestamps and holds its own report; a .sha256 file is written beside it.";

/// Examples for `decrypt`.
pub(crate) const DECRYPT: &str = "\
Examples:
  mf-scan decrypt case.zip                         # what decrypts? writes nothing
  mf-scan decrypt case.zip --to case.decrypted.zip # case.zip + decrypted copies
  mf-scan decrypt case.zip --keyfile keychain.plist --to out.zip

  A keychain/keystore dump beside the source (*keychain*, *keystore*, zipped or
  not) is found on its own. Each copy is name.decrypted.ext beside its original;
  _mf-scan/decryption.json lists them with hashes and how each was decrypted.
  To get decrypted copies in a folder instead: find/grep/app export --export.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::cli::find::normalise_find_args;
    use clap::Parser;
    use std::ffi::OsString;

    use crate::cmd::cli::Cli;

    /// Split a shell-style example line: single quotes group, and `#` outside quotes
    /// starts a comment. Enough for these examples, which use nothing else.
    fn shell_split(line: &str) -> Vec<OsString> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quoted = false;
        for c in line.chars() {
            match c {
                '\'' => quoted = !quoted,
                '#' if !quoted => break,
                c if c.is_whitespace() && !quoted => {
                    if !word.is_empty() {
                        words.push(OsString::from(std::mem::take(&mut word)));
                    }
                }
                c => word.push(c),
            }
        }
        if !word.is_empty() {
            words.push(OsString::from(word));
        }
        words
    }

    #[test]
    fn every_example_parses() {
        let mut checked = 0;
        for text in [TOP, GREP, FIND, EXPORT, DIFF, APP, BACKUP] {
            for line in text.lines().map(str::trim) {
                if line.starts_with("mf-scan ") {
                    let args = normalise_find_args(shell_split(line));
                    if let Err(err) = Cli::try_parse_from(args) {
                        panic!("help example does not parse: {line}\n{err}");
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 20, "only {checked} examples were found");
    }
}
