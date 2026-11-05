//! End-to-end tests of the `mf-scan` binary's grep-facing behaviour.
//!
//! Defines: tests that run the real binary and assert on its exit status, stdout,
//! and the files it leaves behind.
//! Used by: `cargo test`.
//! Uses: `common` (fixture ZIP builder), `tempfile`, and the binary Cargo builds.
//!
//! WHY through the binary: these behaviours live where argument parsing, the regex
//! build, and the exit status meet, so a library-level test would not cover them.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use common::{FileSpec, build_zip};
use tempfile::{TempDir, tempdir};

/// A working directory holding `case.zip`, with a text file and a binary file.
fn case_dir() -> TempDir {
    let dir = tempdir().expect("tempdir");
    let zip = build_zip(
        &[
            FileSpec::stored("a.txt", b"hello world\nbye Hello\nfoo end\n"),
            FileSpec::stored("win.txt", b"carriage end\r\nnext\r\n"),
            FileSpec::stored("bin.dat", b"bin\x00\x1b[31mhello\xff tail\n"),
        ],
        false,
    );
    fs::write(dir.path().join("case.zip"), zip).expect("write zip");
    dir
}

/// Run `mf-scan` in `cwd`.
fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run mf-scan")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The scan reports in `dir`.
fn reports(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("report"))
        .collect()
}

#[test]
fn line_anchors_match_at_each_line_like_grep() {
    let dir = case_dir();
    let start = run(dir.path(), &["grep", "^bye", "case.zip", "--no-report"]);
    assert_eq!(stdout(&start), "a.txt:0xc:bye Hello\n");

    let end = run(dir.path(), &["grep", "world$", "case.zip", "--no-report"]);
    assert_eq!(stdout(&end), "a.txt:0x6:hello world\n");

    // Windows line endings must not hide a match at the end of a line.
    let crlf = run(
        dir.path(),
        &["grep", "carriage end$", "case.zip", "--no-report"],
    );
    assert_eq!(stdout(&crlf), "win.txt:0x0:carriage end\n");

    // The whole-file anchor remains available.
    let file_start = run(dir.path(), &["grep", r"\Abye", "case.zip", "--no-report"]);
    assert_eq!(stdout(&file_start), "");
}

#[test]
fn exit_status_follows_grep() {
    let dir = case_dir();
    let code = |args: &[&str]| run(dir.path(), args).status.code();

    assert_eq!(code(&["grep", "hello", "case.zip", "--no-report"]), Some(0));
    assert_eq!(
        code(&["grep", "absent", "case.zip", "--no-report"]),
        Some(1)
    );
    assert_eq!(
        code(&["grep", "-c", "absent", "case.zip", "--no-report"]),
        Some(1)
    );
    assert_eq!(
        code(&["grep", "-l", "absent", "case.zip", "--no-report"]),
        Some(1)
    );
    assert_eq!(
        code(&["grep", "--match-path", "a\\.txt", "case.zip", "--no-report"]),
        Some(0)
    );
    assert_eq!(
        code(&["grep", "--match-path", "absent", "case.zip", "--no-report"]),
        Some(1)
    );
    // Errors: a bad regex, a missing source, a usage mistake.
    assert_eq!(code(&["grep", "[bad", "case.zip", "--no-report"]), Some(2));
    assert_eq!(code(&["grep", "x", "missing.zip", "--no-report"]), Some(2));
    assert_eq!(code(&["grep"]), Some(2));
}

/// A file that could not be read must not let a run claim "searched and absent".
#[cfg(unix)]
#[test]
fn unreadable_file_means_error_status_even_with_a_match() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("tempdir");
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("mkdir");
    fs::write(tree.join("ok.txt"), "hello\n").expect("write");
    let locked = tree.join("locked.txt");
    fs::write(&locked, "hello\n").expect("write");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&locked).is_ok() {
        return; // Running as root: permissions are not enforced, nothing to test.
    }

    let output = run(
        dir.path(),
        &["grep", "hello", "tree", "--dir-mode", "--no-report"],
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).expect("chmod");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("ok.txt"),
        "the match is still shown"
    );
}

#[test]
fn dash_l_lists_files_and_dash_f_upper_means_literal() {
    let dir = case_dir();
    let listed = run(
        dir.path(),
        &["grep", "-l", "hello", "case.zip", "--no-report"],
    );
    assert_eq!(stdout(&listed), "a.txt\nbin.dat\n");

    let regex = run(
        dir.path(),
        &["grep", "-l", "hel+o", "case.zip", "--no-report"],
    );
    assert_eq!(
        stdout(&regex),
        "a.txt\nbin.dat\n",
        "-l keeps regex matching"
    );

    let literal = run(
        dir.path(),
        &["grep", "-F", "hel+o", "case.zip", "--no-report"],
    );
    assert_eq!(literal.status.code(), Some(1), "-F takes + literally");
}

#[test]
fn dash_l_can_still_export() {
    let dir = case_dir();
    let output = run(
        dir.path(),
        &[
            "grep",
            "-l",
            "world",
            "case.zip",
            "--export",
            "out",
            "--no-report",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(dir.path().join("out/export-report.json").exists());
}

#[test]
fn dash_o_shows_only_the_match_and_writes_no_file() {
    let dir = case_dir();
    let output = run(
        dir.path(),
        &["grep", "-o", "hel+o", "case.zip", "--no-report"],
    );
    // Readable match in a binary line is shown, without the binary around it.
    assert_eq!(stdout(&output), "a.txt:0x0:hello\nbin.dat:0x9:hello\n");
    assert!(!dir.path().join("hel+o").exists());

    // Empty matches print nothing, as in grep -o.
    let empty = run(dir.path(), &["grep", "-o", "z*", "case.zip", "--no-report"]);
    assert_eq!(stdout(&empty), "");

    let json = run(
        dir.path(),
        &["grep", "-o", "x", "case.zip", "-f", "json", "--no-report"],
    );
    assert_eq!(
        json.status.code(),
        Some(2),
        "a silently ignored -o is rejected"
    );
}

#[test]
fn output_is_now_long_form_only() {
    let dir = case_dir();
    let output = run(
        dir.path(),
        &[
            "grep",
            "world",
            "case.zip",
            "--output",
            "hits.txt",
            "--no-report",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        fs::read_to_string(dir.path().join("hits.txt")).expect("output file"),
        "a.txt:0x6:hello world\n"
    );
}

#[test]
fn recursive_reports_the_loose_files_it_skips() {
    let dir = case_dir();
    fs::write(dir.path().join("loose.txt"), "hello\n").expect("write");

    let output = run(
        dir.path(),
        &["grep", "-r", "hello", ".", "--report", "r.json"],
    );
    assert!(
        stderr(&output).contains("1 loose file(s) NOT searched"),
        "{}",
        stderr(&output)
    );
    assert!(!stdout(&output).contains("loose.txt"));
    let report = fs::read_to_string(dir.path().join("r.json")).expect("report");
    assert!(report.contains(r#""loose_files_skipped": 1"#), "{report}");

    // Nothing but loose files: an error that says what to do instead.
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("mkdir");
    fs::write(tree.join("l.txt"), "hello\n").expect("write");
    let none = run(dir.path(), &["grep", "-r", "hello", "tree", "--no-report"]);
    assert_eq!(none.status.code(), Some(2));
    assert!(stderr(&none).contains("--dir-mode"), "{}", stderr(&none));

    // A clean run does not mention it, in the report or on screen.
    let clean = run(
        dir.path(),
        &["grep", "hello", "case.zip", "--report", "c.json"],
    );
    assert!(!stderr(&clean).contains("NOT searched"));
    let report = fs::read_to_string(dir.path().join("c.json")).expect("report");
    assert!(!report.contains("loose_files_skipped"), "{report}");
}

#[test]
fn default_reports_never_overwrite_each_other() {
    let dir = case_dir();
    // Same second is likely here, which is the case the suffix exists for.
    for _ in 0..3 {
        run(dir.path(), &["grep", "hello", "case.zip"]);
    }
    let names = reports(dir.path());
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("mf-scan-report-") && n.ends_with(".json"))
    );

    // Beside --output, keeping the pairing visible.
    run(
        dir.path(),
        &["grep", "hello", "case.zip", "--output", "hits.txt"],
    );
    assert!(
        reports(dir.path())
            .iter()
            .any(|n| n.starts_with("hits.txt.") && n.ends_with(".report.json"))
    );

    // A path named with --report is the operator's choice: replaced, not multiplied.
    for _ in 0..2 {
        run(
            dir.path(),
            &["grep", "hello", "case.zip", "--report", "mine.json"],
        );
    }
    assert_eq!(
        reports(dir.path()).len(),
        4,
        "the named report adds no file because its name holds no \"report\""
    );
    assert!(dir.path().join("mine.json").exists());
}

#[cfg(unix)]
#[test]
fn unwritable_report_location_warns_unless_named() {
    use std::os::unix::fs::PermissionsExt;

    let dir = case_dir();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).expect("mkdir");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).expect("chmod");
    if fs::write(locked.join("probe"), "x").is_ok() {
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("chmod");
        return; // Running as root: permissions are not enforced, nothing to test.
    }

    let warned = run(&locked, &["grep", "world", "../case.zip"]);
    let named = run(
        &locked,
        &["grep", "world", "../case.zip", "--report", "r.json"],
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("chmod");

    assert_eq!(warned.status.code(), Some(0), "{}", stderr(&warned));
    assert!(stderr(&warned).contains("scan report NOT written"));
    assert_eq!(stdout(&warned), "a.txt:0x6:hello world\n");

    assert_eq!(
        named.status.code(),
        Some(2),
        "a named report is an obligation"
    );
}

#[cfg(unix)]
#[test]
fn closed_pipe_is_not_an_error_and_the_report_is_still_written() {
    use std::io::Read;
    use std::process::Stdio;

    let dir = tempdir().expect("tempdir");
    let many = "hello\n".repeat(90_000);
    fs::write(
        dir.path().join("big.zip"),
        build_zip(&[FileSpec::stored("big.txt", many.as_bytes())], false),
    )
    .expect("write zip");

    let mut child = Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(dir.path())
        .args(["grep", "hello", "big.zip", "--report", "r.json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Like `| head -1`: read a little, then close our end of the pipe.
    let mut out = child.stdout.take().expect("stdout");
    let mut first = [0u8; 16];
    out.read_exact(&mut first).expect("read");
    drop(out);

    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("scan statistics"));
    assert!(dir.path().join("r.json").exists());
}

#[test]
fn stats_are_on_by_default_and_can_be_skipped() {
    let dir = case_dir();
    let default = run(dir.path(), &["grep", "world", "case.zip", "--no-report"]);
    assert!(stderr(&default).contains("scan statistics"));

    let quiet = run(
        dir.path(),
        &["grep", "world", "case.zip", "--no-report", "--no-stats"],
    );
    assert_eq!(stderr(&quiet), "", "nothing but results");
    assert_eq!(stdout(&quiet), "a.txt:0x6:hello world\n");
    assert_eq!(quiet.status.code(), Some(0));
}

/// Skipping the summary must not hide that part of the source went unsearched.
#[cfg(unix)]
#[test]
fn no_stats_still_reports_files_it_could_not_search() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("tempdir");
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).expect("mkdir");
    let locked = tree.join("locked.txt");
    fs::write(&locked, "hello\n").expect("write");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&locked).is_ok() {
        return; // Running as root: permissions are not enforced, nothing to test.
    }

    let output = run(
        dir.path(),
        &[
            "grep",
            "hello",
            "tree",
            "--dir-mode",
            "--no-report",
            "--no-stats",
        ],
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).expect("chmod");

    assert!(
        stderr(&output).contains("NOT searched"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("scan statistics"));
    assert_eq!(output.status.code(), Some(2));
}

/// Run with `input` on standard input.
fn run_with_stdin(cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

#[test]
fn dash_n_numbers_lines_and_keeps_the_offset() {
    let dir = case_dir();
    let output = run(
        dir.path(),
        &["grep", "-n", "bye", "case.zip", "--no-report"],
    );
    assert_eq!(stdout(&output), "a.txt:2:0xc:bye Hello\n");

    // Counting continues correctly across several matches in one file.
    let many = run(
        dir.path(),
        &[
            "grep",
            "-n",
            "o",
            "case.zip",
            "--path",
            "a.txt",
            "--no-report",
            "--no-stats",
        ],
    );
    let lines: Vec<&str> = stdout(&many)
        .lines()
        .map(|l| l.split(':').nth(1).unwrap())
        .map(|n| {
            if n == "1" {
                "1"
            } else if n == "2" {
                "2"
            } else {
                "3"
            }
        })
        .collect();
    assert_eq!(lines, ["1", "1", "2", "3", "3"]);
}

#[test]
fn dash_w_matches_whole_words_even_around_punctuation() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("w.txt"), "cat concat cat2 +33 x+33\n").expect("write");
    let hits = |pattern: &str| {
        let output = run(
            dir.path(),
            &[
                "grep",
                "-w",
                "-o",
                pattern,
                "w.txt",
                "--no-report",
                "--no-stats",
            ],
        );
        stdout(&output).lines().count()
    };
    assert_eq!(hits("cat"), 1, "not concat, not cat2");
    // `\b` alone could never match here: `+` is not a word character.
    assert_eq!(run_count_literal(dir.path(), "+33"), 1, "not x+33");
    assert_eq!(hits("ca"), 0);
}

fn run_count_literal(dir: &Path, pattern: &str) -> usize {
    let output = run(
        dir,
        &[
            "grep",
            "-w",
            "-F",
            "-o",
            pattern,
            "w.txt",
            "--no-report",
            "--no-stats",
        ],
    );
    stdout(&output).lines().count()
}

#[test]
fn dash_e_searches_several_patterns_and_treats_the_rest_as_sources() {
    let dir = case_dir();
    let output = run(
        dir.path(),
        &[
            "grep",
            "-o",
            "-e",
            "world",
            "-e",
            "bye",
            "case.zip",
            "--no-report",
            "--no-stats",
        ],
    );
    assert_eq!(stdout(&output), "a.txt:0x6:world\na.txt:0xc:bye\n");

    // One pattern's flags stay its own.
    let scoped = run(
        dir.path(),
        &[
            "grep",
            "-o",
            "-e",
            "(?i)HELLO WORLD",
            "-e",
            "BYE",
            "case.zip",
            "--no-report",
            "--no-stats",
        ],
    );
    assert_eq!(stdout(&scoped), "a.txt:0x0:hello world\n");

    let report = run(
        dir.path(),
        &[
            "grep",
            "-e",
            "world",
            "-e",
            "bye",
            "case.zip",
            "--report",
            "r.json",
            "--no-stats",
        ],
    );
    assert_eq!(report.status.code(), Some(0));
    let record = fs::read_to_string(dir.path().join("r.json")).expect("report");
    assert!(record.contains(r#""pattern": "world | bye""#), "{record}");
}

#[test]
fn dash_q_prints_nothing_and_leaves_no_file() {
    let dir = case_dir();
    let found = run(dir.path(), &["grep", "-q", "hello", "case.zip"]);
    assert_eq!(found.status.code(), Some(0));
    assert_eq!(stdout(&found), "");
    assert_eq!(stderr(&found), "");
    assert!(reports(dir.path()).is_empty());

    let absent = run(dir.path(), &["grep", "-q", "absent", "case.zip"]);
    assert_eq!(absent.status.code(), Some(1));
}

#[test]
fn a_loose_file_is_searched_as_itself_and_a_damaged_archive_still_fails() {
    let dir = case_dir();
    fs::write(dir.path().join("notes.txt"), "one\nneedle two\n").expect("write");
    let output = run(
        dir.path(),
        &[
            "grep",
            "-n",
            "needle",
            "notes.txt",
            "--no-report",
            "--no-stats",
        ],
    );
    assert_eq!(stdout(&output), "notes.txt:2:0x4:needle two\n");

    // Named as an archive but not one: this must fail, not be searched as a blob.
    fs::write(dir.path().join("broken.zip"), "needle").expect("write");
    let broken = run(dir.path(), &["grep", "needle", "broken.zip", "--no-report"]);
    assert_eq!(broken.status.code(), Some(2));
    assert_eq!(stdout(&broken), "");

    // The content decides: a ZIP named like anything is still opened as a ZIP.
    fs::copy(dir.path().join("case.zip"), dir.path().join("evidence.dat")).expect("copy");
    let renamed = run(
        dir.path(),
        &["grep", "world", "evidence.dat", "--no-report", "--no-stats"],
    );
    assert_eq!(stdout(&renamed), "a.txt:0x6:hello world\n");
}

#[test]
fn standard_input_is_searched_by_dash_or_by_default() {
    let dir = tempdir().expect("tempdir");
    for args in [
        &["grep", "needle", "-", "--no-report", "--no-stats"][..],
        &["grep", "needle", "--no-report", "--no-stats"][..],
    ] {
        let output = run_with_stdin(dir.path(), args, b"hay\nneedle\n");
        assert_eq!(stdout(&output), "(standard input):0x4:needle\n");
        assert_eq!(output.status.code(), Some(0));
    }
    let absent = run_with_stdin(dir.path(), &["grep", "needle", "--no-report"], b"hay\n");
    assert_eq!(absent.status.code(), Some(1));
    assert!(stderr(&absent).contains("reading standard input"));
}

#[test]
fn find_takes_finds_own_spellings_and_lists_quietly() {
    let dir = case_dir();
    let output = run(dir.path(), &["find", "case.zip", "-name", "*.txt"]);
    assert_eq!(stdout(&output), "a.txt\nwin.txt\n");
    assert_eq!(stderr(&output), "", "a listing has no summary");
    assert!(reports(dir.path()).is_empty(), "and leaves no file");

    let negated = run(
        dir.path(),
        &["find", "case.zip", "!", "-name", "*.txt", "-type", "f"],
    );
    assert_eq!(stdout(&negated), "bin.dat\n");

    let flags = run(
        dir.path(),
        &["find", "case.zip", "--iname", "A.TXT", "--long"],
    );
    let line = stdout(&flags);
    let fields: Vec<&str> = line.trim_end().split('\t').collect();
    assert_eq!(fields[0], "f");
    assert_eq!(fields[1], "30");
    assert_eq!(fields[3], "a.txt");

    // As with find, no results is not an error, but a bad argument is.
    let none = run(dir.path(), &["find", "case.zip", "-name", "*.nothing"]);
    assert_eq!(none.status.code(), Some(0));
    assert_eq!(stdout(&none), "");
    let bad = run(dir.path(), &["find", "case.zip", "-size", "ten"]);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn find_walks_a_folder_without_being_told_and_exports_what_it_finds() {
    let dir = tempdir().expect("tempdir");
    let tree = dir.path().join("tree/Library/SMS");
    fs::create_dir_all(&tree).expect("mkdir");
    fs::write(tree.join("sms.db"), "SQLite format 3\0").expect("write");
    fs::write(tree.join("note.txt"), "text").expect("write");

    let dirs = run(dir.path(), &["find", "tree", "-type", "d"]);
    assert_eq!(stdout(&dirs), "Library\nLibrary/SMS\n");

    let by_format = run(
        dir.path(),
        &["find", "tree", "--type", "sqlite", "--export", "out"],
    );
    assert_eq!(stdout(&by_format), "Library/SMS/sms.db\n");
    assert!(dir.path().join("out/export-report.json").exists());
}

/// One help screen per command: `--help` adds nothing to `-h`.
#[test]
fn help_and_short_help_are_the_same_screen() {
    let dir = tempdir().expect("tempdir");
    for command in [
        &[][..],
        &["grep"],
        &["find"],
        &["export"],
        &["diff"],
        &["app"],
        &["app", "grep"],
        &["app", "paths"],
        &["app", "export"],
        &["backup"],
        &["backup", "info"],
        &["backup", "rebuild"],
    ] {
        let with = |flag: &'static str| {
            let mut args = command.to_vec();
            args.push(flag);
            stdout(&run(dir.path(), &args))
        };
        let short = with("-h");
        assert!(!short.is_empty(), "{command:?}");
        assert_eq!(short, with("--help"), "{command:?}");
    }
}
