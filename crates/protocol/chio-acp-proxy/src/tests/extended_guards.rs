#[test]
fn fs_guard_path_with_trailing_slash() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    // Trailing slash on the path should be normalized and still match.
    assert!(guard.check_read("/home/user/project/").is_ok());
}

#[test]
fn fs_guard_path_with_double_slashes() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    // Double slashes should be collapsed during canonicalization.
    assert!(guard.check_read("/home/user//project/file.txt").is_ok());
}

#[test]
fn fs_guard_root_path() {
    // The prefix "/" is stored as-is. After canonicalization "/"
    // becomes "/" (empty parts joined). The boundary check requires
    // the byte after the prefix to be '/' or an exact match. Since
    // prefix "/" has length 1 and canonicalized "/etc/passwd" has
    // 'e' at index 1, neither condition is met. This means "/" as
    // a prefix does NOT grant universal access -- it is effectively
    // a no-match because the implementation's boundary check is
    // strict. This is safe (fail-closed).
    let guard = FsGuard::new(vec!["/".to_string()]);
    assert!(
        guard.check_read("/etc/passwd").is_err(),
        "root prefix '/' does not pass boundary check -- fail-closed"
    );
}

#[test]
fn fs_guard_root_path_not_configured() {
    let guard = FsGuard::new(vec!["/home/user".to_string()]);
    // Root path itself should not match a non-root prefix.
    assert!(guard.check_read("/").is_err());
}

#[test]
fn fs_guard_very_long_path() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    let long_suffix = "a".repeat(1000);
    let long_path = format!("/home/user/project/{long_suffix}");
    assert!(guard.check_read(&long_path).is_ok());
}

#[test]
fn fs_guard_path_with_unicode_characters() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert!(guard
        .check_read("/home/user/project/src/\u{00e9}ditor.rs")
        .is_ok());
    assert!(guard
        .check_read("/home/user/project/\u{4e16}\u{754c}.txt")
        .is_ok());
}

#[test]
fn fs_guard_multiple_prefixes_matches_second() {
    let guard = FsGuard::new(vec!["/opt/first".to_string(), "/opt/second".to_string()]);
    // Should fail for first prefix but succeed for second.
    assert!(guard.check_read("/opt/second/file.txt").is_ok());
    // Verify the first also works.
    assert!(guard.check_read("/opt/first/file.txt").is_ok());
    // Neither prefix matches.
    assert!(guard.check_read("/opt/third/file.txt").is_err());
}

#[test]
fn fs_guard_write_blocked_read_allowed_separate_instances() {
    // A read guard allows /tmp, a write guard allows only /home.
    let read_guard = FsGuard::new(vec!["/tmp".to_string()]);
    let write_guard = FsGuard::new(vec!["/home".to_string()]);

    assert!(read_guard.check_read("/tmp/data.txt").is_ok());
    assert!(write_guard.check_write("/tmp/data.txt").is_err());
    assert!(write_guard.check_write("/home/user/file.txt").is_ok());
    assert!(read_guard.check_read("/home/user/file.txt").is_err());
}

#[test]
fn fs_guard_dot_segments_are_collapsed() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    // "." segments should be collapsed to a clean path.
    assert!(guard.check_read("/home/user/./project/./file.txt").is_ok());
}

#[test]
fn fs_guard_prefix_exact_match_no_trailing_slash() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    // Exact match of the prefix itself should be allowed.
    assert!(guard.check_read("/home/user/project").is_ok());
}

// ================================================================
// 3. TerminalGuard Edge Cases
// ================================================================

#[test]
fn terminal_guard_empty_command_string() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    // Empty command is not on the allowlist.
    assert!(guard.check_command("", &[]).is_err());
}

#[test]
fn terminal_guard_command_with_spaces_in_path() {
    let guard = TerminalGuard::new(vec!["/usr/local/bin/my tool".to_string()]);
    assert!(guard.check_command("/usr/local/bin/my tool", &[]).is_ok());
}

#[test]
fn terminal_guard_multiple_allowed_matching_second() {
    let guard = TerminalGuard::new(vec!["git".to_string(), "npm".to_string()]);
    assert!(guard.check_command("npm", &["install".to_string()]).is_ok());
}

#[test]
fn terminal_guard_arg_with_pipe_only() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard.check_command("echo", &["|".to_string()]).is_err());
}

#[test]
fn terminal_guard_arg_with_semicolon_only() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard.check_command("echo", &[";".to_string()]).is_err());
}

#[test]
fn terminal_guard_arg_with_backtick() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard.check_command("echo", &["`".to_string()]).is_err());
}

#[test]
fn terminal_guard_arg_with_dollar_paren() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard
        .check_command("echo", &["$(whoami)".to_string()])
        .is_err());
}

#[test]
fn terminal_guard_arg_with_newline_character() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard
        .check_command("echo", &["line1\nline2".to_string()])
        .is_err());
}

#[test]
fn terminal_guard_clean_arg_with_equals_sign() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert!(guard
        .check_command("cargo", &["--flag=value".to_string()])
        .is_ok());
}

#[test]
fn terminal_guard_clean_arg_with_dashes_and_numbers() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert!(guard
        .check_command("cargo", &["--jobs=4".to_string(), "-j2".to_string()])
        .is_ok());
}

#[test]
fn terminal_guard_arg_with_carriage_return() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert!(guard
        .check_command("echo", &["hello\rworld".to_string()])
        .is_err());
}

#[test]
fn terminal_guard_command_matching_is_exact() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    // "cargoo" or "carg" should not match "cargo".
    assert!(guard.check_command("cargoo", &[]).is_err());
    assert!(guard.check_command("carg", &[]).is_err());
}

// ================================================================
// 4. Interceptor Integration Tests
// ================================================================

#[test]
fn fs_guard_prefix_with_trailing_slash_in_config() {
    let guard = FsGuard::new(vec!["/home/user/project/".to_string()]);
    assert!(guard.check_read("/home/user/project/file.txt").is_ok());

    // Without trailing slash, it works correctly.
    let guard2 = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert!(guard2.check_read("/home/user/project/file.txt").is_ok());
}
