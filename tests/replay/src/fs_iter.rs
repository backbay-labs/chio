//! Deterministic filesystem enumeration with `LC_ALL=C`-equivalent
//! lexicographic byte ordering.
//!
//! Locale-aware sorting (the default for many filesystems and shells)
//! varies across hosts: macOS HFS+/APFS performs Unicode normalization
//! and case-folding, ext4 returns inode-creation order out of
//! `readdir(3)`, NTFS is case-insensitive. The replay-gate corpus must
//! enumerate identically on every machine; this module provides the
//! canonical ordering primitive for that.
//!
//! # Why byte order, not Unicode order
//!
//! `LC_ALL=C` directs every locale-aware POSIX call to fall back to
//! "the POSIX locale", which sorts strings by raw byte value. That is
//! the only ordering that is both well-defined across platforms and
//! cheap to compute. Anything Unicode-aware (UCA, NFC normalization,
//! locale-specific collation) would re-introduce the host-dependent
//! drift we are trying to eliminate.
//!
//! # Platform split
//!
//! On Unix-like targets the `OsStr` is already a sequence of bytes
//! (specifically `&[u8]` via `std::os::unix::ffi::OsStrExt`), so we
//! feed those bytes straight to the comparator. On non-Unix targets
//! the underlying representation is a sequence of `u16` code units
//! whose locale-free byte ordering is ill-defined; we fall back to
//! the lossy UTF-8 form and reject any path component that is not
//! valid UTF-8 with [`FsIterError::NonUtf8Path`]. The M04 corpus is
//! ASCII-only by construction, so this fallback never trips in
//! practice but stays fail-closed if it ever does.
//!
//! # Symlink handling
//!
//! Symbolic links are filtered out fail-closed during recursion:
//! [`walk_files_sorted`] uses `Metadata::file_type` (not
//! `symlink_metadata`) only for plain-file detection and explicitly
//! skips any entry whose `file_type().is_symlink()` returns true. A
//! symlink in the corpus would risk path-traversal nondeterminism we
//! have not vetted, so the policy is "skip during recursion, never
//! follow". [`read_dir_sorted`] does NOT filter symlinks (it returns
//! whatever `read_dir` produces, sorted) because its caller may want
//! to inspect the symlink entry directly; recursion-style callers
//! should always go through [`walk_files_sorted`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors produced while enumerating filesystem entries.
#[derive(Debug, Error)]
pub enum FsIterError {
    /// I/O error reading a directory or stat'ing an entry.
    #[error("io error reading {path}: {source}")]
    Io {
        /// Path that was being read or stat'd when the error occurred.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A path component was not valid UTF-8 on a non-Unix target.
    /// On Unix targets we sort by raw `OsStr` bytes and never produce
    /// this error. On Windows the `OsStr` is a sequence of `u16` code
    /// units; sorting those by raw byte order is ill-defined, so we
    /// fall back to the lossy UTF-8 form and reject any path that
    /// would otherwise have been silently re-encoded.
    #[error("non-utf8 path encountered while sorting: {0:?}")]
    NonUtf8Path(PathBuf),
}

/// Read directory contents and return them sorted by raw byte order
/// (`LC_ALL=C` semantics) on the entry's `OsStr` bytes.
///
/// The returned vector contains every immediate child of `dir`,
/// including subdirectories and symlinks; callers that want only
/// regular files should filter the result themselves or use
/// [`walk_files_sorted`].
///
/// # Errors
///
/// - [`FsIterError::Io`] if `dir` cannot be opened or any individual
///   directory entry cannot be read.
/// - [`FsIterError::NonUtf8Path`] on non-Unix targets only, if any
///   child name is not valid UTF-8.
pub fn read_dir_sorted(dir: impl AsRef<Path>) -> Result<Vec<PathBuf>, FsIterError> {
    let dir = dir.as_ref();
    let read = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(source) => {
            return Err(FsIterError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    };

    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(source) => {
                return Err(FsIterError::Io {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        };
        entries.push(entry.path());
    }

    sort_paths(&mut entries)?;
    Ok(entries)
}

/// Recursively enumerate every regular file under `root` for which
/// `accept(&path)` returns `true`, sorted by raw byte order
/// (`LC_ALL=C` semantics) across the whole tree.
///
/// Recursion is depth-first with directories visited in byte order
/// too, so the final flat list is the same total ordering a `find
/// <root> -type f | LC_ALL=C sort` invocation would produce.
/// Symbolic links are skipped fail-closed; see the module-level docs
/// for the rationale.
///
/// # Errors
///
/// - [`FsIterError::Io`] if any directory cannot be opened or any
///   entry cannot be stat'd.
/// - [`FsIterError::NonUtf8Path`] on non-Unix targets only, if any
///   path component is not valid UTF-8.
pub fn walk_files_sorted<F>(root: impl AsRef<Path>, accept: F) -> Result<Vec<PathBuf>, FsIterError>
where
    F: Fn(&Path) -> bool,
{
    let mut out: Vec<PathBuf> = Vec::new();
    walk_inner(root.as_ref(), &accept, &mut out)?;
    sort_paths(&mut out)?;
    Ok(out)
}

/// Internal recursive helper for [`walk_files_sorted`].
///
/// Visits `dir` in byte order, recurses into subdirectories in byte
/// order, and pushes any regular file that satisfies `accept` into
/// `out`. The final global sort happens once at the top level so the
/// result is correct even if the recursion happened to visit a
/// subtree out of order (it does not, but the post-sort makes the
/// invariant unconditional and trivial to audit).
fn walk_inner<F>(dir: &Path, accept: &F, out: &mut Vec<PathBuf>) -> Result<(), FsIterError>
where
    F: Fn(&Path) -> bool,
{
    let entries = read_dir_sorted(dir)?;
    for path in entries {
        // Use `symlink_metadata` so that a symlink to a directory does
        // not silently resolve to the target's file type. We then skip
        // any symlink fail-closed.
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(source) => {
                return Err(FsIterError::Io {
                    path: path.clone(),
                    source,
                });
            }
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk_inner(&path, accept, out)?;
        } else if ft.is_file() && accept(&path) {
            out.push(path);
        }
        // Anything else (sockets, FIFOs, block / char devices) is
        // ignored: the corpus is plain files only.
    }
    Ok(())
}

/// Sort a slice of paths in place by `LC_ALL=C`-equivalent raw byte
/// ordering on each path's *normalized* string form.
///
/// Used internally by [`read_dir_sorted`] and [`walk_files_sorted`]
/// after enumeration so a single comparator implementation governs
/// every ordering decision. Path components are joined with the
/// forward-slash separator (`/`) before sorting so the byte order of
/// the resulting key is platform-independent: a Windows host that
/// would otherwise hand the comparator backslashes (`\\` = 0x5c) and
/// a POSIX host that hands it forward slashes (`/` = 0x2f) produce
/// the same total order. Path components themselves are compared by
/// their raw byte form (Unix) or UTF-8 byte form (non-Unix), matching
/// `LC_ALL=C` semantics within each component.
fn sort_paths(paths: &mut [PathBuf]) -> Result<(), FsIterError> {
    // Pre-compute sort keys so we surface any [`FsIterError::NonUtf8Path`]
    // before mutating order, and so each path's key is computed once
    // even if `sort_by_key` would have called the closure multiple
    // times.
    let mut keyed: Vec<(Vec<u8>, PathBuf)> = Vec::with_capacity(paths.len());
    for p in paths.iter() {
        let key = sort_key(p)?;
        keyed.push((key, p.clone()));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for (i, (_, p)) in keyed.into_iter().enumerate() {
        paths[i] = p;
    }
    Ok(())
}

/// Produce the raw-byte sort key for a path under `LC_ALL=C`
/// semantics, with platform-independent separator normalization.
///
/// The key is constructed from `path.components()` so the OS-native
/// separator (`/` on Unix, `\\` on Windows) is replaced by an
/// explicit forward-slash join. That keeps `walk_files_sorted` total
/// order identical across hosts even when two paths differ at a
/// directory boundary (for example `a/x.json` vs `aA.json` would
/// otherwise sort differently on Windows because `\\` (0x5c) sorts
/// after `A` (0x41), inverting the cross-platform total order).
///
/// On Unix targets each `Component` is converted to bytes via
/// `OsStrExt::as_bytes`. On non-Unix targets we go via `to_str` and
/// return [`FsIterError::NonUtf8Path`] for any component that would
/// need lossy re-encoding (the M04 corpus is ASCII-only so the
/// non-Unix UTF-8 fallback is fail-closed in practice).
fn sort_key(path: &Path) -> Result<Vec<u8>, FsIterError> {
    use std::path::Component;

    let mut out: Vec<u8> = Vec::with_capacity(path.as_os_str().len());
    let mut first = true;
    for component in path.components() {
        if !first {
            // Use a single byte separator so the key is bit-stable
            // across platforms regardless of the host's path
            // separator. `/` (0x2f) is chosen because it appears in
            // POSIX paths verbatim already and never appears inside
            // a path component (POSIX forbids it; Windows treats it
            // as a separator too).
            out.push(b'/');
        }
        first = false;
        let raw = component.as_os_str();
        let comp_bytes = component_bytes(raw, path)?;
        out.extend_from_slice(&comp_bytes);
        // A `Component::RootDir` already contributed its bytes (e.g.
        // "/" on Unix, "\\" on Windows -> normalised to ""); skip the
        // following separator to avoid emitting "//".
        if matches!(component, Component::RootDir) {
            // The next component is the first real entry; do not
            // prepend a separator before it.
            first = true;
        }
    }
    Ok(out)
}

/// Convert a single [`Component`]'s [`OsStr`] into its byte-form key.
///
/// Mirrors the platform split used by the previous implementation but
/// operates per-component so the caller can interleave a fixed-byte
/// separator. `parent` is only used for diagnostic context in the
/// non-Unix `NonUtf8Path` error.
#[cfg(unix)]
fn component_bytes(raw: &std::ffi::OsStr, _parent: &Path) -> Result<Vec<u8>, FsIterError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(raw.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn component_bytes(raw: &std::ffi::OsStr, parent: &Path) -> Result<Vec<u8>, FsIterError> {
    match raw.to_str() {
        Some(s) => Ok(s.as_bytes().to_vec()),
        None => Err(FsIterError::NonUtf8Path(parent.to_path_buf())),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the deterministic fs-iteration primitives.
    //!
    //! Tests construct fixtures under [`tempfile::TempDir`] so the
    //! tests are hermetic and can run in parallel without colliding.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper: create an empty file at `dir.join(name)`.
    fn touch(dir: &Path, name: &str) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        let mut f = File::create(&p).expect("create file");
        // Write a byte so the file is not zero-length; some helpers
        // use file length as a sanity probe and we want this to be a
        // genuinely populated regular file.
        f.write_all(b"x").expect("write byte");
    }

    #[test]
    fn read_dir_sorted_returns_lexicographic_byte_order() {
        // Uppercase ASCII (0x41-0x5A) sorts before lowercase ASCII
        // (0x61-0x7A) under LC_ALL=C, and digits (0x30-0x39) sort
        // before both. So 0.txt < Z.txt < a.txt < b.txt.
        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "b.txt");
        touch(dir, "a.txt");
        touch(dir, "Z.txt");
        touch(dir, "0.txt");

        let got = read_dir_sorted(dir).unwrap();
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "0.txt".to_string(),
                "Z.txt".to_string(),
                "a.txt".to_string(),
                "b.txt".to_string(),
            ],
            "read_dir_sorted must produce LC_ALL=C byte-order ASCII",
        );
    }

    #[test]
    fn read_dir_sorted_handles_unicode() {
        // 'e' = 0x65, 'f' = 0x66, 'é' UTF-8 = 0xC3 0xA9. Byte order:
        // e.txt < f.txt < é.txt.
        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "\u{00e9}.txt");
        touch(dir, "e.txt");
        touch(dir, "f.txt");

        let got = read_dir_sorted(dir).unwrap();
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "e.txt".to_string(),
                "f.txt".to_string(),
                "\u{00e9}.txt".to_string(),
            ],
            "read_dir_sorted must put plain ASCII before multibyte UTF-8",
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_files_sorted_skips_symlinks() {
        use std::os::unix::fs::symlink;

        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "real.txt");
        // Create a symlink "link.txt" -> "real.txt" alongside it.
        symlink(dir.join("real.txt"), dir.join("link.txt")).expect("create symlink");

        let got = walk_files_sorted(dir, |_| true).unwrap();
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["real.txt".to_string()],
            "walk_files_sorted must filter out symlinks fail-closed",
        );
    }

    #[test]
    fn read_dir_sorted_returns_empty_on_empty_dir() {
        let td = TempDir::new().unwrap();
        let got = read_dir_sorted(td.path()).unwrap();
        assert!(got.is_empty(), "empty directory must yield empty Vec");
    }

    #[test]
    fn walk_files_sorted_recurses_in_byte_order() {
        // Layout:
        //   <root>/a/x.txt
        //   <root>/a/y.txt
        //   <root>/b/x.txt
        //   <root>/b/y.txt
        // Expected total order:
        //   a/x.txt, a/y.txt, b/x.txt, b/y.txt
        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "b/y.txt");
        touch(dir, "b/x.txt");
        touch(dir, "a/y.txt");
        touch(dir, "a/x.txt");

        let got = walk_files_sorted(dir, |_| true).unwrap();
        let rels: Vec<String> = got
            .iter()
            .map(|p| {
                p.strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            rels,
            vec![
                "a/x.txt".to_string(),
                "a/y.txt".to_string(),
                "b/x.txt".to_string(),
                "b/y.txt".to_string(),
            ],
            "walk_files_sorted must visit subtrees in byte order",
        );
    }

    #[test]
    fn walk_files_sorted_filters_via_predicate() {
        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "manifest.json");
        touch(dir, "notes.txt");
        touch(dir, "data.json");
        touch(dir, "readme.md");

        let got = walk_files_sorted(dir, |p| {
            p.extension().and_then(|e| e.to_str()) == Some("json")
        })
        .unwrap();
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["data.json".to_string(), "manifest.json".to_string()],
            "predicate must restrict to .json files in byte order",
        );
    }

    #[test]
    fn sort_key_uses_forward_slash_for_separator_independence() {
        // The sort key must use a fixed `/` separator (not the OS-native
        // path separator) so that the total order is identical across
        // POSIX (where the separator is `/` = 0x2f) and Windows (where
        // it is `\\` = 0x5c). If the comparator were to fall back to
        // the OS separator, the relative order of `a/x.json` vs
        // `aA.json` would flip between platforms because `/` (0x2f)
        // sorts BEFORE the uppercase letters but `\\` (0x5c) sorts
        // AFTER them.
        let path_a = PathBuf::from("a").join("x.json");
        let path_b = PathBuf::from("aA.json");
        let key_a = sort_key(&path_a).expect("sort_key must succeed");
        let key_b = sort_key(&path_b).expect("sort_key must succeed");
        // `a/x.json` < `aA.json` because '/' (0x2f) < 'A' (0x41) byte-wise.
        assert!(
            key_a < key_b,
            "expected {key_a:?} (a/x.json) < {key_b:?} (aA.json) under separator-normalised sort",
        );
        // The key must NOT contain a backslash, regardless of host.
        assert!(
            !key_a.contains(&b'\\'),
            "sort key must use `/` only, got {key_a:?}",
        );
    }

    #[test]
    fn walk_files_sorted_total_order_independent_of_separator() {
        // End-to-end check on a layout where the boundary character
        // matters: `a/x.json` must sort before `aA.json` because the
        // first divergent byte in the normalized key is `/` vs `A`,
        // and `/` (0x2f) < `A` (0x41). On Windows without
        // normalisation, `\\` (0x5c) > `A` would have flipped the
        // order.
        let td = TempDir::new().unwrap();
        let dir = td.path();
        touch(dir, "aA.json");
        touch(dir, "a/x.json");

        let got = walk_files_sorted(dir, |_| true).unwrap();
        let rels: Vec<String> = got
            .iter()
            .map(|p| {
                p.strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            rels,
            vec!["a/x.json".to_string(), "aA.json".to_string()],
            "walk_files_sorted total order must be separator-agnostic",
        );
    }

    #[test]
    fn read_dir_missing_path_returns_io_error() {
        let td = TempDir::new().unwrap();
        let missing = td.path().join("does-not-exist");
        let err = read_dir_sorted(&missing).expect_err("missing path must error");
        match err {
            FsIterError::Io { path, .. } => {
                assert_eq!(path, missing, "Io error must echo the requested path");
            }
            other => panic!("expected FsIterError::Io, got {other:?}"),
        }
    }
}
