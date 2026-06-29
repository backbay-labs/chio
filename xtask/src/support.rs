use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::XtaskError;

pub(crate) fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext.eq_ignore_ascii_case("json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

/// Walk `dir` recursively, collecting every `*.schema.json` file. Mirrors
/// the schema discovery in `chio_spec_codegen::walk_schema_files` so the
/// Rust and TS targets see an identical input set.
pub(crate) fn walk_schema_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_schema_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(name) = path.file_name().and_then(OsStr::to_str) {
                if name.ends_with(".schema.json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn digest_to_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Lower-case hex, two chars per byte, matches `shasum -a 256` output.
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

pub(crate) fn workspace_root() -> Result<PathBuf, XtaskError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut here = PathBuf::from(manifest_dir);
    if !here.pop() {
        return Err(XtaskError::Usage(format!(
            "could not derive workspace root from CARGO_MANIFEST_DIR={manifest_dir}"
        )));
    }
    Ok(here)
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string()
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), XtaskError> {
    fs::create_dir_all(dst).map_err(|err| XtaskError::Io(display_path(dst), err))?;
    let entries = fs::read_dir(src).map_err(|err| XtaskError::Io(display_path(src), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(src), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let Some(name) = path.file_name() else {
            continue;
        };
        if name == "__pycache__" {
            continue;
        }
        let target = dst.join(name);
        if file_type.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            fs::copy(&path, &target).map_err(|err| XtaskError::Io(display_path(&target), err))?;
        }
    }
    Ok(())
}

pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(crate) fn new(prefix: &str) -> std::io::Result<Self> {
        let mut base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        base.push(format!("{prefix}-{pid}-{nanos}"));
        fs::create_dir_all(&base)?;
        Ok(Self { path: base })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
