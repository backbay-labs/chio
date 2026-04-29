// Receipt-log reader for `chio replay`.
//
// Auto-detects whether the input is a single NDJSON file or a directory of
// `*.json`/`*.ndjson` files. Yields `serde_json::Value` receipts; signature
// verification and divergence reporting are layered on top.

/// Errors returned by [`ReceiptLogReader`] while opening or iterating.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// Underlying I/O failure (missing path, permission, read error).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON parse failure with the offending 1-based line number.
    /// For directory mode the line number is local to the file that failed
    /// and the file path is recorded in `path`.
    #[error("malformed JSON at {}:{line}: {detail}", path.display())]
    MalformedJson {
        path: std::path::PathBuf,
        line: usize,
        detail: String,
    },

    /// The receipt log was opened successfully but contained zero receipts.
    /// Replay is fail-closed: an empty corpus must not be silently accepted.
    #[error("empty receipt log: {}", _0.display())]
    Empty(std::path::PathBuf),
}

/// Source kind detected by [`ReceiptLogReader::open`].
#[derive(Debug, Clone)]
pub enum Source {
    /// Single NDJSON file (one JSON receipt per non-empty line).
    NdjsonStream(std::path::PathBuf),
    /// Directory enumerated for `*.json` and `*.ndjson` files in lex order.
    Directory(std::path::PathBuf),
}

/// Auto-detecting receipt-log reader.
///
/// Opens a path with [`ReceiptLogReader::open`] and yields parsed
/// `serde_json::Value` receipts via [`ReceiptLogReader::iter`]. The
/// "auto-detect" rule is purely structural: the path's `metadata().is_file()`
/// vs `is_dir()` determines the [`Source`] kind. Anything else (symlink to
/// a non-existent target, FIFO, socket) returns
/// [`ReadError::Io`] with `InvalidInput`.
#[derive(Debug, Clone)]
pub struct ReceiptLogReader {
    pub source: Source,
}

impl ReceiptLogReader {
    /// Open `path` and detect whether it is an NDJSON stream or directory.
    ///
    /// Errors:
    ///
    /// - [`ReadError::Io`] if `path` does not exist, is unreadable, or is
    ///   neither a regular file nor a directory.
    pub fn open(path: &std::path::Path) -> Result<Self, ReadError> {
        let meta = std::fs::metadata(path)?;
        if meta.is_file() {
            Ok(Self {
                source: Source::NdjsonStream(path.to_path_buf()),
            })
        } else if meta.is_dir() {
            Ok(Self {
                source: Source::Directory(path.to_path_buf()),
            })
        } else {
            Err(ReadError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "receipt log path is neither a file nor a directory",
            )))
        }
    }

    /// Iterate receipts as parsed `serde_json::Value`s.
    ///
    /// File mode reads `path` line-by-line; blank lines are skipped, the
    /// first malformed line returns [`ReadError::MalformedJson`] with the
    /// 1-based line number. Directory mode enumerates `*.json` and
    /// `*.ndjson` files in lexical (`OsStr`) order; each `*.ndjson` is
    /// parsed line-by-line, each `*.json` is parsed as a single receipt.
    ///
    /// An empty corpus (no receipts after enumeration) yields
    /// [`ReadError::Empty`] on the first `next()` call so the consumer is
    /// guaranteed to observe at least one error rather than a silent
    /// success.
    pub fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<serde_json::Value, ReadError>>>, ReadError> {
        match &self.source {
            Source::NdjsonStream(path) => {
                let receipts = read_ndjson_file(path)?;
                if receipts.is_empty() {
                    return Err(ReadError::Empty(path.clone()));
                }
                Ok(Box::new(receipts.into_iter().map(Ok)))
            }
            Source::Directory(dir) => {
                let receipts = read_directory(dir)?;
                if receipts.is_empty() {
                    return Err(ReadError::Empty(dir.clone()));
                }
                Ok(Box::new(receipts.into_iter().map(Ok)))
            }
        }
    }
}

/// Read an NDJSON file into a vector of parsed values.
///
/// Blank lines (containing only whitespace) are skipped silently so a
/// trailing newline at end-of-file does not produce a spurious receipt.
fn read_ndjson_file(path: &std::path::Path) -> Result<Vec<serde_json::Value>, ReadError> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|error| ReadError::MalformedJson {
                path: path.to_path_buf(),
                line: idx + 1,
                detail: error.to_string(),
            })?;
        out.push(value);
    }
    Ok(out)
}

/// Enumerate `*.json` and `*.ndjson` entries in `dir` in lex order and
/// parse each. `*.ndjson` files are split per-line; `*.json` files are
/// parsed as a single receipt.
///
/// Hidden files (leading `.`) are skipped to avoid accidentally including
/// `.DS_Store`, editor backups, and similar artifacts. Subdirectories are
/// not recursed: callers wanting nested layouts should pre-flatten.
fn read_directory(dir: &std::path::Path) -> Result<Vec<serde_json::Value>, ReadError> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".ndjson") || lower.ends_with(".json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let lower = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if lower.ends_with(".ndjson") {
            let mut chunk = read_ndjson_file(&path)?;
            out.append(&mut chunk);
        } else {
            // Single-receipt JSON. Treat empty/whitespace-only files as
            // skip rather than malformed so an editor-touched file does
            // not blow up the whole replay.
            let bytes = std::fs::read(&path)?;
            let text = std::str::from_utf8(&bytes).map_err(|error| ReadError::MalformedJson {
                path: path.clone(),
                line: 1,
                detail: format!("invalid utf-8: {error}"),
            })?;
            if text.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(text).map_err(|error| ReadError::MalformedJson {
                    path: path.clone(),
                    line: 1,
                    detail: error.to_string(),
                })?;
            out.push(value);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_reader_tests {
    use super::*;

    fn write_file(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::io::Write as _;
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn open_detects_file_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_file(tmp.path(), "log.ndjson", "{\"id\":1}\n");
        let reader = ReceiptLogReader::open(&path).unwrap();
        match reader.source {
            Source::NdjsonStream(p) => assert_eq!(p, path),
            Source::Directory(_) => panic!("expected NdjsonStream"),
        }
    }

    #[test]
    fn open_detects_directory_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        match reader.source {
            Source::Directory(p) => assert_eq!(p, tmp.path()),
            Source::NdjsonStream(_) => panic!("expected Directory"),
        }
    }

    #[test]
    fn open_rejects_missing_path() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.ndjson");
        let err = ReceiptLogReader::open(&missing).unwrap_err();
        assert!(matches!(err, ReadError::Io(_)));
    }

    #[test]
    fn iter_file_mode_yields_three_receipts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "log.ndjson",
            "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n",
        );
        let reader = ReceiptLogReader::open(&path).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0]["id"], 1);
        assert_eq!(receipts[1]["id"], 2);
        assert_eq!(receipts[2]["id"], 3);
    }

    #[test]
    fn iter_file_mode_skips_blank_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "log.ndjson",
            "\n{\"id\":1}\n\n{\"id\":2}\n   \n",
        );
        let reader = ReceiptLogReader::open(&path).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(receipts.len(), 2);
    }

    #[test]
    fn iter_directory_mode_two_ndjson_files() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "01.ndjson", "{\"id\":1}\n{\"id\":2}\n");
        write_file(tmp.path(), "02.ndjson", "{\"id\":3}\n");
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0]["id"], 1);
        assert_eq!(receipts[1]["id"], 2);
        assert_eq!(receipts[2]["id"], 3);
    }

    #[test]
    fn iter_directory_mode_mixed_json_and_ndjson() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "01-single.json", "{\"id\":\"a\"}");
        write_file(tmp.path(), "02-stream.ndjson", "{\"id\":\"b\"}\n{\"id\":\"c\"}\n");
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0]["id"], "a");
        assert_eq!(receipts[1]["id"], "b");
        assert_eq!(receipts[2]["id"], "c");
    }

    #[test]
    fn iter_directory_mode_lex_order() {
        let tmp = tempfile::tempdir().unwrap();
        // Intentionally write in non-lex order so the test confirms sort.
        write_file(tmp.path(), "z-last.ndjson", "{\"order\":\"z\"}\n");
        write_file(tmp.path(), "a-first.ndjson", "{\"order\":\"a\"}\n");
        write_file(tmp.path(), "m-mid.ndjson", "{\"order\":\"m\"}\n");
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let order: Vec<&str> = receipts
            .iter()
            .map(|v| v["order"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["a", "m", "z"]);
    }

    #[test]
    fn iter_directory_mode_skips_hidden_and_unrelated() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "01.ndjson", "{\"id\":1}\n");
        // Hidden file (leading dot) and unrelated extension must be ignored.
        write_file(tmp.path(), ".DS_Store", "binary garbage that is not json");
        write_file(tmp.path(), "README.txt", "not a receipt");
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let receipts: Vec<_> = reader
            .iter()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn iter_empty_file_returns_empty_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_file(tmp.path(), "empty.ndjson", "");
        let reader = ReceiptLogReader::open(&path).unwrap();
        let err = reader.iter().err().unwrap();
        match err {
            ReadError::Empty(p) => assert_eq!(p, path),
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn iter_empty_directory_returns_empty_error() {
        let tmp = tempfile::tempdir().unwrap();
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let err = reader.iter().err().unwrap();
        match err {
            ReadError::Empty(p) => assert_eq!(p, tmp.path()),
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn iter_malformed_line_reports_line_number() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "log.ndjson",
            "{\"id\":1}\n{not json}\n{\"id\":3}\n",
        );
        let reader = ReceiptLogReader::open(&path).unwrap();
        let err = reader.iter().err().unwrap();
        match err {
            ReadError::MalformedJson {
                path: p,
                line,
                detail,
            } => {
                assert_eq!(p, path);
                assert_eq!(line, 2);
                assert!(!detail.is_empty());
            }
            other => panic!("expected MalformedJson, got {other:?}"),
        }
    }

    #[test]
    fn iter_directory_malformed_reports_originating_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "01-good.ndjson", "{\"id\":1}\n");
        let bad = write_file(tmp.path(), "02-bad.ndjson", "{\"id\":2}\n{not json}\n");
        let reader = ReceiptLogReader::open(tmp.path()).unwrap();
        let err = reader.iter().err().unwrap();
        match err {
            ReadError::MalformedJson { path, line, .. } => {
                assert_eq!(path, bad);
                assert_eq!(line, 2);
            }
            other => panic!("expected MalformedJson, got {other:?}"),
        }
    }
}
