//! Seed-corpus loader tests.
//!
//! Asserts:
//!
//!   * Loader globs every file under each configured source directory.
//!   * Missing directories are reported in `missing_sources`, not as
//!     fatal errors.
//!   * Artifact records carry stable (path, sha256, size_bytes, family)
//!     tuples and are sorted lexicographically by path.
//!   * The corpus fingerprint is stable across two loads of the same
//!     directory tree.

use std::fs;

use chio_arena::{load_seed_corpus, SeedCorpusSources};
use tempfile::TempDir;

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join(name), content)
}

#[test]
fn loader_collects_artifacts_from_all_three_families() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();
    write_file(&root.join("fuzz/artifacts"), "crash-01.bin", "alpha")?;
    write_file(&root.join("fuzz/artifacts"), "crash-02.bin", "bravo")?;
    write_file(
        &root.join("tests/replay/fixtures/replay_attack"),
        "01_immediate_reuse.json",
        "{}",
    )?;
    write_file(
        &root.join("tests/replay/fixtures/tampered_signature"),
        "01_flipped_byte.json",
        "{}",
    )?;
    let sources = SeedCorpusSources::rooted_at(root);
    let corpus = load_seed_corpus(&sources)?;
    assert_eq!(corpus.len(), 4);
    assert!(corpus.missing_sources.is_empty());

    let families: Vec<&str> = corpus.artifacts.iter().map(|a| a.family.as_str()).collect();
    assert!(families.contains(&"fuzz_artifacts"));
    assert!(families.contains(&"replay_attack"));
    assert!(families.contains(&"tampered_signature"));

    // Sorted lexicographically by path: ascending order.
    let paths: Vec<_> = corpus.artifacts.iter().map(|a| a.path.clone()).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);

    for artifact in &corpus.artifacts {
        assert_eq!(artifact.sha256.len(), 64);
        assert!(artifact.size_bytes > 0);
    }
    Ok(())
}

#[test]
fn loader_records_missing_sources_without_failing() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();
    // Only one of the three sources exists.
    write_file(
        &root.join("tests/replay/fixtures/replay_attack"),
        "01.json",
        "{}",
    )?;
    let sources = SeedCorpusSources::rooted_at(root);
    let corpus = load_seed_corpus(&sources)?;
    assert_eq!(corpus.len(), 1);
    assert_eq!(corpus.missing_sources.len(), 2);
    assert!(corpus
        .missing_sources
        .contains(&"fuzz_artifacts".to_string()));
    assert!(corpus
        .missing_sources
        .contains(&"tampered_signature".to_string()));
    Ok(())
}

#[test]
fn loader_returns_empty_corpus_when_all_sources_missing() -> Result<(), Box<dyn std::error::Error>>
{
    let tmp = TempDir::new()?;
    let sources = SeedCorpusSources::rooted_at(tmp.path());
    let corpus = load_seed_corpus(&sources)?;
    assert!(corpus.is_empty());
    assert_eq!(corpus.missing_sources.len(), 3);
    Ok(())
}

#[test]
fn corpus_fingerprint_is_stable_across_loads() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();
    write_file(&root.join("fuzz/artifacts"), "crash-01.bin", "alpha")?;
    write_file(
        &root.join("tests/replay/fixtures/replay_attack"),
        "01.json",
        "{}",
    )?;
    let sources = SeedCorpusSources::rooted_at(root);
    let first = load_seed_corpus(&sources)?;
    let second = load_seed_corpus(&sources)?;
    assert_eq!(first.fingerprint_hex(), second.fingerprint_hex());

    // Touching one file should change the fingerprint.
    write_file(&root.join("fuzz/artifacts"), "crash-01.bin", "alpha-edited")?;
    let third = load_seed_corpus(&sources)?;
    assert_ne!(first.fingerprint_hex(), third.fingerprint_hex());
    Ok(())
}

#[test]
fn loader_skips_subdirectories() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();
    write_file(&root.join("fuzz/artifacts"), "crash-01.bin", "alpha")?;
    fs::create_dir_all(root.join("fuzz/artifacts/nested"))?;
    fs::write(
        root.join("fuzz/artifacts/nested/ignored.bin"),
        "should not be picked up",
    )?;
    let sources = SeedCorpusSources::rooted_at(root);
    let corpus = load_seed_corpus(&sources)?;
    assert_eq!(corpus.len(), 1);
    Ok(())
}
