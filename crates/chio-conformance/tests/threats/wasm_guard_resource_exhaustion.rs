//! Threat test for threat ID `wasm_guard_resource_exhaustion`.
//!
//! Coverage strategy: pin the WASM guard escape harness fixtures that exercise
//! fuel exhaustion, oversized memory, recursion, and table growth. Each cited
//! fixture must remain a runnable test file with the fail-closed trap assertion
//! named below.

use std::{fs, path::PathBuf};

const ESCAPE_EVIDENCE: &[(&str, &[&str])] = &[
    (
        "fuel_exhaustion.rs",
        &[
            "infinite_loop_traps_with_typed_error",
            "zero_fuel_ceiling_traps_on_first_instruction",
        ],
    ),
    (
        "oversize_memory.rs",
        &[
            "rejects_oversized_module_blob",
            "declared_memory_above_cap_traps_at_instantiate",
        ],
    ),
    ("deep_recursion.rs", &["unbounded_self_recursion_traps"]),
    ("table_grow.rs", &["table_grow_in_loop_traps"]),
];

fn escape_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chio-wasm-guards/tests/escape");
    match dir.canonicalize() {
        Ok(path) => path,
        Err(error) => panic!("resolve wasm guard escape directory: {error}"),
    }
}

#[test]
fn threat_wasm_guard_resource_exhaustion_is_covered() {
    // covers: wasm_guard_resource_exhaustion
    let escape_dir = escape_dir();
    for (fixture, needles) in ESCAPE_EVIDENCE {
        let path = escape_dir.join(fixture);
        assert!(path.is_file(), "{} must remain in tree", path.display());
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        assert!(
            raw.contains("#[test]"),
            "{} must be runnable",
            path.display()
        );
        for needle in *needles {
            assert!(
                raw.contains(needle),
                "{} must retain fail-closed assertion {needle}",
                path.display()
            );
        }
    }
}
