// M05.P5.T3 test body for threat ID `resource_exhaustion_dos`.
//
// Threat: resource_exhaustion_dos (Resource exhaustion denial of service).
// Surfaces: native_chio, hosted_mcp, trust_control, kernel_to_tool.
//
// Coverage strategy: resource exhaustion does not yet have a
// directly-cited adversarial corpus case; the M05.P1 attack-class
// taxonomy is focused on receipt and capability semantics. The
// threat is instead exercised at the runtime layer by the M05.P3
// wasm-guard escape harness: `fuel_exhaustion`, `oversize_memory`,
// `deep_recursion`, and `table_grow_abuse` are all CPU / memory /
// stack exhaustion vectors that yield typed `WasmGuardError`
// outcomes. The native frame size limit (16 MiB; trajectory-1
// invariant) is enforced inside chio-kernel-core's framing layer
// and is exercised by its own integration tests.
//
// This stub asserts the runtime evidence pointer remains in-tree:
// the four cited escape-class fixture files exist under
// `crates/chio-wasm-guards/tests/escape/`. Removing one of them is
// a coordinated change that must update either this test or the
// M05 audit doc.

use std::{fs, path::PathBuf};

/// Pairs of (escape-class fixture filename, evidence needle) that the
/// runtime exhaustion harness must keep in-tree. The needle is a stable
/// test-function name that must remain inside the fixture; a missing
/// needle means the fixture has been gutted into a no-op stub and the
/// threat ID has lost its exercise.
const ESCAPE_CLASS_EVIDENCE: &[(&str, &[&str])] = &[
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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("../chio-wasm-guards/tests/escape");
    match dir.canonicalize() {
        Ok(resolved) => resolved,
        Err(err) => panic!("resolve wasm-guard escape directory: {err}"),
    }
}

#[test]
fn threat_resource_exhaustion_dos_is_covered() {
    // covers: resource_exhaustion_dos
    //
    // The chio-wasm-guards escape harness is the runtime evidence
    // for this threat ID. Verify each cited fixture exists AND
    // still contains its named test body so a future "rename to
    // stub" does not silently strip threat coverage.
    let escape_dir = escape_dir();
    for (fixture, needles) in ESCAPE_CLASS_EVIDENCE {
        let path = escape_dir.join(fixture);
        assert!(
            path.is_file(),
            "expected wasm-guard escape fixture {} to exist; \
             resource_exhaustion_dos is covered by the runtime exhaustion harness",
            path.display()
        );
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(err) => panic!("read {}: {err}", path.display()),
        };
        assert!(
            raw.contains("#[test]"),
            "wasm-guard escape fixture {} must declare at least one #[test] \
             so resource_exhaustion_dos retains a runnable exercise",
            path.display()
        );
        for needle in *needles {
            assert!(
                raw.contains(needle),
                "wasm-guard escape fixture {} must mention test {needle:?} \
                 so resource_exhaustion_dos does not silently regress",
                path.display()
            );
        }
    }
}

#[test]
fn threat_resource_exhaustion_dos_class_set_is_pinned() {
    // covers: resource_exhaustion_dos
    //
    // Pin the cited escape-class set so a future shrink of the
    // runtime evidence list fails this test rather than silently
    // reducing coverage. The full eight-class set lives under
    // crates/chio-wasm-guards/tests/escape/aggregate.rs; this
    // assertion only pins the four that this threat ID cites and
    // verifies they are unique.
    let fixtures: std::collections::BTreeSet<&str> = ESCAPE_CLASS_EVIDENCE
        .iter()
        .map(|(fixture, _)| *fixture)
        .collect();
    let expected: std::collections::BTreeSet<&str> = [
        "fuel_exhaustion.rs",
        "oversize_memory.rs",
        "deep_recursion.rs",
        "table_grow.rs",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        fixtures, expected,
        "resource_exhaustion_dos must cite exactly the four pinned wasm-guard escape fixtures"
    );
}
