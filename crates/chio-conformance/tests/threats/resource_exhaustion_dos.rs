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

use std::path::PathBuf;

const ESCAPE_CLASSES: &[&str] = &[
    "fuel_exhaustion",
    "oversize_memory",
    "deep_recursion",
    "table_grow",
];

#[test]
fn threat_resource_exhaustion_dos_is_covered() {
    // covers: resource_exhaustion_dos
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let escape_dir = manifest_dir.join("../chio-wasm-guards/tests/escape");
    let escape_dir = escape_dir
        .canonicalize()
        .unwrap_or_else(|err| panic!("resolve wasm-guard escape directory: {err}"));

    for class in ESCAPE_CLASSES {
        let fixture = escape_dir.join(format!("{class}.rs"));
        assert!(
            fixture.is_file(),
            "expected wasm-guard escape fixture {} to exist; \
             resource_exhaustion_dos is covered by the runtime exhaustion harness",
            fixture.display()
        );
    }
}

#[test]
fn threat_resource_exhaustion_dos_class_count_is_pinned() {
    // covers: resource_exhaustion_dos
    //
    // Pin the count at 4 so a future shrink of the runtime
    // evidence set fails this test rather than silently reducing
    // coverage. The full eight-class set lives under
    // crates/chio-wasm-guards/tests/escape/aggregate.rs; this
    // assertion only pins the four that this threat ID cites.
    assert_eq!(
        ESCAPE_CLASSES.len(),
        4,
        "resource_exhaustion_dos cites exactly four wasm-guard escape classes"
    );
}
