#[cfg(not(target_arch = "wasm32"))]
use chio_formal_diff_tests::counterexample::replay_receipt_before_allow;
use chio_formal_diff_tests::counterexample::{assert_trace_shape, ExpectedStep};

const TRACE_JSON: &str = include_str!("../fixtures/sample.itf.json");
const TRACE_SHA256: &str = "abfe825d12668975793595907fcaee456e8cc0587b1dab0ac6ebb70354c97b88";
#[cfg(not(target_arch = "wasm32"))]
const WITNESS_AUTHORITY: &str = "1";
#[cfg(not(target_arch = "wasm32"))]
const WITNESS_CAPABILITY: &str = "1";
const VARIABLES: &[&str] = &["allowed", "budget_checked", "clock", "receipt_log"];
const LOOP_START: Option<usize> = None;

const STEPS: &[ExpectedStep<'_>] = &[
    ExpectedStep {
        index: 0,
        action_hint: "initial",
        expected: &[
            (
                "allowed",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}]]}",
            ),
            (
                "budget_checked",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}]]}",
            ),
            ("clock", "{\"#bigint\":\"1\"}"),
            ("receipt_log", "{\"#map\":[[{\"#bigint\":\"1\"},[]]]}"),
        ],
    },
    ExpectedStep {
        index: 1,
        action_hint: "changed: budget_checked",
        expected: &[
            (
                "allowed",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}]]}",
            ),
            (
                "budget_checked",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[{\"#bigint\":\"1\"}]}]]}",
            ),
            ("clock", "{\"#bigint\":\"1\"}"),
            ("receipt_log", "{\"#map\":[[{\"#bigint\":\"1\"},[]]]}"),
        ],
    },
    ExpectedStep {
        index: 2,
        action_hint: "changed: allowed",
        expected: &[
            (
                "allowed",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[{\"#bigint\":\"1\"}]}]]}",
            ),
            (
                "budget_checked",
                "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[{\"#bigint\":\"1\"}]}]]}",
            ),
            ("clock", "{\"#bigint\":\"1\"}"),
            ("receipt_log", "{\"#map\":[[{\"#bigint\":\"1\"},[]]]}"),
        ],
    },
];

#[test]
fn regression_formal_receipt_before_allow_abfe825d1266_trace_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_trace_shape(
        file!(),
        TRACE_JSON,
        TRACE_SHA256,
        VARIABLES,
        STEPS,
        LOOP_START,
    )?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn regression_formal_receipt_before_allow_abfe825d1266_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    replay_receipt_before_allow(TRACE_JSON, WITNESS_AUTHORITY, WITNESS_CAPABILITY)?;
    Ok(())
}
