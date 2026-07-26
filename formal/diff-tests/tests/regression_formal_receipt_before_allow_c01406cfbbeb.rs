#[cfg(not(target_arch = "wasm32"))]
use chio_formal_diff_tests::counterexample::replay_receipt_before_allow;
use chio_formal_diff_tests::counterexample::{assert_trace_shape, ExpectedStep};

const TRACE_JSON: &str =
    include_str!("../../tla/counterexamples/ReceiptBeforeAllowBroken-c01406cfbbeb.itf.json");
const TRACE_SHA256: &str = "c01406cfbbeb13798640c1957aebe459071df06db1679be4c872082ef5f0bec3";
#[cfg(not(target_arch = "wasm32"))]
const WITNESS_AUTHORITY: &str = "3";
#[cfg(not(target_arch = "wasm32"))]
const WITNESS_CAPABILITY: &str = "3";
const VARIABLES: &[&str] = &["budget_checked", "allowed", "receipt_log", "clock"];
const LOOP_START: Option<usize> = None;

const STEPS: &[ExpectedStep<'_>] = &[
    ExpectedStep {
        index: 0,
        action_hint: "initial",
        expected: &[
            (
                "budget_checked",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[]}]]}",
                ),
            ),
            (
                "allowed",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[]}]]}",
                ),
            ),
            (
                "receipt_log",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},[]],[{\"#bigint\":\"2\"},[]],[{\"#bigint\":\"3\"},[]]]",
                    "}",
                ),
            ),
            (
                "clock",
                "{\"#bigint\":\"1\"}",
            ),
        ],
    },
    ExpectedStep {
        index: 1,
        action_hint: "changed: budget_checked",
        expected: &[
            (
                "budget_checked",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[{\"#bigint\":\"3\"}]}]]}",
                ),
            ),
            (
                "allowed",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[]}]]}",
                ),
            ),
            (
                "receipt_log",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},[]],[{\"#bigint\":\"2\"},[]],[{\"#bigint\":\"3\"},[]]]",
                    "}",
                ),
            ),
            (
                "clock",
                "{\"#bigint\":\"1\"}",
            ),
        ],
    },
    ExpectedStep {
        index: 2,
        action_hint: "changed: allowed",
        expected: &[
            (
                "budget_checked",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[{\"#bigint\":\"3\"}]}]]}",
                ),
            ),
            (
                "allowed",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},{\"#set\":[]}],[{\"#bigint\":\"2\"},{\"#set\":[]}],[{\"",
                    "#bigint\":\"3\"},{\"#set\":[{\"#bigint\":\"3\"}]}]]}",
                ),
            ),
            (
                "receipt_log",
                concat!(
                    "{\"#map\":[[{\"#bigint\":\"1\"},[]],[{\"#bigint\":\"2\"},[]],[{\"#bigint\":\"3\"},[]]]",
                    "}",
                ),
            ),
            (
                "clock",
                "{\"#bigint\":\"1\"}",
            ),
        ],
    },
];

#[test]
fn regression_formal_receipt_before_allow_c01406cfbbeb_trace_shape(
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
fn regression_formal_receipt_before_allow_c01406cfbbeb_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    replay_receipt_before_allow(TRACE_JSON, WITNESS_AUTHORITY, WITNESS_CAPABILITY)?;
    Ok(())
}
