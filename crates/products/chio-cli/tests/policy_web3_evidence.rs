#![allow(dead_code, unused_imports)]

#[path = "../../../platform/chio-control-plane/src/policy.rs"]
mod policy;

use chio_test_support::prelude::*;

#[test]
fn web3_evidence_policy_fields_parse_for_cli() {
    let yaml = r#"
kernel:
  require_web3_evidence: true
  checkpoint_batch_size: 32
"#;

    let parsed = policy::parse_policy(yaml).test_unwrap();
    assert!(parsed.kernel.require_web3_evidence);
    assert_eq!(parsed.kernel.checkpoint_batch_size, 32);
}
