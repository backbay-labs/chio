use super::*;

#[test]
fn aeneas_production_targets_require_generated_equivalence() {
    assert_eq!(
        expected_refinement_schema("aeneas", "production", "formal/aeneas/production.toml"),
        Ok("chio.aeneas-production.v1")
    );

    let fixture = r#"
[[targets]]
name = "decision_core"
status = "generated_equivalence"
functions = ["nonce_admits"]
equivalence_theorems = ["nonce_admits|Chio.Proofs.generated_nonce_admits_eq_mirror"]

[[targets]]
name = "reservation_ledger"
status = "generated_equivalence"
functions = ["ledger_is_terminal", "ledger_apply"]
equivalence_theorems = [
  "ledger_is_terminal|Chio.Proofs.generated_ledger_is_terminal_eq_model",
  "ledger_apply|Chio.Proofs.generated_ledger_apply_eq_model",
]
"#;
    let value = match parse_toml("fixture", fixture) {
        Ok(value) => value,
        Err(error) => panic!("Aeneas production fixture parse failed: {error}"),
    };
    assert_eq!(
        aeneas_extracted_symbols(&value, "formal/aeneas/production.toml"),
        Ok(vec![
            "nonce_admits".to_string(),
            "ledger_is_terminal".to_string(),
            "ledger_apply".to_string(),
        ])
    );

    let downgraded = fixture.replacen(
        "status = \"generated_equivalence\"",
        "status = \"extraction_only\"",
        1,
    );
    let value = match parse_toml("fixture", &downgraded) {
        Ok(value) => value,
        Err(error) => panic!("downgraded Aeneas fixture parse failed: {error}"),
    };
    let error = match aeneas_extracted_symbols(&value, "formal/aeneas/production.toml") {
        Ok(_) => panic!("downgraded Aeneas target unexpectedly passed"),
        Err(error) => error,
    };
    assert!(error.contains("not equivalence-checked"));

    let missing_theorem = fixture.replacen(
        "ledger_apply|Chio.Proofs.generated_ledger_apply_eq_model",
        "unregistered_function|Chio.Proofs.generated_ledger_apply_eq_model",
        1,
    );
    let value = match parse_toml("fixture", &missing_theorem) {
        Ok(value) => value,
        Err(error) => panic!("mismatched Aeneas fixture parse failed: {error}"),
    };
    let error = match aeneas_extracted_symbols(&value, "formal/aeneas/production.toml") {
        Ok(_) => panic!("mismatched Aeneas theorem inventory unexpectedly passed"),
        Err(error) => error,
    };
    assert!(error.contains("theorem inventory mismatch"));
}

#[test]
fn aeneas_production_symbols_are_attributed_to_their_sources() {
    let fixture = r#"
[[sources]]
id = "economy"
path = "crates/economy/chio-credit/src/formal_economy.rs"

[[sources]]
id = "kernel"
path = "crates/kernel/chio-kernel-core/src/formal_aeneas.rs"

[[targets]]
name = "kernel_core"
source = "kernel"
status = "generated_equivalence"
functions = ["nonce_admits"]
equivalence_theorems = ["nonce_admits|Chio.Proofs.generated_nonce_admits_eq_mirror"]

[[targets]]
name = "economy_conversion"
source = "economy"
status = "generated_equivalence"
functions = ["convert_ceil_scalar", "convert_floor_scalar"]
equivalence_theorems = [
  "convert_ceil_scalar|Chio.Proofs.generated_convert_ceil_scalar_eq_model",
  "convert_floor_scalar|Chio.Proofs.generated_convert_floor_scalar_eq_model",
]
"#;
    let value = match parse_toml("fixture", fixture) {
        Ok(value) => value,
        Err(error) => panic!("Aeneas source fixture parse failed: {error}"),
    };
    assert_eq!(
        aeneas_extracted_symbols_by_source(&value, "formal/aeneas/production.toml"),
        Ok(vec![
            (
                "crates/economy/chio-credit/src/formal_economy.rs".to_string(),
                vec![
                    "convert_ceil_scalar".to_string(),
                    "convert_floor_scalar".to_string(),
                ],
            ),
            (
                "crates/kernel/chio-kernel-core/src/formal_aeneas.rs".to_string(),
                vec!["nonce_admits".to_string()],
            ),
        ])
    );

    let unknown_source = fixture.replacen("source = \"economy\"", "source = \"missing\"", 1);
    let value = match parse_toml("fixture", &unknown_source) {
        Ok(value) => value,
        Err(error) => panic!("unknown-source fixture parse failed: {error}"),
    };
    let error = match aeneas_extracted_symbols_by_source(&value, "formal/aeneas/production.toml") {
        Ok(_) => panic!("unknown Aeneas source unexpectedly passed"),
        Err(error) => error,
    };
    assert!(error.contains("unknown source"));
}
