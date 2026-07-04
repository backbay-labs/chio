use chio_pheromone_runtime::VerifiedChioWorkflowResolver;

#[test]
fn chio_pheromone_runtime_exposes_chio_named_workflow_resolver() {
    assert_eq!(
        std::any::type_name::<VerifiedChioWorkflowResolver>(),
        "chio_pheromone_runtime::VerifiedChioWorkflowResolver"
    );

    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("pub struct VerifiedChioWorkflowResolver"),
        "public runtime resolver type must be Chio named"
    );
}

#[test]
fn chio_pheromone_runtime_workflow_verification_error_is_chio_owned() {
    let lib = include_str!("../src/lib.rs");
    let public_alias_leaks = lib
        .lines()
        .filter(|line| line.trim_start().starts_with("pub type ") && line.contains("Chio"))
        .collect::<Vec<_>>();
    assert!(
        public_alias_leaks.is_empty(),
        "public Chio aliases must not expose historical verifier types: {public_alias_leaks:#?}"
    );

    let public_signature_leaks = public_signature_chunks(lib)
        .into_iter()
        .filter(|chunk| chunk.contains("chio_attest_buyer_core::"))
        .collect::<Vec<_>>();
    assert!(
        public_signature_leaks.is_empty(),
        "public function signatures must not expose historical verifier types: {public_signature_leaks:#?}"
    );

    let workflow_verification_variant = lib
        .lines()
        .find(|line| line.contains("WorkflowVerification("))
        .unwrap_or("");
    assert!(
        !workflow_verification_variant.contains("chio_attest_buyer_core::")
            && !workflow_verification_variant.contains("#[from]"),
        "workflow verification errors must use a Chio-owned payload: {workflow_verification_variant}"
    );
}

fn public_signature_chunks(source: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut in_signature = false;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub fn ") {
            in_signature = true;
            current.push(line);
        } else if in_signature {
            current.push(line);
        }

        if in_signature && line.contains('{') {
            chunks.push(current.join("\n"));
            current.clear();
            in_signature = false;
        }
    }

    chunks
}
