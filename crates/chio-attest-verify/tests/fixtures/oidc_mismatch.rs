use chio_attest_verify::ExpectedIdentity;

pub fn github_actions_identity() -> ExpectedIdentity {
    ExpectedIdentity::doc_hidden_inline(
        r"https://github\.com/backbay-labs/chio/.*",
        "https://token.actions.githubusercontent.com",
    )
}

pub fn wrong_issuer_identity() -> ExpectedIdentity {
    ExpectedIdentity::doc_hidden_inline(
        r"https://github\.com/backbay-labs/chio/.*",
        "https://issuer.invalid.example.com",
    )
}
