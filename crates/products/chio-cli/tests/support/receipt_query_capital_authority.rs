use chio_core::crypto::Keypair;
pub(crate) use chio_kernel::{CapitalExecutionAuthorityStep, CapitalExecutionRole};

pub(crate) fn signed_capital_authority_chain(
    owner_role: CapitalExecutionRole,
    owner_approved_at: u64,
    owner_expires_at: u64,
    custodian_approved_at: u64,
    custodian_expires_at: u64,
) -> (Vec<CapitalExecutionAuthorityStep>, String) {
    let owner = Keypair::generate();
    let custodian = Keypair::generate();
    let custodian_id = custodian.public_key().to_hex();
    let authority_chain = vec![
        CapitalExecutionAuthorityStep::signed(
            owner_role,
            &owner,
            owner_approved_at,
            owner_expires_at,
            None,
        )
        .expect("sign capital owner authority step"),
        CapitalExecutionAuthorityStep::signed(
            CapitalExecutionRole::Custodian,
            &custodian,
            custodian_approved_at,
            custodian_expires_at,
            None,
        )
        .expect("sign capital custodian authority step"),
    ];
    (authority_chain, custodian_id)
}
