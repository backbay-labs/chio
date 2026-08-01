use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

use super::{ApprovalBinding, SettlementError};

impl ApprovalBinding {
    /// Assert that a settlement dispatch matches the approval-bound spend.
    pub fn assert_dispatch(
        &self,
        lane: &str,
        dispatch: &Web3SettlementDispatchArtifact,
    ) -> Result<(), SettlementError> {
        let expected_chain = format!("eip155:{}", self.chain_id);
        if dispatch.chain_id != expected_chain {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} chain mismatch: dispatch chain {:?} is not the approval-bound chain {expected_chain:?}",
                dispatch.chain_id
            )));
        }
        if !dispatch
            .beneficiary_address
            .trim()
            .eq_ignore_ascii_case(self.payee_address.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} payee mismatch: dispatch payee {:?} is not the approval-bound payee {:?}",
                dispatch.beneficiary_address, self.payee_address
            )));
        }
        if u128::from(dispatch.settlement_amount.units) != self.amount_minor_units {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} amount mismatch: dispatch amount {} is not the approval-bound amount {}",
                dispatch.settlement_amount.units, self.amount_minor_units
            )));
        }
        self.assert_token_symbol(lane, &dispatch.settlement_amount.currency)
    }

    /// Assert that a lane's token symbol matches the approval-bound token.
    pub fn assert_token_symbol(
        &self,
        lane: &str,
        lane_token_symbol: &str,
    ) -> Result<(), SettlementError> {
        if !lane_token_symbol
            .trim()
            .eq_ignore_ascii_case(self.token_symbol.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} token mismatch: lane token {lane_token_symbol:?} is not the \
                 approval-bound token {:?}",
                self.token_symbol
            )));
        }
        Ok(())
    }
}
