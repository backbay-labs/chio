use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, parse_base_units, validate_chain_id, validate_currency, validate_digest,
    validate_evm_address, validate_text, I_JSON_MAX_SAFE_INTEGER,
};
use super::ChannelError;

pub const CHANNEL_ASSET_BINDING_SCHEMA: &str = "chio.channel.asset-binding.v1";

const ASSET_BINDING_DIGEST_DOMAIN: &[u8] = b"chio.channel.asset-binding.digest.v1\0";
const MAX_DECIMALS: u8 = 38;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelAssetBindingV1 {
    pub schema: String,
    pub currency: String,
    pub protocol_minor_unit_decimals: u8,
    pub chain_id: String,
    pub token_address: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub settlement_policy_digest: String,
}

impl ChannelAssetBindingV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_ASSET_BINDING_SCHEMA {
            return Err(ChannelError::InvalidField("asset_binding_schema"));
        }
        validate_currency(&self.currency)?;
        validate_chain_id(&self.chain_id)?;
        validate_evm_address("token_address", &self.token_address)?;
        validate_text("token_symbol", &self.token_symbol)?;
        validate_digest("settlement_policy_digest", &self.settlement_policy_digest)?;
        if self.protocol_minor_unit_decimals > MAX_DECIMALS || self.token_decimals > MAX_DECIMALS {
            return Err(ChannelError::InvalidField("asset_decimals"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(ASSET_BINDING_DIGEST_DOMAIN, self)
    }

    pub fn token_base_units(&self, amount: &MonetaryAmount) -> Result<String, ChannelError> {
        self.validate()?;
        validate_currency(&amount.currency)?;
        if amount.currency != self.currency {
            return Err(ChannelError::InvalidField("amount_currency"));
        }
        if amount.units > I_JSON_MAX_SAFE_INTEGER {
            return Err(ChannelError::InvalidField("amount_units"));
        }
        let units = scale_units(
            u128::from(amount.units),
            self.protocol_minor_unit_decimals,
            self.token_decimals,
        )?;
        Ok(units.to_string())
    }

    pub fn monetary_amount(&self, token_base_units: &str) -> Result<MonetaryAmount, ChannelError> {
        self.validate()?;
        let token_units = parse_base_units(token_base_units)?;
        let units = scale_units(
            token_units,
            self.token_decimals,
            self.protocol_minor_unit_decimals,
        )?;
        let units = u64::try_from(units)
            .ok()
            .filter(|units| *units <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        Ok(MonetaryAmount {
            units,
            currency: self.currency.clone(),
        })
    }

    pub fn verify_round_trip(
        &self,
        amount: &MonetaryAmount,
        token_base_units: &str,
    ) -> Result<(), ChannelError> {
        let expected = self.token_base_units(amount)?;
        if expected != token_base_units || self.monetary_amount(token_base_units)? != *amount {
            return Err(ChannelError::InexactAmount);
        }
        Ok(())
    }
}

fn scale_units(
    units: u128,
    source_decimals: u8,
    target_decimals: u8,
) -> Result<u128, ChannelError> {
    if target_decimals >= source_decimals {
        let scale = 10_u128
            .checked_pow(u32::from(target_decimals - source_decimals))
            .ok_or(ChannelError::ArithmeticOverflow)?;
        units
            .checked_mul(scale)
            .ok_or(ChannelError::ArithmeticOverflow)
    } else {
        let divisor = 10_u128
            .checked_pow(u32::from(source_decimals - target_decimals))
            .ok_or(ChannelError::ArithmeticOverflow)?;
        if !units.is_multiple_of(divisor) {
            return Err(ChannelError::InexactAmount);
        }
        Ok(units / divisor)
    }
}
