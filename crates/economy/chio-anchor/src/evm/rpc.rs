use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use serde_json::{json, Value};

use crate::AnchorError;

use super::egress::validate_rpc_egress_contract;
use super::hashing::parse_hex_u64;
use super::types::{JsonRpcEnvelope, PreparedEvmRootPublication};

pub async fn publish_root(
    publication: &PreparedEvmRootPublication,
    egress_contract: &HttpEgressContract,
) -> Result<String, AnchorError> {
    let gas_limit = estimate_publication_gas(publication, egress_contract)
        .await?
        .saturating_mul(12)
        .saturating_div(10)
        .saturating_add(50_000);
    let result = rpc_call(
        &publication.rpc_url,
        egress_contract,
        "eth_sendTransaction",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
            "gas": format!("0x{gas_limit:x}"),
        }]),
    )
    .await?;

    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| AnchorError::Rpc("eth_sendTransaction did not return a tx hash".to_string()))
}

async fn estimate_publication_gas(
    publication: &PreparedEvmRootPublication,
    egress_contract: &HttpEgressContract,
) -> Result<u64, AnchorError> {
    let result = rpc_call(
        &publication.rpc_url,
        egress_contract,
        "eth_estimateGas",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
        }]),
    )
    .await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            AnchorError::Rpc("eth_estimateGas did not return a string".to_string())
        })?,
    )
}

pub(super) async fn rpc_call(
    rpc_url: &str,
    egress_contract: &HttpEgressContract,
    method: &str,
    params: Value,
) -> Result<Value, AnchorError> {
    validate_rpc_egress_contract(rpc_url, egress_contract)?;
    let client = client_builder_with_contract(egress_contract)
        .build()
        .map_err(|error| AnchorError::Rpc(format!("reqwest build: {error}")))?;
    let request = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .build()
        .map_err(|error| AnchorError::Rpc(format!("reqwest build request: {error}")))?;
    let response = send_with_contract(egress_contract, &client, request)
        .await
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "HttpEgressContract rejects anchor EVM RPC dispatch: {error}"
            ))
        })?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(AnchorError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    envelope
        .result
        .ok_or_else(|| AnchorError::Rpc(format!("{} returned no result", method)))
}
