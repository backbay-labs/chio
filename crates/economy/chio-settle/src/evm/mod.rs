//! EVM settlement rail: call preparation, finalization, signing, and decoding.

use std::str::FromStr;
use std::time::Duration;

#[cfg(test)]
use std::thread;

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CreditBondLifecycleState,
    SignedCapitalExecutionInstruction, SignedCreditBond,
};
use chio_core::hashing::Hash;
use chio_core::merkle::leaf_hash;
use chio_core::receipt::body::ChioReceipt;
use chio_core::web3::anchors::{verify_anchor_inclusion_proof, AnchorInclusionProof};
use chio_core::web3::identity::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3KeyBindingPurpose,
};
use chio_core::web3::settlement::{
    settlement_anchor_receipt_content_hash_parts, validate_web3_settlement_dispatch,
    validate_web3_settlement_execution_receipt, Web3SettlementDispatchArtifact,
    Web3SettlementExecutionReceiptArtifact, Web3SettlementLifecycleState,
    Web3SettlementSupportBoundary, CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA,
    CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use chio_core::web3::trust_profile::Web3SettlementPath;
use chio_egress_contract::{client_builder_with_contract, send_with_contract};
use chio_web3_bindings::{
    ChioMerkleProof, IChioBondVault, IChioEscrow, IChioIdentityRegistry, IChioRootRegistry,
};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    ops::ensure_settlement_completion_flow_binding, SettlementChainConfig, SettlementCommitment,
    SettlementError,
};

mod decode;
mod finalize;
mod prepare;
mod sign;
mod types;

use self::decode::*;
pub use self::finalize::*;
pub use self::prepare::*;
use self::sign::*;
pub use self::types::*;

sol! {
    interface IERC20ApproveOnly {
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

#[cfg(test)]
mod tests;
