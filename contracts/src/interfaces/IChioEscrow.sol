// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ChioMerkle} from "../lib/ChioMerkle.sol";

interface IChioEscrow {
    struct EscrowTerms {
        bytes32 capabilityId;
        address depositor;
        address beneficiary;
        address token;
        uint256 maxAmount;
        uint256 deadline;
        address operator;
        bytes32 operatorKeyHash;
    }

    event EscrowCreated(
        bytes32 indexed escrowId,
        bytes32 indexed capabilityId,
        address indexed depositor,
        address beneficiary,
        address token,
        uint256 maxAmount,
        uint256 deadline,
        address operator
    );

    event EscrowReleased(bytes32 indexed escrowId, uint256 amount, bytes32 receiptHash);

    event EscrowPartialRelease(
        bytes32 indexed escrowId,
        uint256 amount,
        uint256 remaining,
        bytes32 receiptHash
    );

    event EscrowRefunded(bytes32 indexed escrowId, uint256 amount);

    event TokenAllowedSet(address indexed token, bool allowed);

    event PausedSet(address indexed admin, bool paused);

    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    function admin() external view returns (address);

    function pendingAdmin() external view returns (address);

    function paused() external view returns (bool);

    function transferAdmin(address newAdmin) external;

    function acceptAdmin() external;

    function setPaused(bool paused_) external;

    function setTokenAllowed(address token, bool allowed) external;

    function tokenAllowed(address token) external view returns (bool);

    function deriveEscrowId(EscrowTerms calldata terms) external view returns (bytes32 escrowId);

    function createEscrow(EscrowTerms calldata terms) external returns (bytes32 escrowId);

    function createEscrowWithPermit(
        EscrowTerms calldata terms,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32 escrowId);

    function releaseWithProof(
        bytes32 escrowId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 settledAmount
    ) external;

    function releaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 settledAmount
    ) external;

    function releaseWithSignature(
        bytes32 escrowId,
        bytes32 receiptHash,
        uint256 settledAmount,
        uint64 operatorEpoch,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function partialReleaseWithProof(
        bytes32 escrowId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 amount
    ) external;

    function partialReleaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 amount
    ) external;

    function refund(bytes32 escrowId) external;

    function getEscrow(bytes32 escrowId)
        external
        view
        returns (EscrowTerms memory terms, uint256 deposited, uint256 released, bool refunded);
}
