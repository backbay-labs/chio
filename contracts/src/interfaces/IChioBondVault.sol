// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ChioMerkle} from "../lib/ChioMerkle.sol";

interface IChioBondVault {
    struct BondTerms {
        bytes32 bondId;
        bytes32 facilityId;
        address principal;
        address token;
        uint256 collateralAmount;
        uint256 reserveRequirementAmount;
        uint256 expiresAt;
        uint16 reserveRequirementRatioBps;
        address operator;
        bytes32 operatorKeyHash;
    }

    event BondLocked(
        bytes32 indexed vaultId,
        bytes32 indexed bondId,
        bytes32 indexed facilityId,
        address principal,
        address token,
        uint256 collateralAmount,
        uint256 expiresAt
    );

    event BondReleased(bytes32 indexed vaultId, bytes32 indexed bondId, uint256 returnedAmount);

    event BondImpaired(
        bytes32 indexed vaultId,
        bytes32 indexed bondId,
        uint256 slashedAmount,
        uint256 returnedAmount
    );

    event BondExpired(bytes32 indexed vaultId, bytes32 indexed bondId, uint256 returnedAmount);

    event TokenAllowedSet(address indexed token, bool allowed);

    event PausedSet(address indexed admin, bool paused);

    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error BondNoLongerLive();

    function admin() external view returns (address);

    function pendingAdmin() external view returns (address);

    function paused() external view returns (bool);

    function transferAdmin(address newAdmin) external;

    function acceptAdmin() external;

    function setPaused(bool paused_) external;

    function setTokenAllowed(address token, bool allowed) external;

    function tokenAllowed(address token) external view returns (bool);

    function deriveVaultId(BondTerms calldata terms) external view returns (bytes32 vaultId);

    function lockBond(BondTerms calldata terms) external returns (bytes32 vaultId);

    function releaseBond(
        bytes32 vaultId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function releaseBondDetailed(
        bytes32 vaultId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function impairBond(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function impairBondDetailed(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function expireRelease(bytes32 vaultId) external;

    function getBond(bytes32 vaultId)
        external
        view
        returns (BondTerms memory terms, uint256 lockedAmount, uint256 slashedAmount, bool released, bool expired);
}
