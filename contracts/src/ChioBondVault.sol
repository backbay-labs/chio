// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioBondVault} from "./interfaces/IChioBondVault.sol";
import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {ChioMerkle} from "./lib/ChioMerkle.sol";
import {ChioRootRegistry} from "./ChioRootRegistry.sol";

contract ChioBondVault is IChioBondVault {
    bytes32 private constant BOND_PROOF_LEAF_TYPEHASH =
        keccak256("ChioBondProof(uint256 chainId,address vault,bytes32 vaultId,bytes32 evidenceHash,uint8 action,uint256 slashAmount,bytes32 distributionHash)");
    uint8 private constant BOND_ACTION_RELEASE = 0;
    uint8 private constant BOND_ACTION_IMPAIR = 1;
    uint256 private constant MAX_IMPAIR_BENEFICIARIES = 16;

    error InvalidTerms();
    error BondNotFound();
    error BondAlreadyExists();
    error UnauthorizedCaller();
    error AlreadyClosed();
    error BondNotExpired();
    error InvalidSlashDistribution();
    error ProofMetadataRequired();
    error InvalidEvidence();
    error TransferFailed();
    error EvidenceAlreadyUsed();
    error OperatorNotActive();
    error ReentrantCall();
    error NotAdmin();
    error TokenNotAllowed();
    error Paused();
    error InvalidRegistry();

    struct BondState {
        BondTerms terms;
        uint256 lockedAmount;
        uint256 slashedAmount;
        bool released;
        bool expired;
    }

    ChioRootRegistry public immutable rootRegistry;
    IChioIdentityRegistry public immutable identityRegistry;
    address public immutable admin;
    bool public paused;

    mapping(bytes32 => BondState) private bonds;
    mapping(bytes32 => mapping(bytes32 => bool)) private consumedEvidence;
    mapping(address => bool) public tokenAllowed;
    uint256 private reentrancyStatus;

    constructor(address rootRegistry_, address identityRegistry_, address admin_) {
        if (admin_ == address(0)) revert InvalidTerms();
        if (
            rootRegistry_ == address(0) ||
            identityRegistry_ == address(0) ||
            rootRegistry_.code.length == 0 ||
            identityRegistry_.code.length == 0
        ) {
            revert InvalidRegistry();
        }
        rootRegistry = ChioRootRegistry(rootRegistry_);
        identityRegistry = IChioIdentityRegistry(identityRegistry_);
        admin = admin_;
    }

    function deriveVaultId(BondTerms calldata terms) external view returns (bytes32 vaultId) {
        return _deriveVaultId(terms);
    }

    modifier nonReentrant() {
        if (reentrancyStatus == 1) revert ReentrantCall();
        reentrancyStatus = 1;
        _;
        reentrancyStatus = 0;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    function setPaused(bool paused_) external onlyAdmin {
        paused = paused_;
        emit PausedSet(msg.sender, paused_);
    }

    function setTokenAllowed(address token, bool allowed) external onlyAdmin {
        if (token == address(0)) revert InvalidTerms();
        tokenAllowed[token] = allowed;
        emit TokenAllowedSet(token, allowed);
    }

    function lockBond(BondTerms calldata terms) external nonReentrant whenNotPaused returns (bytes32 vaultId) {
        if (
            terms.principal != msg.sender ||
            terms.bondId == bytes32(0) ||
            terms.facilityId == bytes32(0) ||
            terms.token == address(0) ||
            terms.collateralAmount == 0 ||
            terms.expiresAt <= block.timestamp ||
            !identityRegistry.isOperator(terms.operator)
        ) {
            revert InvalidTerms();
        }
        if (!tokenAllowed[terms.token]) revert TokenNotAllowed();

        vaultId = _deriveVaultId(terms);
        if (bonds[vaultId].terms.principal != address(0)) revert BondAlreadyExists();
        uint256 received =
            _transferFromToken(terms.token, msg.sender, address(this), terms.collateralAmount);
        bonds[vaultId] = BondState({
            terms: terms,
            lockedAmount: received,
            slashedAmount: 0,
            released: false,
            expired: false
        });

        emit BondLocked(
            vaultId,
            terms.bondId,
            terms.facilityId,
            terms.principal,
            terms.token,
            received,
            terms.expiresAt
        );
    }

    function releaseBond(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32
    ) external pure {
        revert ProofMetadataRequired();
    }

    function releaseBondDetailed(
        bytes32 vaultId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external nonReentrant whenNotPaused {
        BondState storage bond = _requireBond(vaultId);
        if (msg.sender != bond.terms.operator) revert UnauthorizedCaller();
        if (bond.released || bond.expired) revert AlreadyClosed();
        _ensureOperatorActive(bond.terms.operator);
        bytes32 leafHash = _proofLeaf(vaultId, evidenceHash, BOND_ACTION_RELEASE, 0, bytes32(0));
        if (!rootRegistry.verifyInclusionDetailed(proof, root, leafHash, bond.terms.operator)) {
            revert InvalidEvidence();
        }

        _consumeEvidence(vaultId, evidenceHash);
        bond.released = true;
        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        if (returned > 0) {
            _transferToken(bond.terms.token, bond.terms.principal, returned);
        }
        emit BondReleased(vaultId, bond.terms.bondId, returned);
    }

    function impairBond(
        bytes32,
        uint256,
        address[] calldata,
        uint256[] calldata,
        bytes32[] calldata,
        bytes32,
        bytes32
    ) external pure {
        revert ProofMetadataRequired();
    }

    function impairBondDetailed(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external nonReentrant whenNotPaused {
        BondState storage bond = _requireBond(vaultId);
        if (msg.sender != bond.terms.operator) revert UnauthorizedCaller();
        if (bond.released || bond.expired) revert AlreadyClosed();
        _ensureOperatorActive(bond.terms.operator);
        if (
            beneficiaries.length == 0 ||
            beneficiaries.length > MAX_IMPAIR_BENEFICIARIES ||
            beneficiaries.length != shares.length ||
            slashAmount == 0 ||
            slashAmount > bond.lockedAmount - bond.slashedAmount
        ) {
            revert InvalidSlashDistribution();
        }

        uint256 totalShares = 0;
        for (uint256 i = 0; i < shares.length; ++i) {
            if (beneficiaries[i] == address(0)) revert InvalidSlashDistribution();
            totalShares += shares[i];
        }
        if (totalShares != slashAmount) revert InvalidSlashDistribution();

        bytes32 distributionHash = keccak256(abi.encode(beneficiaries, shares));
        bytes32 leafHash =
            _proofLeaf(vaultId, evidenceHash, BOND_ACTION_IMPAIR, slashAmount, distributionHash);
        if (!rootRegistry.verifyInclusionDetailed(proof, root, leafHash, bond.terms.operator)) {
            revert InvalidEvidence();
        }

        _consumeEvidence(vaultId, evidenceHash);
        bond.slashedAmount += slashAmount;
        for (uint256 i = 0; i < beneficiaries.length; ++i) {
            _transferToken(bond.terms.token, beneficiaries[i], shares[i]);
        }

        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        emit BondImpaired(vaultId, bond.terms.bondId, slashAmount, returned);
    }

    function expireRelease(bytes32 vaultId) external nonReentrant {
        BondState storage bond = _requireBond(vaultId);
        if (bond.released || bond.expired) revert AlreadyClosed();
        if (block.timestamp <= bond.terms.expiresAt) revert BondNotExpired();

        bond.expired = true;
        uint256 returned = bond.lockedAmount - bond.slashedAmount;
        if (returned > 0) {
            _transferToken(bond.terms.token, bond.terms.principal, returned);
        }
        emit BondExpired(vaultId, bond.terms.bondId, returned);
    }

    function getBond(bytes32 vaultId)
        external
        view
        returns (
            BondTerms memory terms,
            uint256 lockedAmount,
            uint256 slashedAmount,
            bool released,
            bool expired
        )
    {
        BondState storage bond = bonds[vaultId];
        return (bond.terms, bond.lockedAmount, bond.slashedAmount, bond.released, bond.expired);
    }

    function _consumeEvidence(bytes32 vaultId, bytes32 evidenceHash) internal {
        if (consumedEvidence[vaultId][evidenceHash]) revert EvidenceAlreadyUsed();
        consumedEvidence[vaultId][evidenceHash] = true;
    }

    function _ensureOperatorActive(address operator) internal view {
        if (!identityRegistry.isOperator(operator)) revert OperatorNotActive();
    }

    function _proofLeaf(
        bytes32 vaultId,
        bytes32 evidenceHash,
        uint8 action,
        uint256 slashAmount,
        bytes32 distributionHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                BOND_PROOF_LEAF_TYPEHASH,
                block.chainid,
                address(this),
                vaultId,
                evidenceHash,
                action,
                slashAmount,
                distributionHash
            )
        );
    }

    function _transferFromToken(address token, address from, address to, uint256 amount)
        internal
        returns (uint256 received)
    {
        uint256 beforeBalance = IERC20(token).balanceOf(to);
        bytes memory data = abi.encodeCall(IERC20.transferFrom, (from, to, amount));
        _callOptionalReturn(token, data);
        uint256 afterBalance = IERC20(token).balanceOf(to);
        received = afterBalance - beforeBalance;
        if (received == 0 || received > amount) revert TransferFailed();
    }

    function _transferToken(address token, address to, uint256 amount) internal {
        uint256 beforeBalance = IERC20(token).balanceOf(to);
        bytes memory data = abi.encodeCall(IERC20.transfer, (to, amount));
        _callOptionalReturn(token, data);
        uint256 afterBalance = IERC20(token).balanceOf(to);
        if (afterBalance - beforeBalance != amount) revert TransferFailed();
    }

    function _callOptionalReturn(address token, bytes memory data) internal {
        (bool ok, bytes memory returnData) = token.call(data);
        if (!ok) revert TransferFailed();
        if (returnData.length == 0) return;
        if (returnData.length < 32 || !abi.decode(returnData, (bool))) {
            revert TransferFailed();
        }
    }

    function _requireBond(bytes32 vaultId) internal view returns (BondState storage bond) {
        bond = bonds[vaultId];
        if (bond.terms.principal == address(0)) revert BondNotFound();
    }

    function _deriveVaultId(BondTerms calldata terms) internal view returns (bytes32 vaultId) {
        vaultId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                terms.bondId,
                terms.facilityId,
                terms.principal,
                terms.token,
                terms.collateralAmount,
                terms.reserveRequirementAmount,
                terms.expiresAt,
                terms.reserveRequirementRatioBps,
                terms.operator
            )
        );
    }
}
