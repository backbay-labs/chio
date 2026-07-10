// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioEscrow} from "./interfaces/IChioEscrow.sol";
import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {IERC20Permit} from "./interfaces/IERC20Permit.sol";
import {ChioMerkle} from "./lib/ChioMerkle.sol";
import {ChioRootRegistry} from "./ChioRootRegistry.sol";

contract ChioEscrow is IChioEscrow {
    bytes32 private constant ESCROW_PROOF_LEAF_TYPEHASH =
        keccak256("ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,address token,address beneficiary,bytes32 operatorKeyHash,bytes32 receiptHash,uint256 amount,bool partial)");
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ESCROW_RELEASE_TYPEHASH =
        keccak256("ChioEscrowRelease(bytes32 escrowId,bytes32 receiptHash,uint256 amount,uint64 operatorEpoch)");
    bytes32 private constant EIP712_NAME_HASH = keccak256("ChioEscrow");
    bytes32 private constant EIP712_VERSION_HASH = keccak256("1");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    error InvalidTerms();
    error EscrowNotFound();
    error EscrowAlreadyExists();
    error EscrowAlreadyRefunded();
    error EscrowExpired();
    error EscrowNotExpired();
    error UnauthorizedCaller();
    error InvalidReleaseAmount();
    error TransferFailed();
    error ProofMetadataRequired();
    error InvalidSignature();
    error OperatorKeyHashMismatch();
    error ReceiptAlreadyUsed();
    error OperatorNotActive();
    error ReentrantCall();
    error NotAdmin();
    error TokenNotAllowed();
    error Paused();
    error PermitFailed();
    error InvalidRegistry();
    error NotPendingAdmin();

    struct EscrowState {
        EscrowTerms terms;
        uint256 deposited;
        uint256 released;
        bool refunded;
    }

    ChioRootRegistry public immutable rootRegistry;
    IChioIdentityRegistry public immutable identityRegistry;
    address public admin;
    address public pendingAdmin;
    bool public paused;

    mapping(bytes32 => EscrowState) private escrows;
    mapping(bytes32 => mapping(bytes32 => bool)) private consumedReceipts;
    mapping(bytes32 => bool) private consumedReceiptHashes;
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
        ChioRootRegistry root = ChioRootRegistry(rootRegistry_);
        if (address(root.identityRegistry()) != identityRegistry_) revert InvalidRegistry();
        rootRegistry = root;
        identityRegistry = IChioIdentityRegistry(identityRegistry_);
        admin = admin_;
    }

    function deriveEscrowId(EscrowTerms calldata terms) external view returns (bytes32 escrowId) {
        return _deriveEscrowId(terms);
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

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert InvalidTerms();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(msg.sender, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        address previous = admin;
        admin = msg.sender;
        pendingAdmin = address(0);
        emit AdminTransferred(previous, msg.sender);
    }

    function setTokenAllowed(address token, bool allowed) external onlyAdmin {
        if (token == address(0)) revert InvalidTerms();
        tokenAllowed[token] = allowed;
        emit TokenAllowedSet(token, allowed);
    }

    function createEscrow(EscrowTerms calldata terms) external nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (terms.depositor != msg.sender) revert UnauthorizedCaller();
        escrowId = _createEscrow(terms);
        uint256 received = _transferFromToken(terms.token, msg.sender, address(this), terms.maxAmount);
        escrows[escrowId].deposited = received;
    }

    function createEscrowWithPermit(
        EscrowTerms calldata terms,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (terms.depositor != msg.sender) revert UnauthorizedCaller();
        if (!tokenAllowed[terms.token]) revert TokenNotAllowed();
        _permitOrAllowance(
            terms.token,
            msg.sender,
            address(this),
            terms.maxAmount,
            permitDeadline,
            v,
            r,
            s
        );
        escrowId = _createEscrow(terms);
        uint256 received = _transferFromToken(terms.token, msg.sender, address(this), terms.maxAmount);
        escrows[escrowId].deposited = received;
    }

    function releaseWithProof(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32,
        uint256
    ) external pure {
        revert ProofMetadataRequired();
    }

    function releaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 settledAmount
    ) external nonReentrant whenNotPaused {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, settledAmount);
        if (settledAmount != escrow.deposited - escrow.released) {
            revert InvalidReleaseAmount();
        }
        _requireCurrentOperatorKey(escrow.terms.operator, escrow.terms.operatorKeyHash);
        bytes32 leafHash = _proofLeaf(escrow, escrowId, receiptHash, settledAmount, false);
        if (
            !rootRegistry.verifyInclusionDetailedForKeyHash(
                proof,
                root,
                leafHash,
                escrow.terms.operator,
                escrow.terms.operatorKeyHash
            )
        ) {
            revert InvalidSignature();
        }
        _consumeReceipt(escrowId, receiptHash);
        _release(escrowId, escrow, settledAmount, receiptHash, false);
    }

    function releaseWithSignature(
        bytes32 escrowId,
        bytes32 receiptHash,
        uint256 settledAmount,
        uint64 operatorEpoch,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant whenNotPaused {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, settledAmount);
        if (settledAmount != escrow.deposited - escrow.released) {
            revert InvalidReleaseAmount();
        }
        IChioIdentityRegistry.OperatorRecord memory operatorRecord =
            _requireCurrentOperatorKey(escrow.terms.operator, escrow.terms.operatorKeyHash);
        if (operatorRecord.operatorEpoch != operatorEpoch) {
            revert OperatorKeyHashMismatch();
        }

        address signer = _recoverSigner(_releaseDigest(escrowId, receiptHash, settledAmount, operatorEpoch), v, r, s);
        if (signer != operatorRecord.settlementKey) {
            revert InvalidSignature();
        }

        _consumeReceipt(escrowId, receiptHash);
        _release(escrowId, escrow, settledAmount, receiptHash, false);
    }

    function partialReleaseWithProof(
        bytes32,
        bytes32[] calldata,
        bytes32,
        bytes32,
        uint256
    ) external pure {
        revert ProofMetadataRequired();
    }

    function partialReleaseWithProofDetailed(
        bytes32 escrowId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        EscrowState storage escrow = _requireEscrow(escrowId);
        _requireBeneficiary(escrow);
        _ensureLive(escrow);
        _ensureReleaseAmount(escrow, amount);
        _requireCurrentOperatorKey(escrow.terms.operator, escrow.terms.operatorKeyHash);
        bytes32 leafHash = _proofLeaf(escrow, escrowId, receiptHash, amount, true);
        if (
            !rootRegistry.verifyInclusionDetailedForKeyHash(
                proof,
                root,
                leafHash,
                escrow.terms.operator,
                escrow.terms.operatorKeyHash
            )
        ) {
            revert InvalidSignature();
        }
        _consumeReceipt(escrowId, receiptHash);
        _release(escrowId, escrow, amount, receiptHash, true);
    }

    function refund(bytes32 escrowId) external nonReentrant {
        EscrowState storage escrow = _requireEscrow(escrowId);
        if (escrow.refunded) revert EscrowAlreadyRefunded();
        if (block.timestamp <= escrow.terms.deadline) revert EscrowNotExpired();

        escrow.refunded = true;
        uint256 remaining = escrow.deposited - escrow.released;
        if (remaining > 0) {
            _transferToken(escrow.terms.token, escrow.terms.depositor, remaining);
        }
        emit EscrowRefunded(escrowId, remaining);
    }

    function getEscrow(bytes32 escrowId)
        external
        view
        returns (EscrowTerms memory terms, uint256 deposited, uint256 released, bool refunded)
    {
        EscrowState storage escrow = escrows[escrowId];
        return (escrow.terms, escrow.deposited, escrow.released, escrow.refunded);
    }

    function _createEscrow(EscrowTerms calldata terms) internal returns (bytes32 escrowId) {
        if (
            terms.capabilityId == bytes32(0) ||
            terms.beneficiary == address(0) ||
                terms.token == address(0) ||
                terms.maxAmount == 0 ||
                terms.operatorKeyHash == bytes32(0) ||
                terms.deadline <= block.timestamp ||
                !identityRegistry.isOperator(terms.operator)
        ) {
            revert InvalidTerms();
        }
        if (!tokenAllowed[terms.token]) revert TokenNotAllowed();

        IChioIdentityRegistry.OperatorRecord memory operatorRecord =
            identityRegistry.getOperator(terms.operator);
        if (operatorRecord.edKeyHash != terms.operatorKeyHash) revert OperatorKeyHashMismatch();

        escrowId = _deriveEscrowId(terms);
        if (escrows[escrowId].terms.depositor != address(0)) revert EscrowAlreadyExists();

        escrows[escrowId] = EscrowState({
            terms: terms,
            deposited: 0,
            released: 0,
            refunded: false
        });

        emit EscrowCreated(
            escrowId,
            terms.capabilityId,
            terms.depositor,
            terms.beneficiary,
            terms.token,
            terms.maxAmount,
            terms.deadline,
            terms.operator
        );
    }

    function _deriveEscrowId(EscrowTerms calldata terms) internal view returns (bytes32 escrowId) {
        escrowId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                terms.capabilityId,
                terms.depositor,
                terms.beneficiary,
                terms.token,
                terms.maxAmount,
                terms.deadline,
                terms.operator,
                terms.operatorKeyHash
            )
        );
    }

    function _requireEscrow(bytes32 escrowId) internal view returns (EscrowState storage escrow) {
        escrow = escrows[escrowId];
        if (escrow.terms.depositor == address(0)) revert EscrowNotFound();
    }

    function _ensureLive(EscrowState storage escrow) internal view {
        if (escrow.refunded) revert EscrowAlreadyRefunded();
        if (block.timestamp > escrow.terms.deadline) revert EscrowExpired();
    }

    function _requireBeneficiary(EscrowState storage escrow) internal view {
        if (msg.sender != escrow.terms.beneficiary) revert UnauthorizedCaller();
    }

    function _ensureReleaseAmount(EscrowState storage escrow, uint256 amount) internal view {
        if (amount == 0 || escrow.released + amount > escrow.deposited) {
            revert InvalidReleaseAmount();
        }
    }

    function _ensureOperatorActive(address operator) internal view {
        if (!identityRegistry.isOperator(operator)) revert OperatorNotActive();
    }

    function _requireCurrentOperatorKey(address operator, bytes32 operatorKeyHash)
        internal
        view
        returns (IChioIdentityRegistry.OperatorRecord memory operatorRecord)
    {
        operatorRecord = identityRegistry.getOperator(operator);
        if (!operatorRecord.active) revert OperatorNotActive();
        if (operatorRecord.edKeyHash != operatorKeyHash) revert OperatorKeyHashMismatch();
    }

    function _proofLeaf(
        EscrowState storage escrow,
        bytes32 escrowId,
        bytes32 receiptHash,
        uint256 amount,
        bool isPartial
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                ESCROW_PROOF_LEAF_TYPEHASH,
                block.chainid,
                address(this),
                escrowId,
                escrow.terms.token,
                escrow.terms.beneficiary,
                escrow.terms.operatorKeyHash,
                receiptHash,
                amount,
                isPartial
            )
        );
    }

    function _releaseDigest(bytes32 escrowId, bytes32 receiptHash, uint256 amount, uint64 operatorEpoch)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                EIP712_NAME_HASH,
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(ESCROW_RELEASE_TYPEHASH, escrowId, receiptHash, amount, operatorEpoch)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _consumeReceipt(bytes32 escrowId, bytes32 receiptHash) internal {
        if (receiptHash == bytes32(0)) {
            revert InvalidSignature();
        }
        if (consumedReceipts[escrowId][receiptHash] || consumedReceiptHashes[receiptHash]) {
            revert ReceiptAlreadyUsed();
        }
        consumedReceipts[escrowId][receiptHash] = true;
        consumedReceiptHashes[receiptHash] = true;
    }

    function _recoverSigner(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (address)
    {
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) revert InvalidSignature();
        if (uint256(s) > SECP256K1_HALF_ORDER) revert InvalidSignature();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _release(
        bytes32 escrowId,
        EscrowState storage escrow,
        uint256 amount,
        bytes32 receiptHash,
        bool isPartial
    ) internal {
        escrow.released += amount;
        _transferToken(escrow.terms.token, escrow.terms.beneficiary, amount);
        if (isPartial && escrow.released < escrow.deposited) {
            emit EscrowPartialRelease(
                escrowId, amount, escrow.deposited - escrow.released, receiptHash
            );
        } else {
            emit EscrowReleased(escrowId, amount, receiptHash);
        }
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
        if (received != amount) revert TransferFailed();
    }

    function _permitOrAllowance(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        bytes memory data = abi.encodeCall(IERC20Permit.permit, (owner, spender, amount, permitDeadline, v, r, s));
        (bool ok,) = token.call(data);
        if (!ok && IERC20(token).allowance(owner, spender) < amount) revert PermitFailed();
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
}
