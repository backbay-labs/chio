// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";
import {IChioRootRegistry} from "./interfaces/IChioRootRegistry.sol";
import {ChioMerkle} from "./lib/ChioMerkle.sol";

contract ChioRootRegistry is IChioRootRegistry {
    uint256 public constant MAX_ACTIVE_DELEGATES = 3;
    uint256 public constant MAX_BATCH_ROOTS = 32;

    error OperatorNotAuthorized();
    error InvalidCheckpointSequence();
    error InvalidBatchRange();
    error InvalidMerkleRoot();
    error OperatorKeyHashMismatch();
    error ProofMetadataRequired();
    error InvalidDelegate();
    error DelegateLimitReached();
    error RootNotFound();
    error InvalidRegistry();

    IChioIdentityRegistry public immutable identityRegistry;

    mapping(address => mapping(uint64 => RootEntry)) private rootEntries;
    mapping(address => mapping(bytes32 => bool)) private publishedRoots;
    mapping(address => mapping(bytes32 => uint64)) private rootTreeSizes;
    mapping(address => uint64) private latestSeq;
    mapping(address => uint64) private latestBatchEndSeq;
    mapping(address => mapping(address => uint64)) private delegateExpiries;
    mapping(address => address[]) private delegateSlots;

    constructor(address identityRegistry_) {
        if (identityRegistry_ == address(0) || identityRegistry_.code.length == 0) {
            revert InvalidRegistry();
        }
        identityRegistry = IChioIdentityRegistry(identityRegistry_);
    }

    function publishRoot(
        address operator,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) external {
        _publishSingle(
            operator,
            msg.sender,
            merkleRoot,
            checkpointSeq,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            operatorKeyHash
        );
    }

    function publishRootBatch(
        address operator,
        bytes32[] calldata merkleRoots,
        uint64[] calldata checkpointSeqs,
        uint64[] calldata batchStartSeqs,
        uint64[] calldata batchEndSeqs,
        uint64[] calldata treeSizes,
        bytes32 operatorKeyHash
    ) external {
        uint256 count = merkleRoots.length;
        if (
            count == 0 ||
            count > MAX_BATCH_ROOTS ||
            checkpointSeqs.length != count ||
            batchStartSeqs.length != count ||
            batchEndSeqs.length != count ||
            treeSizes.length != count
        ) {
            revert InvalidBatchRange();
        }

        for (uint256 i = 0; i < count; ++i) {
            _publishSingle(
                operator,
                msg.sender,
                merkleRoots[i],
                checkpointSeqs[i],
                batchStartSeqs[i],
                batchEndSeqs[i],
                treeSizes[i],
                operatorKeyHash
            );
        }
    }

    function registerDelegate(address delegate, uint64 expiresAt) external {
        if (!identityRegistry.isOperator(msg.sender)) revert OperatorNotAuthorized();
        if (delegate == address(0) || delegate == msg.sender || expiresAt <= block.timestamp) {
            revert InvalidDelegate();
        }

        _pruneExpiredDelegates(msg.sender);
        uint64 currentExpiry = delegateExpiries[msg.sender][delegate];
        bool currentlyActive = currentExpiry > block.timestamp;
        if (!currentlyActive) {
            if (delegateSlots[msg.sender].length >= MAX_ACTIVE_DELEGATES) {
                revert DelegateLimitReached();
            }
            delegateSlots[msg.sender].push(delegate);
        }

        delegateExpiries[msg.sender][delegate] = expiresAt;
        emit DelegateRegistered(msg.sender, delegate, expiresAt);
    }

    function revokeDelegate(address delegate) external {
        uint64 currentExpiry = delegateExpiries[msg.sender][delegate];
        if (currentExpiry == 0) revert InvalidDelegate();
        delete delegateExpiries[msg.sender][delegate];
        _removeDelegateSlot(msg.sender, delegate);
        emit DelegateRevoked(msg.sender, delegate);
    }

    function isAuthorizedPublisher(address operator, address publisher)
        public
        view
        returns (bool)
    {
        if (publisher == operator) {
            return identityRegistry.isOperator(operator);
        }
        return
            identityRegistry.isOperator(operator)
                && delegateExpiries[operator][publisher] > block.timestamp;
    }

    function verifyInclusion(
        bytes32[] calldata,
        bytes32,
        bytes32,
        address
    ) external pure returns (bool) {
        revert ProofMetadataRequired();
    }

    function verifyInclusionDetailed(
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator
    ) external view returns (bool) {
        if (!publishedRoots[operator][root]) {
            return false;
        }
        uint64 treeSize = rootTreeSizes[operator][root];
        if (treeSize == 0 || proof.treeSize != uint256(treeSize)) {
            return false;
        }
        return ChioMerkle.verifyRFC6962(proof, root, leafHash);
    }

    function getLatestRoot(address operator) external view returns (RootEntry memory) {
        uint64 checkpointSeq = latestSeq[operator];
        if (checkpointSeq == 0) revert RootNotFound();
        return rootEntries[operator][checkpointSeq];
    }

    function getRoot(address operator, uint64 checkpointSeq) external view returns (RootEntry memory) {
        RootEntry memory entry = rootEntries[operator][checkpointSeq];
        if (entry.treeSize == 0) revert RootNotFound();
        return entry;
    }

    function getLatestSeq(address operator) external view returns (uint64) {
        return latestSeq[operator];
    }

    function _pruneExpiredDelegates(address operator) private {
        address[] storage slots = delegateSlots[operator];
        uint256 index = 0;
        while (index < slots.length) {
            address delegate = slots[index];
            if (delegateExpiries[operator][delegate] <= block.timestamp) {
                delete delegateExpiries[operator][delegate];
                uint256 lastIndex = slots.length - 1;
                if (index != lastIndex) {
                    slots[index] = slots[lastIndex];
                }
                slots.pop();
            } else {
                ++index;
            }
        }
    }

    function _removeDelegateSlot(address operator, address delegate) private {
        address[] storage slots = delegateSlots[operator];
        for (uint256 index = 0; index < slots.length; ++index) {
            if (slots[index] == delegate) {
                uint256 lastIndex = slots.length - 1;
                if (index != lastIndex) {
                    slots[index] = slots[lastIndex];
                }
                slots.pop();
                return;
            }
        }
    }

    function _publishSingle(
        address operator,
        address publisher,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) internal {
        if (!isAuthorizedPublisher(operator, publisher)) revert OperatorNotAuthorized();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (batchStartSeq > batchEndSeq || treeSize == 0) revert InvalidBatchRange();
        if (checkpointSeq != latestSeq[operator] + 1) revert InvalidCheckpointSequence();
        uint64 previousBatchEndSeq = latestBatchEndSeq[operator];
        if (
            previousBatchEndSeq == type(uint64).max ||
            batchStartSeq != previousBatchEndSeq + 1
        ) {
            revert InvalidBatchRange();
        }
        uint64 storedTreeSize = rootTreeSizes[operator][merkleRoot];
        if (storedTreeSize != 0 && storedTreeSize != treeSize) revert InvalidMerkleRoot();

        IChioIdentityRegistry.OperatorRecord memory record = identityRegistry.getOperator(operator);
        if (record.edKeyHash != operatorKeyHash) revert OperatorKeyHashMismatch();

        RootEntry memory entry = RootEntry({
            merkleRoot: merkleRoot,
            checkpointSeq: checkpointSeq,
            batchStartSeq: batchStartSeq,
            batchEndSeq: batchEndSeq,
            treeSize: treeSize,
            publishedAt: uint64(block.timestamp),
            operatorKeyHash: operatorKeyHash
        });

        rootEntries[operator][checkpointSeq] = entry;
        latestSeq[operator] = checkpointSeq;
        latestBatchEndSeq[operator] = batchEndSeq;
        publishedRoots[operator][merkleRoot] = true;
        rootTreeSizes[operator][merkleRoot] = treeSize;

        emit RootPublished(
            operator,
            publisher,
            checkpointSeq,
            merkleRoot,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            entry.publishedAt,
            operatorKeyHash
        );
    }
}
