// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ChioMerkle} from "../lib/ChioMerkle.sol";

interface IChioRootRegistry {
    struct RootEntry {
        bytes32 merkleRoot;
        uint64 checkpointSeq;
        uint64 batchStartSeq;
        uint64 batchEndSeq;
        uint64 treeSize;
        uint64 publishedAt;
        bytes32 operatorKeyHash;
        uint64 operatorEpoch;
    }

    event RootPublished(
        address indexed operator,
        address indexed publisher,
        uint64 indexed checkpointSeq,
        bytes32 merkleRoot,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        uint64 publishedAt,
        bytes32 operatorKeyHash,
        uint64 operatorEpoch
    );

    event DelegateRegistered(address indexed operator, address indexed delegate, uint64 expiresAt);

    event DelegateRevoked(address indexed operator, address indexed delegate);

    function publishRoot(
        address operator,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) external;

    function publishRootBatch(
        address operator,
        bytes32[] calldata merkleRoots,
        uint64[] calldata checkpointSeqs,
        uint64[] calldata batchStartSeqs,
        uint64[] calldata batchEndSeqs,
        uint64[] calldata treeSizes,
        bytes32 operatorKeyHash
    ) external;

    function registerDelegate(address delegate, uint64 expiresAt) external;

    function revokeDelegate(address delegate) external;

    function isAuthorizedPublisher(address operator, address publisher)
        external
        view
        returns (bool);

    function isAuthorizedPublisherForKeyHash(
        address operator,
        address publisher,
        bytes32 operatorKeyHash
    ) external view returns (bool);

    function verifyInclusion(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator
    ) external view returns (bool valid);

    function verifyInclusionDetailed(
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator
    ) external pure returns (bool valid);

    function verifyInclusionDetailedForKeyHash(
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator,
        bytes32 operatorKeyHash
    ) external view returns (bool valid);

    function getLatestRoot(address operator) external view returns (RootEntry memory);

    function getRoot(address operator, uint64 checkpointSeq) external view returns (RootEntry memory);

    function getLatestSeq(address operator) external view returns (uint64);
}
