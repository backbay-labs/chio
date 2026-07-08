// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IChioIdentityRegistry {
    struct OperatorRecord {
        bytes32 edKeyHash;
        address settlementKey;
        uint64 registeredAt;
        uint64 operatorEpoch;
        bool active;
    }

    struct EntityRecord {
        bytes32 chioEntityId;
        address settlementAddress;
        address operator;
        uint64 registeredAt;
        bool active;
    }

    event OperatorRegistered(
        address indexed operatorAddress,
        bytes32 indexed edKeyHash,
        address settlementKey
    );

    event OperatorDeactivated(address indexed operatorAddress);

    event OperatorReactivated(address indexed operatorAddress);

    event EntityRegistered(
        bytes32 indexed chioEntityId,
        address indexed settlementAddress,
        address indexed operator
    );

    event EntityDeactivated(bytes32 indexed chioEntityId, address indexed operator);

    event EntityReassigned(
        bytes32 indexed chioEntityId,
        address indexed settlementAddress,
        address indexed operator
    );

    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    function admin() external view returns (address);

    function pendingAdmin() external view returns (address);

    function transferAdmin(address newAdmin) external;

    function acceptAdmin() external;

    function registerOperator(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) external;

    function deactivateOperator(address operatorAddress) external;

    function reactivateOperator(address operatorAddress) external;

    function registerEntity(
        bytes32 chioEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external;

    function deactivateEntity(bytes32 chioEntityId) external;

    function reassignEntity(
        bytes32 chioEntityId,
        address settlementAddress,
        address operatorAddress,
        bytes calldata bindingProof
    ) external;

    function isOperator(address addr) external view returns (bool);

    function getSettlementKey(address operator) external view returns (address);

    function getEntityAddress(bytes32 chioEntityId) external view returns (address);

    function getOperator(address operator) external view returns (OperatorRecord memory);
}
