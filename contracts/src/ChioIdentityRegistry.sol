// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IChioIdentityRegistry} from "./interfaces/IChioIdentityRegistry.sol";

contract ChioIdentityRegistry is IChioIdentityRegistry {
    bytes32 private constant ENTITY_BINDING_TYPEHASH =
        keccak256("ChioEntityBinding(bytes32 chioEntityId,address settlementAddress,address operator)");
    bytes32 private constant OPERATOR_BINDING_TYPEHASH =
        keccak256("ChioOperatorBinding(address operatorAddress,bytes32 edKeyHash,address settlementKey)");
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant EIP712_NAME_HASH = keccak256("ChioIdentityRegistry");
    bytes32 private constant EIP712_VERSION_HASH = keccak256("1");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    error NotAdmin();
    error ZeroAddress();
    error OperatorAlreadyRegistered();
    error OperatorNotActive();
    error EntityAlreadyRegistered();
    error EntityNotFound();
    error EntityNotActive();
    error InvalidEntity();
    error InvalidOperatorKeyHash();
    error InvalidSignature();
    error NotPendingAdmin();

    event OperatorBindingProofRecorded(address indexed operatorAddress, bytes bindingProof);
    event EntityBindingProofRecorded(bytes32 indexed chioEntityId, bytes bindingProof);

    address public admin;
    address public pendingAdmin;

    mapping(address => OperatorRecord) private operatorRecords;
    mapping(bytes32 => EntityRecord) private entityRecords;

    constructor(address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
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

    function registerOperator(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) external onlyAdmin {
        if (operatorAddress == address(0) || settlementKey == address(0)) revert ZeroAddress();
        if (edKeyHash == bytes32(0)) revert InvalidOperatorKeyHash();
        _requireOperatorBinding(operatorAddress, edKeyHash, settlementKey, bindingProof);
        OperatorRecord storage record = operatorRecords[operatorAddress];
        if (record.active) revert OperatorAlreadyRegistered();
        uint64 nextEpoch = record.operatorEpoch + 1;

        operatorRecords[operatorAddress] = OperatorRecord({
            edKeyHash: edKeyHash,
            settlementKey: settlementKey,
            registeredAt: uint64(block.timestamp),
            operatorEpoch: nextEpoch,
            active: true
        });

        emit OperatorRegistered(operatorAddress, edKeyHash, settlementKey);
        emit OperatorBindingProofRecorded(operatorAddress, bindingProof);
    }

    function deactivateOperator(address operatorAddress) external onlyAdmin {
        OperatorRecord storage record = operatorRecords[operatorAddress];
        if (!record.active) revert OperatorNotActive();
        record.operatorEpoch += 1;
        record.active = false;
        emit OperatorDeactivated(operatorAddress);
    }

    function reactivateOperator(address operatorAddress) external onlyAdmin {
        if (operatorAddress == address(0)) revert ZeroAddress();
        OperatorRecord storage record = operatorRecords[operatorAddress];
        if (record.registeredAt == 0) revert OperatorNotActive();
        if (record.active) revert OperatorAlreadyRegistered();
        record.operatorEpoch += 1;
        record.active = true;
        emit OperatorReactivated(operatorAddress);
    }

    function registerEntity(
        bytes32 chioEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external {
        if (chioEntityId == bytes32(0)) revert InvalidEntity();
        if (!operatorRecords[msg.sender].active) revert OperatorNotActive();
        if (settlementAddress == address(0)) revert ZeroAddress();
        _requireEntityBinding(chioEntityId, settlementAddress, msg.sender, bindingProof);
        EntityRecord storage record = entityRecords[chioEntityId];
        if (record.registeredAt != 0 && record.active) revert EntityAlreadyRegistered();

        entityRecords[chioEntityId] = EntityRecord({
            chioEntityId: chioEntityId,
            settlementAddress: settlementAddress,
            operator: msg.sender,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit EntityRegistered(chioEntityId, settlementAddress, msg.sender);
        emit EntityBindingProofRecorded(chioEntityId, bindingProof);
    }

    function deactivateEntity(bytes32 chioEntityId) external onlyAdmin {
        if (chioEntityId == bytes32(0)) revert InvalidEntity();
        EntityRecord storage record = entityRecords[chioEntityId];
        if (record.registeredAt == 0) revert EntityNotFound();
        if (!record.active) revert EntityNotActive();
        record.active = false;
        emit EntityDeactivated(chioEntityId, record.operator);
    }

    function reassignEntity(
        bytes32 chioEntityId,
        address settlementAddress,
        address operatorAddress,
        bytes calldata bindingProof
    ) external onlyAdmin {
        if (chioEntityId == bytes32(0)) revert InvalidEntity();
        if (settlementAddress == address(0) || operatorAddress == address(0)) revert ZeroAddress();
        if (!operatorRecords[operatorAddress].active) revert OperatorNotActive();
        EntityRecord storage record = entityRecords[chioEntityId];
        if (record.registeredAt == 0) revert EntityNotFound();
        _requireEntityBinding(chioEntityId, settlementAddress, operatorAddress, bindingProof);

        entityRecords[chioEntityId] = EntityRecord({
            chioEntityId: chioEntityId,
            settlementAddress: settlementAddress,
            operator: operatorAddress,
            registeredAt: uint64(block.timestamp),
            active: true
        });

        emit EntityReassigned(chioEntityId, settlementAddress, operatorAddress);
        emit EntityBindingProofRecorded(chioEntityId, bindingProof);
    }

    function isOperator(address addr) external view returns (bool) {
        return operatorRecords[addr].active;
    }

    function getSettlementKey(address operator) external view returns (address) {
        return operatorRecords[operator].settlementKey;
    }

    function getEntityAddress(bytes32 chioEntityId) external view returns (address) {
        EntityRecord storage record = entityRecords[chioEntityId];
        if (record.registeredAt == 0) revert EntityNotFound();
        if (!record.active || !operatorRecords[record.operator].active) revert EntityNotActive();
        return record.settlementAddress;
    }

    function getOperator(address operator) external view returns (OperatorRecord memory) {
        return operatorRecords[operator];
    }

    function _requireOperatorBinding(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) internal view {
        bytes32 structHash = keccak256(
            abi.encode(OPERATOR_BINDING_TYPEHASH, operatorAddress, edKeyHash, settlementKey)
        );
        _requireAdminSignature(structHash, bindingProof);
    }

    function _requireEntityBinding(
        bytes32 chioEntityId,
        address settlementAddress,
        address operatorAddress,
        bytes calldata bindingProof
    ) internal view {
        bytes32 structHash = keccak256(
            abi.encode(ENTITY_BINDING_TYPEHASH, chioEntityId, settlementAddress, operatorAddress)
        );
        _requireAdminSignature(structHash, bindingProof);
    }

    function _requireAdminSignature(bytes32 structHash, bytes calldata bindingProof) internal view {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                EIP712_NAME_HASH,
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        if (admin.code.length == 0) {
            if (_recoverSigner(digest, bindingProof) != admin) revert InvalidSignature();
            return;
        }

        (bool ok, bytes memory returnData) = admin.staticcall(
            abi.encodeWithSelector(ERC1271_MAGIC_VALUE, digest, bindingProof)
        );
        if (!ok || returnData.length < 32 || abi.decode(returnData, (bytes4)) != ERC1271_MAGIC_VALUE) {
            revert InvalidSignature();
        }
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) revert InvalidSignature();
        if (uint256(s) > SECP256K1_HALF_ORDER) revert InvalidSignature();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
}
