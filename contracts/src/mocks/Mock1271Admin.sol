// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract Mock1271Admin {
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant INVALID_VALUE = 0xffffffff;
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    error NotOwner();
    error CallFailed();

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory result) {
        if (msg.sender != owner) revert NotOwner();
        (bool ok, bytes memory returnData) = target.call(data);
        if (!ok) revert CallFailed();
        return returnData;
    }

    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (signature.length != 65) return INVALID_VALUE;

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
        if (v != 27 && v != 28) return INVALID_VALUE;
        if (uint256(s) > SECP256K1_HALF_ORDER) return INVALID_VALUE;

        address signer = ecrecover(digest, v, r, s);
        return signer == owner ? MAGIC_VALUE : INVALID_VALUE;
    }
}
