// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "src/mocks/MockERC20.sol";

/// Local test asset with EIP-3009 authorization, used by the official x402 client.
/// Minting remains unrestricted, as in MockERC20. Never deploy this test asset.
contract LocalPaymentToken is MockERC20 {
    string public constant version = "1";
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    constructor() MockERC20("Work order test dollars", "wUSD", 6) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this)
        ));
    }

    function transferWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter,
        uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp > validAfter && block.timestamp < validBefore, "authorization expired or not active");
        require(!authorizationState[from][nonce], "authorization used");
        require(v == 27 || v == 28, "invalid recovery id");
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "noncanonical signature");
        bytes32 message = keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        address recovered = ecrecover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, message)), v, r, s);
        require(recovered != address(0) && recovered == from, "invalid authorization");
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }
}
