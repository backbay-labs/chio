// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ChioMerkle} from "../lib/ChioMerkle.sol";

interface IReentrantBondVault {
    function impairBondDetailed(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    function releaseBondDetailed(
        bytes32 vaultId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;
}

interface IReentrantRootRegistry {
    function publishRoot(
        address operator,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) external;
}

contract ReentrantBondToken {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    IReentrantBondVault private reentryVault;
    bytes32 private reentryVaultId;
    bytes32 private reentryRoot;
    bytes32 private reentryEvidenceHash;
    bytes32[] private reentryAuditPath;
    uint256 private reentryLeafIndex;
    uint256 private reentryTreeSize;
    bool private reentryArmed;
    bool private reentryEntered;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "insufficient allowance");
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function publishRoot(
        address rootRegistry,
        bytes32 merkleRoot,
        uint64 checkpointSeq,
        uint64 batchStartSeq,
        uint64 batchEndSeq,
        uint64 treeSize,
        bytes32 operatorKeyHash
    ) external {
        IReentrantRootRegistry(rootRegistry).publishRoot(
            address(this),
            merkleRoot,
            checkpointSeq,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            operatorKeyHash
        );
    }

    function configureReleaseReentry(
        address vault,
        bytes32 vaultId,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external {
        reentryVault = IReentrantBondVault(vault);
        reentryVaultId = vaultId;
        reentryRoot = root;
        reentryEvidenceHash = evidenceHash;
        reentryLeafIndex = proof.leafIndex;
        reentryTreeSize = proof.treeSize;
        delete reentryAuditPath;
        for (uint256 index = 0; index < proof.auditPath.length; ++index) {
            reentryAuditPath.push(proof.auditPath[index]);
        }
        reentryArmed = true;
        reentryEntered = false;
    }

    function impairBond(
        address vault,
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        ChioMerkle.Proof calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external {
        IReentrantBondVault(vault).impairBondDetailed(
            vaultId, slashAmount, beneficiaries, shares, proof, root, evidenceHash
        );
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero recipient");
        uint256 fromBalance = balanceOf[from];
        require(fromBalance >= amount, "insufficient balance");
        balanceOf[from] = fromBalance - amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);

        if (reentryArmed && !reentryEntered && from == address(reentryVault)) {
            reentryEntered = true;
            reentryArmed = false;
            ChioMerkle.Proof memory proof = ChioMerkle.Proof({
                auditPath: _copyAuditPath(),
                leafIndex: reentryLeafIndex,
                treeSize: reentryTreeSize
            });
            reentryVault.releaseBondDetailed(
                reentryVaultId, proof, reentryRoot, reentryEvidenceHash
            );
        }
    }

    function _copyAuditPath() private view returns (bytes32[] memory auditPath) {
        auditPath = new bytes32[](reentryAuditPath.length);
        for (uint256 index = 0; index < reentryAuditPath.length; ++index) {
            auditPath[index] = reentryAuditPath[index];
        }
    }
}
