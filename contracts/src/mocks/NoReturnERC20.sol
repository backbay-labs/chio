// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract NoReturnERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
    }

    function transfer(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "insufficient allowance");
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero recipient");
        uint256 fromBalance = balanceOf[from];
        require(fromBalance >= amount, "insufficient balance");
        balanceOf[from] = fromBalance - amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
