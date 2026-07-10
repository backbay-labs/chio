// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IChioPriceResolver {
    struct PriceFeed {
        address aggregator;
        uint256 maxStalenessSeconds;
        uint8 decimals;
        string description;
    }

    event FeedRegistered(
        bytes32 indexed base,
        bytes32 indexed quote,
        address aggregator,
        uint256 maxStalenessSeconds
    );

    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    function admin() external view returns (address);

    function pendingAdmin() external view returns (address);

    function transferAdmin(address newAdmin) external;

    function acceptAdmin() external;

    function getPrice(bytes32 base, bytes32 quote)
        external
        view
        returns (int256 price, uint8 decimals, uint256 updatedAt);

    function registerFeed(
        bytes32 base,
        bytes32 quote,
        address aggregator,
        uint256 maxStalenessSeconds
    ) external;

    function sequencerStatus() external view returns (bool up, uint256 startedAt);
}
