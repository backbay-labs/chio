// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IAggregatorV3} from "./interfaces/IAggregatorV3.sol";
import {IChioPriceResolver} from "./interfaces/IChioPriceResolver.sol";

contract ChioPriceResolver is IChioPriceResolver {
    error NotAdmin();
    error ZeroAddress();
    error FeedNotConfigured();
    error StalePrice();
    error SequencerDown();
    error InvalidPrice();
    error InvalidTimestamp();
    error InvalidRound();
    error SequencerGracePeriodActive();
    error NotPendingAdmin();
    error InvalidStaleness();

    uint256 private constant SEQUENCER_GRACE_PERIOD_SECONDS = 3600;
    uint256 public constant MAX_FEED_STALENESS_SECONDS = 7 days;

    address public admin;
    address public pendingAdmin;
    address public immutable sequencerFeed;

    mapping(bytes32 => PriceFeed) private feeds;

    constructor(address admin_, address sequencerFeed_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
        sequencerFeed = sequencerFeed_;
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

    function registerFeed(
        bytes32 base,
        bytes32 quote,
        address aggregator,
        uint256 maxStalenessSeconds
    ) external onlyAdmin {
        if (aggregator == address(0)) revert ZeroAddress();
        if (
            maxStalenessSeconds == 0 ||
            maxStalenessSeconds > MAX_FEED_STALENESS_SECONDS
        ) {
            revert InvalidStaleness();
        }
        feeds[_feedKey(base, quote)] = PriceFeed({
            aggregator: aggregator,
            maxStalenessSeconds: maxStalenessSeconds,
            decimals: IAggregatorV3(aggregator).decimals(),
            description: IAggregatorV3(aggregator).description()
        });
        emit FeedRegistered(base, quote, aggregator, maxStalenessSeconds);
    }

    function getPrice(bytes32 base, bytes32 quote)
        external
        view
        returns (int256 price, uint8 decimals, uint256 updatedAt)
    {
        (bool up, uint256 sequencerStartedAt) = sequencerStatus();
        if (!up) revert SequencerDown();
        if (
            sequencerFeed != address(0) &&
            block.timestamp <= sequencerStartedAt + SEQUENCER_GRACE_PERIOD_SECONDS
        ) {
            revert SequencerGracePeriodActive();
        }

        PriceFeed memory feed = feeds[_feedKey(base, quote)];
        if (feed.aggregator == address(0)) revert FeedNotConfigured();

        (uint80 roundId, int256 answer, uint256 startedAt, uint256 reportedUpdatedAt, uint80 answeredInRound) =
            IAggregatorV3(feed.aggregator).latestRoundData();
        price = answer;
        updatedAt = reportedUpdatedAt;
        if (roundId == 0 || answeredInRound < roundId) revert InvalidRound();
        if (price <= 0) revert InvalidPrice();
        if (
            startedAt == 0 || updatedAt == 0 || startedAt > updatedAt
                || updatedAt > block.timestamp
        ) {
            revert InvalidTimestamp();
        }
        if (block.timestamp > updatedAt + feed.maxStalenessSeconds) revert StalePrice();
        return (price, feed.decimals, updatedAt);
    }

    function sequencerStatus() public view returns (bool up, uint256 startedAt) {
        if (sequencerFeed == address(0)) {
            return (true, block.timestamp);
        }
        (uint80 roundId, int256 answer, uint256 reportedStartedAt, uint256 updatedAt, uint80 answeredInRound) =
            IAggregatorV3(sequencerFeed).latestRoundData();
        if (roundId == 0 || answeredInRound < roundId) revert InvalidRound();
        if (
            reportedStartedAt == 0 || updatedAt == 0 || reportedStartedAt > updatedAt
                || updatedAt > block.timestamp
        ) {
            revert InvalidTimestamp();
        }
        return (answer == 0, reportedStartedAt);
    }

    function _feedKey(bytes32 base, bytes32 quote) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(base, quote));
    }
}
