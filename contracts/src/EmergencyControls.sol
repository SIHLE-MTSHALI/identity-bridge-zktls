// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title EmergencyControls
 * @notice System-wide pause with a reason, consulted by every write and access path.
 *
 * @dev ## Fail-closed by design
 *
 *      While paused, {PolicyManagerAdapter.evaluate} returns
 *      `SYSTEM_PAUSED` and `allowed == false`. This is the safe direction: if the
 *      system cannot tell whether its own state is trustworthy, it must not
 *      report that a credential is fine.
 *
 *      A pause cannot hide existing state. {CredentialRegistry} reads stay
 *      available so holders, integrators, and auditors keep visibility into what
 *      is true right now - a pause stops new decisions, it does not rewrite
 *      history.
 *
 *      ## Roles
 *
 *      `GUARDIAN` can pause immediately and needs no delay, because the whole
 *      point is to be able to stop during an incident. `ADMIN` can unpause and
 *      must go through a timelock, so that resuming cannot be rushed in response
 *      to pressure during an unresolved incident. This asymmetry is intentional:
 *      stopping is cheap and reversible, resuming is the risky direction.
 */
contract EmergencyControls is AccessControl {
    /// @dev keccak256("GUARDIAN") - may pause immediately. May not unpause.
    bytes32 public constant GUARDIAN = keccak256("GUARDIAN");

    /// @dev keccak256("TIMELOCK_ADMIN") - may unpause, subject to {UNPAUSE_DELAY}.
    bytes32 public constant TIMELOCK_ADMIN = keccak256("TIMELOCK_ADMIN");

    /// @notice Emitted whenever the pause state changes.
    event PauseStateChanged(bool paused, string reason);

    /// @notice Emitted when a resume is scheduled, before the delay elapses.
    event UnpauseScheduled(uint64 executableAt, string reason);

    /// @notice Emitted when a scheduled resume actually executes.
    event UnpauseExecuted();

    /// @dev keccak256("DEFAULT_ADMIN_ROLE") - role administration and scheduling.
    bytes32 private constant _ADMIN = keccak256("DEFAULT_ADMIN_ROLE");

    /// @notice True while the system is paused.
    bool public paused;

    /// @notice Earliest timestamp at which a scheduled unpause may execute.
    uint64 public unpauseExecutableAt;

    /// @notice Delay that must elapse between scheduling and executing an unpause.
    uint64 public constant UNPAUSE_DELAY = 24 hours;

    /// @notice Max reason string length, so events stay cheap and bounded.
    uint256 public constant MAX_REASON_LENGTH = 256;

    error NotGuardian(address caller);
    error NotTimelockAdmin(address caller);
    error InvalidAddress();
    error ReasonTooLong(uint256 length);
    error AlreadyPaused();
    error NotPaused();
    error UnpauseNotScheduled();
    error UnpauseDelayNotElapsed(uint64 executableAt, uint64 nowTs);

    constructor(address admin, address guardian) {
        if (admin == address(0) || guardian == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(_ADMIN, admin);
        _grantRole(GUARDIAN, guardian);
        _grantRole(TIMELOCK_ADMIN, admin);
    }

    modifier onlyGuardian() {
        if (!hasRole(GUARDIAN, msg.sender)) revert NotGuardian(msg.sender);
        _;
    }

    modifier onlyTimelockAdmin() {
        if (!hasRole(TIMELOCK_ADMIN, msg.sender)) revert NotTimelockAdmin(msg.sender);
        _;
    }

    function isPaused() external view returns (bool) {
        return paused;
    }

    /**
     * @notice Pause the system. Immediate, single-call, no delay.
     * @param reason Short human-readable cause, emitted for responders. Must not
     *        contain sensitive data; it is public chain state.
     */
    function pause(string calldata reason) external onlyGuardian {
        if (paused) revert AlreadyPaused();
        if (bytes(reason).length > MAX_REASON_LENGTH) revert ReasonTooLong(bytes(reason).length);
        paused = true;
        unpauseExecutableAt = 0;
        emit PauseStateChanged(true, reason);
    }

    /**
     * @notice Schedule an unpause. Executes no earlier than `UNPAUSE_DELAY` later.
     * @dev Two steps so that resuming is always a deliberate, public, delayed act.
     */
    function scheduleUnpause(string calldata reason) external onlyTimelockAdmin {
        if (!paused) revert NotPaused();
        if (bytes(reason).length > MAX_REASON_LENGTH) revert ReasonTooLong(bytes(reason).length);
        unpauseExecutableAt = uint64(block.timestamp) + UNPAUSE_DELAY;
        emit UnpauseScheduled(unpauseExecutableAt, reason);
        emit PauseStateChanged(false, reason);
    }

    /// @notice Execute a scheduled unpause once the delay has elapsed.
    function executeUnpause() external onlyTimelockAdmin {
        if (!paused) revert NotPaused();
        if (unpauseExecutableAt == 0) revert UnpauseNotScheduled();
        if (uint64(block.timestamp) < unpauseExecutableAt) {
            revert UnpauseDelayNotElapsed(unpauseExecutableAt, uint64(block.timestamp));
        }
        paused = false;
        unpauseExecutableAt = 0;
        emit UnpauseExecuted();
        emit PauseStateChanged(false, "");
    }

    /// @notice Cancel a scheduled unpause. Does not unpause.
    function cancelUnpause() external onlyTimelockAdmin {
        if (!paused) revert NotPaused();
        unpauseExecutableAt = 0;
        emit PauseStateChanged(true, "unpause cancelled");
    }
}
