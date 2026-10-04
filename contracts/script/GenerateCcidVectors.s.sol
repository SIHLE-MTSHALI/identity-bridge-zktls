// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CCIDResolver} from "../src/CCIDResolver.sol";
import {Script, console} from "forge-std/Script.sol";

/**
 * @title GenerateCcidVectors
 * @notice Emits CCID test vectors computed by the on-chain resolver.
 *
 * @dev ## Why this exists
 *
 *      The workflow derives the same CCID the contract validates. If the two ever
 *      disagree on field order, hash, or integer widening, the symptom is that the
 *      bridge rejects *every* credential result with `InvalidCCID` - or, far worse,
 *      that a result is accepted while bound to the wrong subject.
 *
 *      Nothing unit-testing TypeScript alone can catch that, because the TypeScript
 *      would only ever be compared against itself. So the contract emits
 *      authoritative vectors and `workflows/test/ccid-parity.test.ts` asserts the
 *      workflow reproduces every one of them exactly.
 *
 *      Run:
 *        pnpm run vectors:ccid
 */
contract GenerateCcidVectors is Script {
    function run() external {
        CCIDResolver resolver = new CCIDResolver();
        bytes32 domain = resolver.DOMAIN();

        console.log(string.concat("{\"domain\": \"", vm.toString(domain), "\", \"vectors\": ["));

        // Fixed inputs, including edge cases where a widening mistake would hide:
        // a zero schema version, a max uint32, and zero-valued identifiers.
        // Labels are emitted alongside the hashes because the workflow derives its
        // bytes32 identifiers from labels, so parity can only be checked from the
        // label side. Re-deriving the label from the hash is impossible.
        _emit(resolver, "kyc.basic", 1, "provider.reclaim", "subject-alice");
        _emit(resolver, "kyc.basic", 2, "provider.mock-zktls", "subject-bob");
        _emit(resolver, "accreditation.investor", 1, "provider.reclaim", "subject-carol");
        _emit(resolver, "kyc.basic", 0, "provider.reclaim", "subject-dave");
        _emit(resolver, "kyc.basic", 1, "", "subject-erin");
        _emit(resolver, "kyc.basic", 1, "provider.reclaim", "");
        _emit(resolver, "", 1, "provider.reclaim", "subject-frank");
        _emit(resolver, "kyc.basic", 4_294_967_295, "provider.reclaim", "subject-grace");

        console.log("]}");
    }

    function _emit(
        CCIDResolver resolver,
        string memory credentialTypeLabel,
        uint32 schemaVersion,
        string memory providerIdLabel,
        string memory subjectLabel
    ) private view {
        bytes32 credentialType = keccak256(bytes(credentialTypeLabel));
        bytes32 providerId = keccak256(bytes(providerIdLabel));
        bytes32 subjectCommitment = keccak256(bytes(subjectLabel));
        bytes32 ccid = resolver.compute(credentialType, schemaVersion, providerId, subjectCommitment);

        console.log(
            string.concat(
                "  {\"credentialTypeLabel\": \"",
                credentialTypeLabel,
                "\", \"providerIdLabel\": \"",
                providerIdLabel,
                "\", \"subjectLabel\": \"",
                subjectLabel,
                "\", \"credentialType\": \"",
                vm.toString(credentialType),
                "\", \"schemaVersion\": ",
                vm.toString(uint256(schemaVersion)),
                ", \"providerId\": \"",
                vm.toString(providerId),
                "\", \"subjectCommitment\": \"",
                vm.toString(subjectCommitment),
                "\", \"ccid\": \"",
                vm.toString(ccid),
                "\"},"
            )
        );
    }
}
