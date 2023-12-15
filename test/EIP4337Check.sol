pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import "forge-std/console2.sol";

library EIP4337Check {

    function validateUserOp(
        Vm.DebugStep[] memory debugSteps,
        UserOperation memory userOp,
        EntryPoint entryPoint
    ) internal view returns (bool) {
        Vm.DebugStep[] memory senderSteps = new Vm.DebugStep[](debugSteps.length);
        uint128 senderStepsLen = 0;

        address currentAddr;
        for (uint256 i = 0; i < debugSteps.length; i++) {
            // We start analyze the forbidden opcodes from depth > 2
            // Note that in forge test, the "test" itself wiill be depth 1. So the EntryPoint will be depth 2.
            //
            // Also, the `EntryPoint.simulateValidation()` function do have call back to
            // the EntryPoint contract with `this.xxx()` so we will need to filter those as well.
            // The code here group the opcodes by addresses, and then we only check the
            // forbidden opcodes on those addresses we are interested.
            if (debugSteps[i].depth == 2) {
                uint8 opcode = debugSteps[i].opcode;
                if (opcode == 0xF1 || opcode == 0xFA) { // CALL and STATICCALL
                    currentAddr = address(uint160(debugSteps[i].stack[1]));
                }

                // ignore all opcodes on depth 1 and do not add to the `addrToOpcodes` mapping
                continue;
            }

            if (debugSteps[i].depth > 2 && currentAddr == userOp.sender) {
                senderSteps[senderStepsLen++] = debugSteps[i];
            }
        }

        // Reset the senderOpcodes to correct length
        assembly {
            mstore(senderSteps, senderStepsLen)
        }

        if (!validateForbiddenOpcodes(senderSteps)) {
            console2.log("Invalid Sender Opcodes (validateUserOp)");
            return false;
        }
        if (!validateCall(senderSteps, address(entryPoint), true)) {
            console2.log("Breaching Call Limitation (validateUserOp)");
            return false;
        }
        if (!validateExtcodeMayNotAccessAddressWithoutCode(senderSteps)) {
            console2.log("EXTCODEHASH, EXTCODELENGTH, EXTCODECOPY may not access address with no code");
            return false;
        }
        if (!validateCreate2(senderSteps, userOp)) {
            console2.log("allow at most one CREATE2 opcode call only when op.initcode.length != 0");
            return false;
        }

        if(!validateStorage(senderSteps, userOp, entryPoint)) {
            console2.log("Storage access rule breached");
            return false;
        }

        return true;
    }

    function validateStorage(
        Vm.DebugStep[] memory debugSteps,
        UserOperation memory userOp,
        EntryPoint entryPoint
    ) private view returns (bool) {
        address factory = getFactoryAddr(userOp);
        IStakeManager.StakeInfo memory factoryStakeInfo = getStakeInfo(factory, entryPoint);

        address paymaster = getPaymasterAddr(userOp);
        IStakeManager.StakeInfo memory paymasterStakeInfo = getStakeInfo(paymaster, entryPoint);

        bytes32[] memory associatedSlots = findAddressAssociatedSlots(userOp.sender, debugSteps);

        for (uint i=0 ; i < debugSteps.length; i++) {
            Vm.DebugStep memory debugStep = debugSteps[i];
            uint8 opcode = debugSteps[i].opcode;
            if (opcode != 0x54 /*SLOAD*/ && opcode != 0x55 /*SSTORE*/) {
                continue;
            }


            // self storage (of factory/paymaster, respectively) is allowed,
            // but only if self entity is staked
            //
            // note: this implementation only take into the original EIP-4337 spec.
            // There are slight difference with the draft spec from eth-infinitism:
            // https://github.com/eth-infinitism/account-abstraction/blob/develop/eip/EIPS/eip-aa-rules.md#storage-rules
            // see: STO-032, and STO-033
            if (
                debugStep.contractAddr == factory
                && factoryStakeInfo.stake > 0
                && factoryStakeInfo.unstakeDelaySec > 0
            ) {
                continue;
            }
            if (
                debugStep.contractAddr == paymaster
                && paymasterStakeInfo.stake > 0
                && paymasterStakeInfo.unstakeDelaySec > 0
            ) {
                continue;
            }

            // account storage access is allowed, including address associated storage
            if (debugStep.contractAddr == userOp.sender) {
                // Slots of contract A address itself
                continue;
            }

            bytes32 key = bytes32(debugStep.stack[0]);

            bool isAssociated;
            for (uint j=0 ; j < associatedSlots.length; j++) {
                if (key == associatedSlots[j]) {
                    console2.log("found associated slot on account: ", debugStep.contractAddr);
                    console2.logBytes32(key);
                    isAssociated = true;
                    break;
                }
            }
            if (!isAssociated) {
                console2.log("non-associated slot detected on account: ", debugStep.contractAddr);
                console2.logBytes32(key);
                console2.log("sender address: ", userOp.sender);
                return false;
            }
        }

        return true;
    }

    function findAddressAssociatedSlots(
        address addr,
        Vm.DebugStep[] memory debugSteps
    ) private pure returns (bytes32[] memory) {
        bytes32[] memory associatedSlots = new bytes32[](debugSteps.length * 128);
        uint slotLen = 0;

        for (uint256 i = 0; i < debugSteps.length; i++) {
            uint8 opcode = debugSteps[i].opcode;

            if (opcode != 0x20 /*SHA3*/) {
                continue;
            }

            // find the inputs for the KECCAK256
            bytes memory input = new bytes(debugSteps[i].memoryData.length);
            for(uint j = 0; j < debugSteps[i].memoryData.length; j++) {
                input[j] = bytes1(debugSteps[i].memoryData[j]);
            }

            // console2.log("searching associated slot: ", addr);
            // console2.logBytes(input);
            address inputStartAddr = address(uint160(uint256(bytes32(input))));
            if (input.length >= 20 && inputStartAddr == addr) {
                // console2.log("found associated slot: ", addr);
                // console2.logBytes(input);
                // Slots of type keccak256(A || X) + n, n in range [0, 128]
                for (uint j = 0; j < 128; j++) {
                    unchecked {
                        associatedSlots[slotLen++] = bytes32(uint256(keccak256(input)) + j);
                    }
                }
            }
        }

        // Reset to correct length
        assembly {
            mstore(associatedSlots, slotLen)
        }

        return associatedSlots;
    }

    function getStakeInfo(address addr, EntryPoint entryPoint) internal view returns (IStakeManager.StakeInfo memory) {
        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(addr);

        return IStakeManager.StakeInfo({
            stake: depositInfo.stake,
            unstakeDelaySec: depositInfo.unstakeDelaySec
        });
    }

    function getFactoryAddr(UserOperation memory userOp) private pure returns (address) {
        bytes memory initCode = userOp.initCode;
        return initCode.length >= 20 ? address(bytes20(initCode)) : address(0);
    }

    function getPaymasterAddr(UserOperation memory userOp) private pure returns (address) {
        bytes memory pData = userOp.paymasterAndData;
        return pData.length >= 20 ? address(bytes20(pData)) : address(0);
    }

    /**
     * May not invokes any forbidden opcodes
     * Must not use GAS opcode (unless followed immediately by one of { CALL, DELEGATECALL, CALLCODE, STATICCALL }.)
     */
    function validateForbiddenOpcodes(Vm.DebugStep[] memory debugSteps) private pure returns (bool) {
        for (uint256 i = 0; i < debugSteps.length; i++) {
            uint8 opcode = debugSteps[i].opcode;
            if (isForbiddenOpcode(opcode)) {
                // exception case for GAS opcode
                if (opcode == 0x5A && i < debugSteps.length -1) {
                    if (!isValidNextOpcodeOfGas(debugSteps[i+1].opcode)) {
                        console2.log("fobidden GAS op-code, next opcode: ", debugSteps[i+1].opcode, "depth: ", debugSteps[i].depth);
                        return false;
                    }
                } else {
                    console2.log("fobidden op-code: ", opcode, "depth: ", debugSteps[i].depth);
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Limitation on “CALL” opcodes (CALL, DELEGATECALL, CALLCODE, STATICCALL):
     * ✅ 1. must not use value (except from account to the entrypoint)
     * ✅ 2. must not revert with out-of-gas
     * ✅ 3. destination address must have code (EXTCODESIZE>0) or be a standard Ethereum precompile defined at addresses from 0x01 to 0x09
     * ✅ 4. cannot call EntryPoint’s methods, except depositTo (to avoid recursion)
     */
    function validateCall(
        Vm.DebugStep[] memory debugSteps,
        address entryPoint,
        bool isFromAccount
    ) private view returns (bool) {
        for (uint256 i = 0; i < debugSteps.length; i++) {
            // the current mechanism will only record the instruction result on the last opcode
            // that failed. It will not go all the way back to the call related opcode so
            // need to call this before filtering
            if (isCallOutOfGas(debugSteps[i])) { // TODO: checked, not working as expected :(
                console2.log("must not revert with out-of-gas");
                return false;
            }

            // we only care about OPCODES related to calls, so filter out those unrelated.
            uint8 op = debugSteps[i].opcode;
            if (op != 0xF1 /*CALL*/
                && op != 0xF2 /*CALLCODE*/
                && op != 0xF4 /*DELEGATECALL*/
                && op != 0xFA /*STATICCALL*/
            ) {
                continue;
            }

            if (isCallWithValue(debugSteps[i], entryPoint, isFromAccount)) {
                console2.log("must not use value (except from account to the entrypoint)");
                return false;
            }
            if (!isPrecompile(debugSteps[i]) && isCallWithEmptyCode(debugSteps[i])) {
                address dest = address(uint160(debugSteps[i].stack[1]));
                console2.log("destination address must have code or be precompile: ", dest, op);
                return false;
            }
            if (isCallToEntryPoint(debugSteps[i], entryPoint)) {
                console2.log("cannot call EntryPoint methods, except depositTo");
                return false;
            }
        }
        return true;
    }

    function validateExtcodeMayNotAccessAddressWithoutCode(
        Vm.DebugStep[] memory debugSteps
    ) private view returns (bool) {
        for (uint256 i = 0; i < debugSteps.length; i++) {
            uint8 op = debugSteps[i].opcode;
            // EXTCODEHASH, EXTCODELENGTH, EXTCODECOPY
            if (op != 0x3B && op != 0x3C && op != 0x3F) {
                continue;
            }

            address addr = address(uint160(debugSteps[i].stack[0]));
            if (isEmptyCodeAddress(addr)) {
                return false;
            }
        }
        return true;
    }

    function validateCreate2(
        Vm.DebugStep[] memory debugSteps,
        UserOperation memory userOp
    ) private pure returns (bool) {
        uint create2Cnt = 0;
        for (uint256 i = 0; i < debugSteps.length; i++) {
            if (debugSteps[i].opcode == 0xF5 /*CREATE2*/) {
                create2Cnt += 1;
            }

            if (create2Cnt == 1 && userOp.initCode.length == 0) {
                return false;
            }

            if (create2Cnt > 1) {
                return false;
            }
        }
        return true;
    }

    function isForbiddenOpcode(uint8 opcode) private pure returns (bool) {
        return opcode == 0x3A // GASPRICE
            || opcode == 0x45 // GASLIMIT
            || opcode == 0x44 // DIFFICULTY
            || opcode == 0x42 // TIMESTAMP
            || opcode == 0x48 // BASEFEE
            || opcode == 0x40 // BLOCKHASH
            || opcode == 0x43 // NUMBER
            || opcode == 0x47 // SELFBALANCE
            || opcode == 0x31 // BALANCE
            || opcode == 0x32 // ORIGIN
            || opcode == 0x5A // GAS
            || opcode == 0xF0 // CREATE
            || opcode == 0x41 // COINBASE
            || opcode == 0xFF; // SELFDESTRUCT
    }

    function isValidNextOpcodeOfGas(uint8 nextOpcode) private pure returns (bool) {
        return nextOpcode == 0xF1 // CALL
            || nextOpcode == 0xF4 // DELEGATECALL
            || nextOpcode == 0xF2 // CALLCODE
            || nextOpcode == 0xFA; // STATICCALL
    }

    function isCallWithValue(
        Vm.DebugStep memory debugStep,
        address entryPoint,
        bool isFromAccount
    ) private pure returns (bool) {
        uint8 op = debugStep.opcode;
        // only the following two has value, delegate call and static call does not have
        if (op == 0xF1 /*CALL*/ || op == 0xF2 /*CALLCODE*/) {
            address dest = address(uint160(debugStep.stack[1]));
            uint256 value = debugStep.stack[2];
            // exception, allow account to call entrypoint with value
            if (value > 0 && (isFromAccount && dest != entryPoint)) {
                return true;
            }
        }
        return false;
    }

    function isCallOutOfGas(Vm.DebugStep memory debugStep) private pure returns (bool) {
        // https://github.com/bluealloy/revm/blob/5a47ae0d2bb0909cc70d1b8ae2b6fc721ab1ca7d/crates/interpreter/src/instruction_result.rs#L23-L27
        return debugStep.instructionResult >= 0x50 && debugStep.instructionResult <= 0x54;
    }

    function isCallWithEmptyCode(Vm.DebugStep memory debugStep) private view returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));

        return isEmptyCodeAddress(dest);
    }

    function isPrecompile(Vm.DebugStep memory debugStep) private pure returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));

        // precompile contracts
        if (dest >= address(0x01) && dest <= address(0x09)) {
            return true;
        }

        // address used for console and console2 for debugging
        if (dest == address(0x000000000000000000636F6e736F6c652e6c6f67)) {
            return true;
        }

        return false;
    }

    function isCallToEntryPoint(Vm.DebugStep memory debugStep, address entryPoint) private pure returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));
        uint8[] memory memoryData = debugStep.memoryData;
        bytes4 selector;

        if (memoryData.length >= 4) {
            selector = bytes4(abi.encodePacked(
                memoryData[0], memoryData[1], memoryData[2], memoryData[3]
            ));
        }

        // note: the check againts selector != bytes4(0) is not really from the spec, but the BaseAccount will return fund
        // not sure if it is an implementation issue but intention wise, it is fine.
        if (dest == entryPoint && selector != bytes4(0) && selector != bytes4(keccak256("depositTo(address)"))) {
            return true;
        }

        return false;
    }

    function isEmptyCodeAddress(address addr) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }

        return size == 0;
    }
}
