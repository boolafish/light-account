pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import "forge-std/console2.sol";

library EIP4337Check {

    function checkForbiddenOpcodes(
        Vm.OpcodeAccess[] memory opcodes,
        UserOperation memory userOp,
        address entryPoint
    ) internal pure returns (bool) {
        Vm.OpcodeAccess[] memory senderOpcodes = new Vm.OpcodeAccess[](opcodes.length);
        uint senderOpcodesLen = 0;

        address currentAddr;
        for (uint256 i = 0; i < opcodes.length; i++) {
            // We start analyze the forbidden opcodes from depth > 2
            // Note that in forge test, the "test" itself wiill be depth 1. So the EntryPoint will be depth 2.
            //
            // Also, the `EntryPoint.simulateValidation()` function do have call back to
            // the EntryPoint contract with `this.xxx()` so we will need to filter those as well.
            // The code here group the opcodes by addresses, and then we only check the
            // forbidden opcodes on those addresses we are interested.
            if (opcodes[i].depth == 2) {
                uint8 opcode = opcodes[i].opcode;
                if (opcode == 0xF1 || opcode == 0xFA) { // CALL and STATICCALL
                    currentAddr = address(uint160(opcodes[i].stackInputs[1]));
                }

                // ignore all opcodes on depth 1 and do not add to the `addrToOpcodes` mapping
                continue;
            }

            if (currentAddr == userOp.sender) {
                senderOpcodes[senderOpcodesLen++] = opcodes[i];
            }
        }

        // Reset the senderOpcodes to correct length
        assembly {
            mstore(senderOpcodes, senderOpcodesLen)
        }

        if (!validateForbiddenOpcodes(senderOpcodes)) {
            console2.log("Invalid Sender Opcodes (validateUserOp)");
            return false;
        }
        if (!validateCall(senderOpcodes, entryPoint, true)) {
            console2.log("Call with non zero value (validateUserOp)");
            return false;
        }

        return true;
    }

    /**
     * Limitation on “CALL” opcodes (CALL, DELEGATECALL, CALLCODE, STATICCALL):
     * ✅ 1. must not use value (except from account to the entrypoint)
     * ❌ 2. must not revert with out-of-gas  (🙅‍♂️ technical issue, not supporting now)
     * 🚧 3. destination address must have code (EXTCODESIZE>0) or be a standard Ethereum precompile defined at addresses from 0x01 to 0x09
     * 🚧 4. cannot call EntryPoint’s methods, except depositFor (to avoid recursion)
     */
    function validateCall(
        Vm.OpcodeAccess[] memory opcodes,
        address entryPoint,
        bool isFromAccount
    ) private pure returns (bool) {
        for (uint256 i = 0; i < opcodes.length; i++) {
            if (!isCallWithoutZeroValue(opcodes[i], entryPoint, isFromAccount)) {
                return false;
            }
        }
        return true;
    }

    /**
     * May not invokes any forbidden opcodes
     * Must not use GAS opcode (unless followed immediately by one of { CALL, DELEGATECALL, CALLCODE, STATICCALL }.)
     */
    function validateForbiddenOpcodes(Vm.OpcodeAccess[] memory opcodes) private pure returns (bool) {
        for (uint256 i = 0; i < opcodes.length; i++) {
            uint8 opcode = opcodes[i].opcode;
            if (isForbiddenOpcode(opcode)) {
                // exception case for GAS opcode
                if (opcode == 0x5A && i < opcodes.length -1) {
                    if (!isValidNextOpcodeOfGas(opcodes[i+1].opcode)) {
                        console2.log("fobidden GAS op-code, next opcode: ", opcodes[i+1].opcode, "depth: ", opcodes[i].depth);
                        return false;
                    }
                } else {
                    console2.log("fobidden op-code: ", opcode, "depth: ", opcodes[i].depth);
                    return false;
                }
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

    function isCallWithoutZeroValue(
        Vm.OpcodeAccess memory opcode,
        address entryPoint,
        bool isFromAccount
    ) private pure returns (bool) {
        uint8 op = opcode.opcode;
        if (op == 0xF1 /*CALL*/ || op == 0xF2 /*CALLCODE*/) {
            address dest = address(uint160(opcode.stackInputs[1]));
            uint256 value = opcode.stackInputs[2];
            // exception, allow account to call entrypoint with value
            if (value > 0 && (isFromAccount && dest != entryPoint)) {
                return false;
            }
        }
        return true;
    }
}
