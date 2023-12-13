pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import "forge-std/console2.sol";

library EIP4337Check {

    function checkForbiddenOpcodes(
        Vm.OpcodeAccess[] memory opcodes,
        UserOperation memory userOp
    ) internal pure returns (bool) {
        Vm.OpcodeAccess[] memory senderOpcodes = new Vm.OpcodeAccess[](opcodes.length);
        uint senderOpcodesLen = 0;

        address currentAddr;
        for (uint256 i = 0; i < opcodes.length; i++) {
            // We start analyze the forbidden opcodes from depth > 1
            // Also, the `EntryPoint.simulateValidation()` function do have call back to
            // the EntryPoint contract with `this.xxx()` so we will need to filter those as well.
            // The code here group the opcodes by addresses, and then we only check the
            // forbidden opcodes on those addresses we are interested.
            if (opcodes[i].depth == 1) {
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

        for (uint256 i = 0; i < senderOpcodesLen; i++) {
            uint8 opcode = senderOpcodes[i].opcode;
            if (isForbiddenOpcode(opcode)) {
                // exception case for GAS opcode
                if (opcode == 0x5A && i < opcodes.length -1) {
                    if (!validNextOpcodeOfGas(senderOpcodes[i+1].opcode)) {
                        console2.log("fobidden GAS op-code, next opcode: %d, depth: %d", senderOpcodes[i+1].opcode, senderOpcodes[i].depth);
                        return false;
                    }
                } else {
                    console2.log("fobidden op-code: %d, depth: %d", opcode, senderOpcodes[i].depth);
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

    function validNextOpcodeOfGas(uint8 nextOpcode) private pure returns (bool) {
        return nextOpcode == 0xF1 // CALL
            || nextOpcode == 0xF4 // DELEGATECALL
            || nextOpcode == 0xF2 // CALLCODE
            || nextOpcode == 0xFA; // STATICCALL
    }
}
