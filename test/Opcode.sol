pragma solidity ^0.8.0;

library Opcode {
    function getOpcode(uint8 code) internal pure returns (string memory) {
        if (code == 0x00) return "STOP";
        if (code == 0x01) return "ADD";
        if (code == 0x02) return "MUL";
        if (code == 0x03) return "SUB";
        if (code == 0x04) return "DIV";
        if (code == 0x05) return "SDIV";
        if (code == 0x06) return "MOD";
        if (code == 0x07) return "SMOD";
        if (code == 0x08) return "ADDMOD";
        if (code == 0x09) return "MULMOD";
        if (code == 0x0A) return "EXP";
        if (code == 0x0B) return "SIGNEXTEND";
        // Skipping 0x0C - 0x0F (undefined)
        if (code == 0x10) return "LT";
        if (code == 0x11) return "GT";
        if (code == 0x12) return "SLT";
        if (code == 0x13) return "SGT";
        if (code == 0x14) return "EQ";
        if (code == 0x15) return "ISZERO";
        if (code == 0x16) return "AND";
        if (code == 0x17) return "OR";
        if (code == 0x18) return "XOR";
        if (code == 0x19) return "NOT";
        if (code == 0x1A) return "BYTE";
        if (code == 0x1B) return "SHL";
        if (code == 0x1C) return "SHR";
        if (code == 0x1D) return "SAR";
        // Skipping 0x1E - 0x1F (undefined)
        if (code == 0x20) return "KECCAK256";
        // Skipping 0x21 - 0x2F (undefined)
        if (code == 0x30) return "ADDRESS";
        if (code == 0x31) return "BALANCE";
        if (code == 0x32) return "ORIGIN";
        if (code == 0x33) return "CALLER";
        if (code == 0x34) return "CALLVALUE";
        if (code == 0x35) return "CALLDATALOAD";
        if (code == 0x36) return "CALLDATASIZE";
        if (code == 0x37) return "CALLDATACOPY";
        if (code == 0x38) return "CODESIZE";
        if (code == 0x39) return "CODECOPY";
        if (code == 0x3A) return "GASPRICE";
        if (code == 0x3B) return "EXTCODESIZE";
        if (code == 0x3C) return "EXTCODECOPY";
        if (code == 0x3D) return "RETURNDATASIZE";
        if (code == 0x3E) return "RETURNDATACOPY";
        if (code == 0x3F) return "EXTCODEHASH";
        if (code == 0x40) return "BLOCKHASH";
        if (code == 0x41) return "COINBASE";
        if (code == 0x42) return "TIMESTAMP";
        if (code == 0x43) return "NUMBER";
        if (code == 0x44) return "DIFFICULTY";
        if (code == 0x45) return "GASLIMIT";
        if (code == 0x46) return "CHAINID";
        if (code == 0x47) return "SELFBALANCE";
        if (code == 0x48) return "BASEFEE";
        if (code == 0x49) return "BLOBHASH";
        if (code == 0x4A) return "BLOBBASEFEE";
        // Skipping 0x4B - 0x4F (undefined)
        if (code == 0x50) return "POP";
        if (code == 0x51) return "MLOAD";
        if (code == 0x52) return "MSTORE";
        if (code == 0x53) return "MSTORE8";
        if (code == 0x54) return "SLOAD";
        if (code == 0x55) return "SSTORE";
        if (code == 0x56) return "JUMP";
        if (code == 0x57) return "JUMPI";
        if (code == 0x58) return "PC";
        if (code == 0x59) return "MSIZE";
        if (code == 0x5A) return "GAS";
        if (code == 0x5B) return "JUMPDEST";
        if (code == 0x5C) return "TLOAD";
        if (code == 0x5D) return "TSTORE";
        if (code == 0x5E) return "MCOPY";
        // PUSH1 to PUSH32
        for (uint8 i = 0x60; i <= 0x7F; i++) {
            if (code == i) return string(abi.encodePacked("PUSH", uint2str(i - 0x60 + 1)));
        }
        // DUP1 to DUP16
        for (uint8 i = 0x80; i <= 0x8F; i++) {
            if (code == i) return string(abi.encodePacked("DUP", uint2str(i - 0x80 + 1)));
        }
        // SWAP1 to SWAP16
        for (uint8 i = 0x90; i <= 0x9F; i++) {
            if (code == i) return string(abi.encodePacked("SWAP", uint2str(i - 0x90 + 1)));
        }
        if (code == 0xA0) return "LOG0";
        if (code == 0xA1) return "LOG1";
        if (code == 0xA2) return "LOG2";
        if (code == 0xA3) return "LOG3";
        if (code == 0xA4) return "LOG4";
        // Undefined opcodes 0xA5 to 0xEF
        if (code == 0xF0) return "CREATE";
        if (code == 0xF1) return "CALL";
        if (code == 0xF2) return "CALLCODE";
        if (code == 0xF3) return "RETURN";
        if (code == 0xF4) return "DELEGATECALL";
        if (code == 0xF5) return "CREATE2";
        // Undefined opcodes 0xF6 to 0xF9, 0xFB to 0xFC
        if (code == 0xFA) return "STATICCALL";
        if (code == 0xFD) return "REVERT";
        if (code == 0xFE) return "INVALID";
        if (code == 0xFF) return "SELFDESTRUCT";

        revert("undefined opcode");
    }

    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}
