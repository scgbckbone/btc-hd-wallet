from io import BytesIO

from btc_hd_wallet.helper import (
    encode_varint, read_varint, little_endian_to_int, int_to_little_endian
)
from btc_hd_wallet.op import OP_CODE_NAMES


def p2wsh_script(h256: bytes) -> "Script":
    """Takes sha256 and returns p2wsh script"""
    # [OP_0, 32-byte element]
    return Script([0x00, h256])


def p2wpkh_script(h160: bytes) -> "Script":
    """Takes hash160 and returns p2wpkh script"""
    # [OP_0, 20-byte element]
    return Script([0x00, h160])


def p2sh_script(h160: bytes) -> "Script":
    """Takes a hash160 and returns the p2sh ScriptPubKey"""
    # [OP_HASH160, 20-byte element, OP_EQUAL]
    return Script([0xa9, h160, 0x87])


def p2pkh_script(h160: bytes) -> "Script":
    """Takes a hash160and returns the p2pkh ScriptPubKey"""
    # [OP_DUP, OP_HASH160, 20-byte element, OP_EQUALVERIFY, OP_CHECKSIG]
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


class Script:
    def __init__(self, cmds: list = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __eq__(self, other) -> bool:
        return self.cmds == other.cmds

    def __repr__(self) -> str:
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other) -> "Script":
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s: BytesIO) -> "Script":
        # Script serialization starts with the length of the entire script.
        length = read_varint(s)
        cmds = []
        count = 0
        # we parse until the right of bytes is consumed
        while count < length:
            current = s.read(1)
            count += 1
            # This converts the byte into an integer in Python.
            current_byte = current[0]
            if 1 <= current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            # 76 OP_PUSHDATA1,  next byte tells us how many bytes to read.
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            # 77 OP_PUSHDATA2, next two bytes tell us how many bytes to read.
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # opcode
                op_code = current_byte
                cmds.append(op_code)

        if count != length:
            raise SyntaxError("parsing script failed")
        return cls(cmds)

    def raw_serialize(self) -> bytes:
        result = b""
        for cmd in self.cmds:
            # If the command is an integer, we know that’s an opcode.
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    # length between 1 - 75 inclusive,
                    # we encode the length as a single byte.
                    result += int_to_little_endian(length, 1)
                elif 75 < length < 256:
                    # For any element with length from 76 to 255,
                    # we put OP_PUSHDATA1 first, then encode the length
                    # as a single byte, followed by the element.
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif 256 <= length <= 520:
                    # For an element with a length from 256 to 520,
                    # we put OP_PUSHDATA2 first, then encode the length
                    # as two bytes in little endian, followed by the element.
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    # Any element longer than 520 bytes cannot be serialized.
                    raise ValueError("too long an cmd")
                # actual element appending
                result += cmd
        return result

    def serialize(self) -> bytes:
        result = self.raw_serialize()
        # Script serialization starts with the length of the entire script.
        return encode_varint(len(result)) + result
