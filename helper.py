import hashlib
from io import BytesIO
from typing import List

import bech32


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14


def encode_base58(s: bytes) -> str:
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(b: bytes) -> str:
    return encode_base58(b + hash256(b)[:4])


def decode_base58(s: str) -> bytes:
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)

    h = hex(num)[2:]
    h = '0' + h if len(h) % 2 else h
    return bytes.fromhex(h)


def decode_base58_checksum(s: str) -> bytes:
    """removes ONLY checksum"""
    num_bytes = decode_base58(s=s)
    checksum = num_bytes[-4:]
    if hash256(num_bytes[:-4])[:4] != checksum:
        raise ValueError(
            'bad address: {} {}'.format(
                checksum,
                hash256(num_bytes[:-4])[:4]
            )
        )
    return num_bytes[:-4]


def b58decode_addr(s: str) -> bytes:
    """removes first byte --> mostly testnet/mainnet marker"""
    return decode_base58_checksum(s=s)[1:]


def hash160(s: bytes) -> bytes:
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def sha256(s: bytes) -> bytes:
    return hashlib.sha256(s).digest()


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


def big_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def read_varint(s: BytesIO) -> int:
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xfd:
        # number is between 253 and 2^16 -1
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # number is between 2^16 and 2^32 – 1
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # number is between 2^32 and 2^64 – 1
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i: int) -> bytes:
    """Encode integer as varint"""
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))


def h160_to_p2pkh_address(h160: bytes, testnet: bool = False) -> str:
    """Takes a byte sequence hash160 and returns a p2pkh address string"""
    # p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    # use encode_base58_checksum to get the address
    prefix = b"\x6f" if testnet else b"\x00"
    return encode_base58_checksum(prefix + h160)


def wif(key_bytes, compressed=True, testnet=False):
    prefix = b"\xef" if testnet else b"\x80"
    suffix = b"\x01" if compressed else b""
    return encode_base58_checksum(prefix + key_bytes + suffix)


def h160_to_p2sh_address(h160: bytes, testnet: bool = False) -> str:
    """Takes a byte sequence hash160 and returns a p2sh address string"""
    # p2sh has a prefix of b'\x05' for mainnet, b'\xc4' for testnet
    # use encode_base58_checksum to get the address
    prefix = b"\xc4" if testnet else b"\x05"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2wpkh_address(h160: bytes, testnet: bool = False, witver: int = 0) -> str:
    """Takes a byte sequence hash160 and returns a p2wpkh address string"""
    hrp = "tb" if testnet else "bc"
    return bech32.encode(hrp=hrp, witver=witver, witprog=h160)


def h256_to_p2wsh_address(h256: bytes, testnet: bool = False, witver: int = 0) -> str:
    """Takes a byte sequence sha256 and returns a p2wsh address string"""
    hrp = "tb" if testnet else "bc"
    return bech32.encode(hrp=hrp, witver=witver, witprog=h256)


def bech32_decode_address(addr: str, testnet: bool = False) -> bytes:
    hrp = "tb" if testnet else "bc"
    return bytes(bech32.decode(hrp=hrp, addr=addr)[1])


def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 ** (exponent - 3)


def target_to_bits(target):
    raw_bytes = int_to_big_endian(target, 32)
    raw_bytes = raw_bytes.lstrip(b"\x00")
    if raw_bytes[0] > 0xf7:
        exponent = len(raw_bytes + 1)
        coefficient = b"\x00" + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


def calculate_new_bits(previous_bits, time_differential):
    """
    Calculates the new bits given
    a 2016-block time differential and the previous bits
    """
    # if the time differential is greater than 8 weeks, set to 8 weeks
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    # if the time differential is less than half a week, set to half a week
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    # the new target is the previous target * time differential / two weeks
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
    # TODO ^^^
    # convert the new target to bits
    return target_to_bits(new_target)


def merkle_parent(hash1: bytes, hash2: bytes) -> bytes:
    """Takes the binary hashes and calculates the hash256"""
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes: List[bytes]) -> List[bytes]:
    """
    Takes a list of binary hashes and returns a list that's half the length
    """
    # if the list has exactly 1 element raise an error
    if len(hashes) == 1:
        raise ValueError("Cannot take a parent level with only 1 item")
    # if the list has an odd number of elements, duplicate the last one
    # and put it at the end so it has an even number of elements
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # initialize next level
    parent_level = []
    # loop over every pair
    for i in range(0, len(hashes), 2):
        # get the merkle parent of the hashes at index i and i+1
        # append parent to parent level
        parent_level.append(merkle_parent(hashes[i], hashes[i + 1]))
    # return parent level
    return parent_level


def merkle_root(hashes: List[bytes]) -> bytes:
    """Takes a list of binary hashes and returns the merkle root"""
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of the current level
    return current_level[0]


def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError(
            'bit_field does not have a length that is divisible by 8'
        )
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def bytes_to_bit_field(some_bytes):
    flag_bits = []
    for byte in some_bytes:
        for _ in range(8):
            flag_bits.append(byte & 1)
            byte >>= 1
    return flag_bits


def murmur3(data: bytes, seed: int = 0) -> int:
    '''from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash'''
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, rounded_end, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
            ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64
    # tail
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[rounded_end] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
    # finalization
    h1 ^= length
    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)
    return h1 & 0xffffffff


def count_bytes(lst):
    witness_bytes_len = 0
    for item in lst:
        witness_bytes_len += len(item)
    return witness_bytes_len


def p2wpkh_script_serialized(h160):
    result = int_to_little_endian(0x00, 1)
    result += int_to_little_endian(len(h160), 1)
    result += h160
    return result
