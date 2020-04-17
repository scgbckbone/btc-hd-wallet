import hashlib
from io import BytesIO
from typing import List

import btc_hd_wallet.bech32 as bech32


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
        if c not in BASE58_ALPHABET:
            raise ValueError(
                "character {} is not valid base58 character".format(c)
            )
        num *= 58
        num += BASE58_ALPHABET.index(c)

    h = hex(num)[2:]
    h = '0' + h if len(h) % 2 else h
    res = bytes.fromhex(h)

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


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
        return int_to_little_endian(i, 1)
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))


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
    """one round of sha256"""
    return hashlib.sha256(s).digest()


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


def big_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def h160_to_p2pkh_address(h160: bytes, testnet: bool = False) -> str:
    """Takes a byte sequence hash160 and returns a p2pkh address string"""
    prefix = b"\x6f" if testnet else b"\x00"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160: bytes, testnet: bool = False) -> str:
    """Takes a byte sequence hash160 and returns a p2sh address string"""
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
