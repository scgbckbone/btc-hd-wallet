import hmac
import hashlib
from io import BytesIO
from typing import List, Any, Generator

import btc_hd_wallet.bech32 as bech32


BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14


def chunks(lst: List[Any], n: int) -> Generator[List[Any], None, None]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def encode_base58(data: bytes) -> str:
    """
    Encode base58.

    :param data: data to encode
    :return: base58 encoded string
    """
    count = 0
    for c in data:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(data: bytes) -> str:
    """
    Encode base58 checksum.

    :param data: data to encode
    :return: base58 encoded string with checksum
    """
    return encode_base58(data + hash256(data)[:4])


def decode_base58(s: str) -> bytes:
    """
    Decode base58.

    :param s: base58 encoded string
    :return: decoded data
    """
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
    """
    Decode base58 checksum.

    :param s: base58 encoded string with checksum
    :return: decoded data (without checksum)
    """
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
    """
    Reads variable integer from buffer.

    :param s: encoded varint
    :return: integer
    """
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
    """
    Encode variable integer.

    :param i: integer
    :return: encoded varint
    """
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
    """
    Base58 decode + remove first byte (mostly testnet/mainnet marker)

    :param s: base58 encoded
    :return: decoded with first byte removed
    """
    return decode_base58_checksum(s=s)[1:]


def hash160(s: bytes) -> bytes:
    """
    sha256 followed by ripemd160

    :param s: data
    :return: hashed data
    """
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    """
    two rounds of sha256

    :param s: data
    :return: hashed data
    """
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def sha256(s: bytes) -> bytes:
    """
    one round of sha256

    :param s: data
    :return: hashed data
    """
    return hashlib.sha256(s).digest()


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """
    Hash-based message authentication code with sha512

    :param key: secret key
    :param msg: message
    :return: digest bytes
    """
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha512).digest()


def little_endian_to_int(b: bytes) -> int:
    """
    Little endian representation to integer.

    :param b: little endian representation
    :return: integer
    """
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    """
    Represents integer in little endian byteorder.

    :param n: integer
    :param length: byte length
    :return: little endian
    """
    return n.to_bytes(length, 'little')


def big_endian_to_int(b: bytes) -> int:
    """
    Big endian representation to integer.

    :param b: big endian representation
    :return: integer
    """
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    """
    Represents integer in big endian byteorder.

    :param n: integer
    :param length: byte length
    :return: big endian
    """
    return n.to_bytes(length, "big")


def h160_to_p2pkh_address(h160: bytes, testnet: bool = False) -> str:
    """
    p2pkh address from hash160.

    :param h160: hash160 hashed data
    :param testnet: whether to encode as a testnet address (default=False)
    :return: p2pkh bitcoin address
    """
    prefix = b"\x6f" if testnet else b"\x00"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160: bytes, testnet: bool = False) -> str:
    """
    p2sh address from hash160.

    :param h160: hash160 hashed data
    :param testnet: whether to encode as a testnet address (default=False)
    :return: p2sh bitcoin address
    """
    prefix = b"\xc4" if testnet else b"\x05"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2wpkh_address(h160: bytes, testnet: bool = False,
                           witver: int = 0) -> str:
    """
    p2wpkh address from hash160.

    :param h160: hash160 hashed data
    :param testnet: whether to encode as a testnet address (default=False)
    :param witver: witness version (default=0)
    :return: p2wpkh bitcoin address
    """
    hrp = "tb" if testnet else "bc"
    return bech32.encode(hrp=hrp, witver=witver, witprog=h160)


def h256_to_p2wsh_address(h256: bytes, testnet: bool = False,
                          witver: int = 0) -> str:
    """
    p2wpkh address from hash160.

    :param h256: sha256 hashed data
    :param testnet: whether to encode as a testnet address (default=False)
    :param witver: witness version (default=0)
    :return: p2wsh bitcoin address
    """
    hrp = "tb" if testnet else "bc"
    return bech32.encode(hrp=hrp, witver=witver, witprog=h256)


def bech32_decode_address(addr: str, testnet: bool = False) -> bytes:
    """
    Decodes bech32 address.

    :param addr: bech32 address
    :param testnet: whether to encode as a testnet address (default=False)
    :return: decoded address
    """
    hrp = "tb" if testnet else "bc"
    return bytes(bech32.decode(hrp=hrp, addr=addr)[1])


def merkle_parent(hash1: bytes, hash2: bytes) -> bytes:
    """
    Calculates merkle parent of two children.

    :param hash1: hash 1
    :param hash2: hash 2
    :return: parent
    """
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes: List[bytes]) -> List[bytes]:
    """
    Calculates merkle parent level from child level (one below parent).

    :param hashes: child level
    :return: parent level
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
    """
    Calculates merkle root.

    :param hashes: child level
    :return: merkle root
    """
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of the current level
    return current_level[0]
