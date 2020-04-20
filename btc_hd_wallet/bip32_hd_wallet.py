import re
import hmac
import ecdsa
import random
import hashlib
import unicodedata
from io import BytesIO
from typing import List, Union

from btc_hd_wallet.keys import PrivateKey, PublicKey
from btc_hd_wallet.helper import (
    sha256, encode_base58_checksum, big_endian_to_int, int_to_big_endian,
    decode_base58_checksum, hash160
)
from btc_hd_wallet.bip39_wordlist import word_list


random = random.SystemRandom()

HARDENED = 2 ** 31
PBKDF2_ROUNDS = 2048
CORRECT_ENTROPY_BITS = [128, 160, 192, 224, 256]

Priv_or_PubKeyNode = Union["PrivKeyNode", "PubKeyNode"]

SECP256k1 = ecdsa.curves.SECP256k1
CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER = CURVE_GEN.order()
FIELD_ORDER = SECP256k1.curve.p()
INFINITY = ecdsa.ellipticcurve.INFINITY


def correct_entropy_bits_value(entropy_bits: int) -> None:
    if entropy_bits not in CORRECT_ENTROPY_BITS:
        raise ValueError("incorrect entropy bits")


def checksum_length(entropy_bits: int) -> int:
    return int(entropy_bits / 32)


def mnemonic_sentence_length(entropy_bits: int) -> int:
    return int((entropy_bits + checksum_length(entropy_bits)) / 11)


def mnemonic_from_entropy_bits(entropy_bits: int = 256) -> str:
    correct_entropy_bits_value(entropy_bits=entropy_bits)
    entropy_int = random.getrandbits(entropy_bits)
    entropy_bytes = int_to_big_endian(entropy_int, int(entropy_bits / 8))
    return mnemonic_from_entropy(entropy_bytes.hex())


def mnemonic_from_entropy(entropy: str) -> str:
    entropy_bits = len(entropy) * 4
    entropy_bytes = bytes.fromhex(entropy)
    entropy_int = big_endian_to_int(entropy_bytes)
    sha256_entropy_bytes = sha256(entropy_bytes)
    sha256_entropy_int = big_endian_to_int(sha256_entropy_bytes)
    checksum_bit_length = checksum_length(entropy_bits=entropy_bits)
    checksum = bin(sha256_entropy_int)[2:].zfill(256)[:checksum_bit_length]
    entropy_checksum = bin(entropy_int)[2:] + checksum
    entropy_checksum = entropy_checksum.zfill(
        entropy_bits + checksum_bit_length
    )
    bin_indexes = re.findall("." * 11, entropy_checksum)
    indexes = [int(index, 2) for index in bin_indexes]
    mnemonic_lst = [word_list[index] for index in indexes]
    mnemonic_sentence = " ".join(mnemonic_lst)
    return mnemonic_sentence


def bip32_seed_from_mnemonic(mnemonic: str, password: str = "") -> bytes:
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    password = unicodedata.normalize("NFKD", password)
    passphrase = unicodedata.normalize("NFKD", "mnemonic") + password
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        passphrase.encode("utf-8"),
        PBKDF2_ROUNDS
    )
    return seed


class InvalidKeyError(Exception):
    """Raised when derived key is invalid"""


class PubKeyNode(object):
    mark: str = "M"
    testnet_version: int = 0x043587CF
    mainnet_version: int = 0x0488B21E

    __slots__ = (
        "parent",
        "_key",
        "chain_code",
        "depth",
        "index",
        "_parent_fingerprint",
        "parsed_version",
        "testnet",
        "children"
    )

    def __init__(self, key: bytes, chain_code: bytes, index: int = 0,
                 depth: int = 0, testnet: bool = False,
                 parent: Union["PubKeyNode", "PrivKeyNode"] = None,
                 parent_fingerprint: bytes = None):
        self.parent = parent
        self._key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self._parent_fingerprint = parent_fingerprint
        self.parsed_version = None
        self.testnet = testnet
        self.children = []

    def __eq__(self, other) -> bool:
        if type(self) != type(other):
            return False
        self_key = big_endian_to_int(self._key)
        other_key = big_endian_to_int(other._key)
        return self_key == other_key and \
            self.chain_code == other.chain_code and \
            self.depth == other.depth and \
            self.index == other.index and \
            self.testnet == other.testnet and \
            self.parent_fingerprint == other.parent_fingerprint

    @property
    def public_key(self) -> PublicKey:
        return PublicKey.parse(key_bytes=self._key)

    @property
    def parent_fingerprint(self) -> bytes:
        if self.parent:
            fingerprint = self.parent.fingerprint()
        else:
            fingerprint = self._parent_fingerprint
        # in case there is still None here - it is master
        return fingerprint or b"\x00\x00\x00\x00"

    @property
    def pub_version(self) -> int:
        if self.testnet:
            return PubKeyNode.testnet_version
        return PubKeyNode.mainnet_version

    def check_fingerprint(self) -> Union[None, bool]:
        if self.parent and self._parent_fingerprint:
            return self.parent.fingerprint() == self._parent_fingerprint

    def __repr__(self) -> str:
        if self.is_master() or self.is_root():
            return self.mark
        if self.is_hardened():
            index = str(self.index - 2**31) + "'"
        else:
            index = str(self.index)
        parent = str(self.parent) if self.parent else self.mark
        return parent + "/" + index

    def is_hardened(self) -> bool:
        return self.index >= 2**31

    def is_master(self) -> bool:
        return self.depth == 0 and self.index == 0 and self.parent is None

    def is_root(self) -> bool:
        return self.parent is None

    def fingerprint(self) -> bytes:
        return hash160(self.public_key.sec())[:4]

    @classmethod
    def parse(cls, s: Union[str, bytes, BytesIO], testnet: bool = False):
        if isinstance(s, str):
            s = BytesIO(decode_base58_checksum(s=s))
        elif isinstance(s, bytes):
            s = BytesIO(s)
        elif isinstance(s, BytesIO):
            pass
        else:
            raise ValueError("has to be bytes, str or BytesIO")
        return cls._parse(s, testnet=testnet)

    @classmethod
    def _parse(cls, s: BytesIO, testnet: bool = False):
        version = big_endian_to_int(s.read(4))
        depth = big_endian_to_int(s.read(1))
        parent_fingerprint = s.read(4)
        index = big_endian_to_int(s.read(4))
        chain_code = s.read(32)
        key_bytes = s.read(33)
        key = cls(
            key=key_bytes,
            chain_code=chain_code,
            index=index,
            depth=depth,
            testnet=testnet,
            parent_fingerprint=parent_fingerprint,
        )
        key.parsed_version = version
        return key

    def _serialize(self, key: bytes, version: int = None) -> bytes:
        # 4 byte: version bytes
        result = int_to_big_endian(version, 4)
        # 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys
        result += int_to_big_endian(self.depth, 1)
        # 4 bytes: the fingerprint of the parent key (0x00000000 if master key)
        if self.is_master():
            result += int_to_big_endian(0x00000000, 4)
        else:
            result += self.parent_fingerprint
        # 4 bytes: child number. This is ser32(i) for i in xi = xpar/i,
        # with xi the key being serialized. (0x00000000 if master key)
        result += int_to_big_endian(self.index, 4)
        # 32 bytes: the chain code
        result += self.chain_code
        # 33 bytes: the public key or private key data
        # (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        result += key
        return result

    def serialize_public(self, version: int = None) -> bytes:
        return self._serialize(
            version=self.pub_version if version is None else version,
            key=self.public_key.sec()
        )

    def extended_public_key(self, version: int = None) -> str:
        return encode_base58_checksum(self.serialize_public(version=version))

    def ckd(self, index: int) -> "PubKeyNode":
        """
        The function CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child
        extended public key from the parent extended public key.
        It is only defined for non-hardened child keys.

        * Check whether i ≥ 231 (whether the child is a hardened key).
        * If so (hardened child):
            return failure
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(Kpar) || ser32(i)).
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key Ki is point(parse256(IL)) + Kpar.
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or Ki is the point at infinity,
            the resulting key is invalid, and one should proceed with the next
             value for i.
        """
        if index >= HARDENED:
            # (hardened child): return failure
            raise RuntimeError("failure: hardened child for public ckd")
        I = hmac.new(
            key=self.chain_code,
            msg=self._key + int_to_big_endian(index, 4),
            digestmod=hashlib.sha512
        ).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            InvalidKeyError(
                "public key {} is greater/equal to curve order".format(
                    big_endian_to_int(IL)
                )
            )
        point = PrivateKey.parse(IL).K.point + self.public_key.point
        if point == INFINITY:
            raise InvalidKeyError("public key is a point at infinity")
        Ki = PublicKey.from_point(point=point)
        child = self.__class__(
            key=Ki.sec(),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        self.children.append(child)
        return child

    def generate_children(self, interval: tuple = (0, 20)
                          ) -> List[Priv_or_PubKeyNode]:
        return [self.ckd(index=i) for i in range(*interval)]

    def derive_path(self, index_list: List[int]) -> Priv_or_PubKeyNode:
        node = self
        for i in index_list:
            node = node.ckd(index=i)
        return node


class PrivKeyNode(PubKeyNode):
    mark: str = "m"
    testnet_version: int = 0x04358394
    mainnet_version: int = 0x0488ADE4

    @property
    def private_key(self) -> PrivateKey:
        return PrivateKey(sec_exp=big_endian_to_int(self._key))

    @property
    def public_key(self) -> PublicKey:
        return self.private_key.K

    @property
    def priv_version(self) -> int:
        if self.testnet:
            return PrivKeyNode.testnet_version
        return PrivKeyNode.mainnet_version

    @classmethod
    def master_key(cls, bip32_seed: bytes, testnet=False) -> "PrivKeyNode":
        """
        * Generate a seed byte sequence S of a chosen length
          (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
        * Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
        * Split I into two 32-byte sequences, IL and IR.
        * Use parse256(IL) as master secret key, and IR as master chain code.
        """
        I = hmac.new(
            key=b"Bitcoin seed",
            msg=bip32_seed,
            digestmod=hashlib.sha512
        ).digest()
        # private key
        IL = I[:32]
        # In case IL is 0 or ≥ n, the master key is invalid
        int_left_key = big_endian_to_int(IL)
        if int_left_key == 0:
            raise InvalidKeyError("master key is zero")
        if int_left_key >= CURVE_ORDER:
            raise InvalidKeyError(
                "master key {} is greater/equal to curve order".format(
                    int_left_key
                )
            )
        # chain code
        IR = I[32:]
        return cls(
            key=IL,
            chain_code=IR,
            testnet=testnet
        )

    def serialize_private(self, version: int = None) -> bytes:
        return self._serialize(
            version=self.priv_version if version is None else version,
            key=b"\x00" + bytes(self.private_key)
        )

    def extended_private_key(self, version: int = None) -> str:
        return encode_base58_checksum(self.serialize_private(version=version))

    def ckd(self, index: int) -> "PrivKeyNode":
        """
        The function CKDpriv((kpar, cpar), i) → (ki, ci) computes
        a child extended private key from the parent extended private key:

        * Check whether i ≥ 231 (whether the child is a hardened key).
        * If so (hardened child):
            let I = HMAC-SHA512(Key=cpar, Data=0x00 || ser256(kpar) || ser32(i))
            (Note: The 0x00 pads the private key to make it 33 bytes long.)
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(point(kpar)) || ser32(i))
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key ki is parse256(IL) + kpar (mod n).
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
            and one should proceed with the next value for i.
            (Note: this has probability lower than 1 in 2127.)
        """
        if index >= HARDENED:
            # hardened
            data = b"\x00"+bytes(self.private_key) + int_to_big_endian(index, 4)
        else:
            data = self.public_key.sec() + int_to_big_endian(index, 4)
        I = hmac.new(
            key=self.chain_code,
            msg=data,
            digestmod=hashlib.sha512
        ).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            InvalidKeyError(
                "private key {} is greater/equal to curve order".format(
                    big_endian_to_int(IL)
                )
            )
        ki = (int.from_bytes(IL, "big") +
              big_endian_to_int(bytes(self.private_key))) % CURVE_ORDER
        if ki == 0:
            InvalidKeyError("private key is zero")
        child = self.__class__(
            key=int_to_big_endian(ki, 32),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        self.children.append(child)
        return child
