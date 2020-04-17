import ecdsa
from typing import Union

from helper import (
    encode_base58_checksum, decode_base58_checksum, big_endian_to_int,
    hash160, h160_to_p2wpkh_address, h160_to_p2pkh_address
)


SECP256k1 = ecdsa.curves.SECP256k1
Point_or_PointJacobi = Union[
    ecdsa.ellipticcurve.Point,
    ecdsa.ellipticcurve.PointJacobi
]


class PrivateKey(object):

    __slots__ = (
        "sec_exp",
        "k",
        "K"
    )

    def __init__(self, sec_exp: int):
        self.sec_exp = sec_exp
        self.k = ecdsa.SigningKey.from_secret_exponent(
            secexp=sec_exp,
            curve=SECP256k1
        )
        self.K = PublicKey(key=self.k.get_verifying_key())

    def __bytes__(self) -> bytes:
        return self.k.to_string()

    def __eq__(self, other: "PrivateKey") -> bool:
        return self.sec_exp == other.sec_exp

    def wif(self, compressed: bool = True, testnet: bool = False) -> str:
        prefix = b"\xef" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        return encode_base58_checksum(prefix + bytes(self) + suffix)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        decoded = decode_base58_checksum(s=wif_str)
        if wif_str[0] in ("K", "L", "c"):
            # compressed key --> so remove last byte that has to be 01
            assert decoded[-1] == 1
            decoded = decoded[:-1]
        return cls(sec_exp=big_endian_to_int(decoded[1:]))

    @classmethod
    def parse(cls, byte_str: bytes) -> "PrivateKey":
        return cls(sec_exp=big_endian_to_int(byte_str))


class PublicKey(object):

    __slots__ = (
        "K"
    )

    def __init__(self, key: ecdsa.VerifyingKey):
        self.K = key

    @property
    def point(self) -> ecdsa.ellipticcurve.Point:
        return self.K.pubkey.point

    def sec(self, compressed: bool = True) -> bytes:
        if compressed:
            return self.K.to_string(encoding="compressed")
        return self.K.to_string(encoding="uncompressed")

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PublicKey":
        return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point: Point_or_PointJacobi) -> "PublicKey":
        return cls(ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1))

    def h160(self, compressed: bool = True) -> bytes:
        return hash160(self.sec(compressed=compressed))

    def address(self, compressed: bool = True, testnet: bool = False,
                addr_type: str = "p2pkh") -> str:
        h160 = self.h160(compressed=compressed)
        if addr_type == "p2pkh":
            return h160_to_p2pkh_address(h160=h160, testnet=testnet)
        elif addr_type == "p2wpkh":
            return h160_to_p2wpkh_address(h160=h160, testnet=testnet)
        raise ValueError("Unsupported address type.")
