import ecdsa
from typing import Union

from btc_hd_wallet.helper import (
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
        """
        Initializes private key from secret exponent.

        :param sec_exp: secret
        """
        self.sec_exp = sec_exp
        self.k = ecdsa.SigningKey.from_secret_exponent(
            secexp=sec_exp,
            curve=SECP256k1
        )
        self.K = PublicKey(key=self.k.get_verifying_key())

    def __bytes__(self) -> bytes:
        """
        Encodes private key into corresponding byte sequence.

        :return: byte representation of PrivateKey object
        """
        return self.k.to_string()

    def __eq__(self, other: "PrivateKey") -> bool:
        """
        Checks whether two private keys are equal.

        :param other: other private key
        """
        return self.sec_exp == other.sec_exp

    def wif(self, compressed: bool = True, testnet: bool = False) -> str:
        """
        Encodes private key into wallet import/export format.

        :param compressed: whether public key is compressed (default=True)
        :param testnet: whether to encode as a testnet key (default=False)
        :return: WIF encoded private key
        """
        prefix = b"\xef" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        return encode_base58_checksum(prefix + bytes(self) + suffix)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        """
        Initializes private key from wallet import format encoding.

        :param wif_str: wallet import format private key
        :return: private key
        """
        decoded = decode_base58_checksum(s=wif_str)
        if wif_str[0] in ("K", "L", "c"):
            # compressed key --> so remove last byte that has to be 01
            assert decoded[-1] == 1
            decoded = decoded[:-1]
        return cls(sec_exp=big_endian_to_int(decoded[1:]))

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PrivateKey":
        """
        Initializes private key from byte sequence.

        :param key_bytes: byte representation of private key
        :return: private key
        """
        return cls(sec_exp=big_endian_to_int(key_bytes))


class PublicKey(object):

    __slots__ = (
        "K"
    )

    def __init__(self, key: ecdsa.VerifyingKey):
        """
        Initializes PublicKey object from ecdsa verifying key

        :param key: ecdsa verifying key
        """
        self.K = key

    def __eq__(self, other: "PublicKey") -> bool:
        """
        Checks whether two public keys are equal.

        :param other: other public key
        """
        return self.sec() == other.sec()

    @property
    def point(self) -> ecdsa.ellipticcurve.Point:
        """
        Point on curve (x and y coordinates).

        :return: point on curve
        """
        return self.K.pubkey.point

    def sec(self, compressed: bool = True) -> bytes:
        """
        Encodes public key to SEC format.

        :param compressed: whether to use compressed format (default=True)
        :return: SEC encoded public key
        """
        if compressed:
            return self.K.to_string(encoding="compressed")
        return self.K.to_string(encoding="uncompressed")

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PublicKey":
        """
        Initializes public key from byte sequence.

        :param key_bytes: byte representation of public key
        :return: public key
        """
        return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point: Point_or_PointJacobi) -> "PublicKey":
        """
        Initializes public key from point on elliptic curve.

        :param point: point on elliptic curve
        :return: public key
        """
        return cls(ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1))

    def h160(self, compressed: bool = True) -> bytes:
        """
        SHA256 followed by RIPEMD160 of public key.

        :param compressed: whether to use compressed format (default=True)
        :return: SHA256(RIPEMD160(public key))
        """
        return hash160(self.sec(compressed=compressed))

    def address(self, compressed: bool = True, testnet: bool = False,
                addr_type: str = "p2wpkh") -> str:
        """
        Generates bitcoin address from public key.

        :param compressed: whether to use compressed format (default=True)
        :param testnet: whether to encode as a testnet address (default=False)
        :param addr_type: which address type to generate:
                            1. p2pkh
                            2. p2wpkh (default)
        :return: bitcoin address
        """
        h160 = self.h160(compressed=compressed)
        if addr_type == "p2pkh":
            return h160_to_p2pkh_address(h160=h160, testnet=testnet)
        elif addr_type == "p2wpkh":
            return h160_to_p2wpkh_address(h160=h160, testnet=testnet)
        raise ValueError("Unsupported address type.")
