from typing import Union

try:
    from pysecp256k1 import (
        ec_seckey_verify, ec_pubkey_create, ec_pubkey_serialize, ec_pubkey_parse,
        ec_seckey_tweak_add, ec_pubkey_tweak_add,
    )
except ImportError:
    import ecdsa
    SECP256k1 = ecdsa.curves.SECP256k1
    CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
    CURVE_ORDER = CURVE_GEN.order()
    FIELD_ORDER = SECP256k1.curve.p()
    INFINITY = ecdsa.ellipticcurve.INFINITY


from btc_hd_wallet.helper import (
    encode_base58_checksum, decode_base58_checksum,
    hash160, h160_to_p2wpkh_address, h160_to_p2pkh_address, int_to_big_endian,
)


class PrivateKey(object):

    __slots__ = (
        "k",
        "K"
    )

    def __init__(self, sec_exp: Union[bytes, int]):
        """
        Initializes private key.

        :param sec_exp: secret
        """
        if isinstance(sec_exp, int):
            sec_exp = int_to_big_endian(sec_exp, 32)
        try:
            ec_seckey_verify(sec_exp)
            self.k = sec_exp
            self.K = PublicKey(ec_pubkey_create(self.k))
        except NameError:
            k = ecdsa.SigningKey.from_string(sec_exp, curve=SECP256k1)
            self.K = PublicKey(pub_key=k.get_verifying_key())
            self.k = k.to_string()
        else:
            ec_seckey_verify(self.k)
            self.K = PublicKey(ec_pubkey_create(self.k))

    def __bytes__(self) -> bytes:
        """
        Encodes private key into corresponding byte sequence.

        :return: byte representation of PrivateKey object
        """
        return self.k

    def __eq__(self, other: "PrivateKey") -> bool:
        """
        Checks whether two private keys are equal.

        :param other: other private key
        """
        return self.k == other.k

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

    def tweak_add(self, tweak32: bytes) -> "PrivateKey":
        tweaked = ec_seckey_tweak_add(self.k, tweak32)
        return PrivateKey(sec_exp=tweaked)

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
        return cls(sec_exp=decoded[1:])

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PrivateKey":
        """
        Initializes private key from byte sequence.

        :param key_bytes: byte representation of private key
        :return: private key
        """
        return cls(sec_exp=key_bytes)

    @classmethod
    def from_int(cls, sec_exp: int) -> "Privatekey":
        return cls(sec_exp=int_to_big_endian(sec_exp, 32))


class PublicKey(object):

    __slots__ = (
        "K"
    )

    def __init__(self, pub_key):
        """
        Initializes PublicKey object. 

        :param key: secp256k1 pubkey or ecdsa.VerifyingKey
        """
        self.K = pub_key

    def __eq__(self, other: "PublicKey") -> bool:
        """
        Checks whether two public keys are equal.

        :param other: other public key
        """
        return self.sec() == other.sec()

    @property
    def point(self): # -> ecdsa.ellipticcurve.Point:
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
        try:
            return ec_pubkey_serialize(self.K, compressed=compressed)
        except NameError:
            return self.K.to_string(encoding="compressed" if compressed else "uncompressed")

    def tweak_add(self, tweak32: bytes) -> "PublicKey":
        return PublicKey(pub_key=ec_pubkey_tweak_add(self.K, tweak32))

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PublicKey":
        """
        Initializes public key from byte sequence.

        :param key_bytes: byte representation of public key
        :return: public key
        """
        try:
            return cls(pub_key=ec_pubkey_parse(key_bytes))
        except NameError:
            return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point) -> "PublicKey":
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
