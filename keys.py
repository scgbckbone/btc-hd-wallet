import ecdsa

from helper import (
    encode_base58_checksum, decode_base58_checksum, big_endian_to_int,
    hash160, h160_to_p2wpkh_address
)


SECP256k1 = ecdsa.curves.SECP256k1


class PrivateKey(object):
    def __init__(self, sec_exp):
        self.sec_exp = sec_exp
        self.k = ecdsa.SigningKey.from_secret_exponent(
            secexp=sec_exp,
            curve=SECP256k1
        )
        self.K = PublicKey(key=self.k.get_verifying_key())

    def __bytes__(self):
        return self.k.to_string()

    def __eq__(self, other):
        return self.sec_exp == other.sec_exp

    def wif(self, compressed=True, testnet=False):
        prefix = b"\xef" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        return encode_base58_checksum(prefix + bytes(self) + suffix)

    @classmethod
    def from_wif(cls, wif_str: str):
        decoded = decode_base58_checksum(s=wif_str)
        if wif_str[0] in ("K", "L", "c"):
            # compressed key --> so remove last byte that has to be 01
            assert decoded[-1] == 1
            decoded = decoded[:-1]
        return cls(sec_exp=big_endian_to_int(decoded[1:]))

    @classmethod
    def parse(cls, byte_str: bytes):
        return cls(sec_exp=big_endian_to_int(byte_str))


class PublicKey(object):
    def __init__(self, key: ecdsa.VerifyingKey):
        self.K = key

    @property
    def point(self):
        return self.K.pubkey.point

    def sec(self, compressed=True):
        if compressed:
            return self.K.to_string(encoding="compressed")
        return self.K.to_string(encoding="uncompressed")

    @classmethod
    def parse(cls, key_bytes):
        return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point):
        return cls(ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1))

    def h160(self, compressed=True):
        return hash160(self.sec(compressed=compressed))

    def address(self, compressed=True, testnet=False, addr_type="p2pkh"):
        h160 = self.h160(compressed=compressed)
        if addr_type == "p2pkh":
            prefix = b"\x6f" if testnet else b"\x00"
            return encode_base58_checksum(prefix + h160)
        elif addr_type == "p2wpkh":
            return h160_to_p2wpkh_address(h160=h160, testnet=testnet)
        raise ValueError("Unsupported address type.")
