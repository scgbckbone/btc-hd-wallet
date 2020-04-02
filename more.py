import re
import hmac
import enum
import ecdsa
import random
import hashlib
import requests
import unicodedata
from io import BytesIO
from typing import List


from helper import (
    sha256, encode_base58_checksum, big_endian_to_int, int_to_big_endian,
    h160_to_p2sh_address, hash160,
    decode_base58_check,
    h160_to_p2wpkh_address)


random = random.SystemRandom()

PBKDF2_ROUNDS = 2048

SECP256k1 = ecdsa.curves.SECP256k1
CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER = CURVE_GEN.order()
FIELD_ORDER = ecdsa.curves.SECP256k1.curve.p()
INFINITY = ecdsa.ellipticcurve.INFINITY


class Bip(enum.Enum):
    BIP44 = 0
    BIP49 = 1
    BIP84 = 2
    # when it is unknown bip - go with xprv xpub tprv tpub
    UNKNOWN = 0


class Key(enum.Enum):
    PRV = 0
    PUB = 1


def list_get(lst: list, i: int):
    try:
        return lst[i]
    except IndexError:
        return None


def get_word_list() -> List[str]:
    url = "https://raw.githubusercontent.com"
    uri = "/bitcoin/bips/master/bip-0039/english.txt"
    return requests.get(url + uri).text.split()


def correct_entropy_bits_value(entropy_bits: int) -> None:
    if entropy_bits not in [128, 160, 192, 224, 256]:
        raise ValueError("incorrect entropy bits")


def checksum_length(entropy_bits: int) -> int:
    return int(entropy_bits / 32)


def mnemonic_sentence_length(entropy_bits: int) -> int:
    return int((entropy_bits + checksum_length(entropy_bits)) / 11)


def mnemonic_from_entropy_bits(entropy_bits: int = 256) -> str:
    correct_entropy_bits_value(entropy_bits=entropy_bits)
    entropy_int = random.getrandbits(entropy_bits)
    entropy_bytes = int_to_big_endian(entropy_int, 32)
    return mnemonic_from_entropy(entropy_bytes.hex())


def mnemonic_from_entropy(entropy: str, word_list=None) -> str:
    if word_list is None:
        word_list = get_word_list()
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
    pass


class Version(object):
    main = {
        Key.PUB.name: {
            Bip.BIP44.name: 0x0488B21E,
            Bip.BIP49.name: 0x049d7cb2,
            Bip.BIP84.name: 0x04b24746
        },
        Key.PRV.name: {
            Bip.BIP44.name: 0x0488ADE4,
            Bip.BIP49.name: 0x049d7878,
            Bip.BIP84.name: 0x04b2430c
        }
    }
    test = {
        Key.PUB.name: {
            Bip.BIP44.name: 0x043587CF,
            Bip.BIP49.name: 0x044a5262,
            Bip.BIP84.name: 0x045f1cf6
        },
        Key.PRV.name: {
            Bip.BIP44.name: 0x04358394,
            Bip.BIP49.name: 0x044a4e28,
            Bip.BIP84.name: 0x045f18bc
        }
    }

    def __init__(self, key_type, bip, testnet):
        self.key_type = Key(key_type)
        self.bip = Bip(bip)
        self.testnet = testnet

    def __int__(self):
        if self.testnet:
            return self.test[self.key_type.name][self.bip.name]
        return self.main[self.key_type.name][self.bip.name]

    def __hex__(self):
        return hex(self.__int__())

    @classmethod
    def parse(cls, s: int):
        if not isinstance(s, int):
            raise ValueError("has to be integer")
        if not cls.valid_version(version=s):
            raise ValueError("invalid version")
        testnet = s in cls.testnet_versions()
        private = s in cls.priv_versions()
        return cls(
            key_type=Key.PRV.value if private else Key.PUB.value,
            bip=cls.bip(version=s),
            testnet=testnet
        )

    @classmethod
    def valid_version(cls, version):
        _all = cls.testnet_versions() + cls.mainnet_versions()
        if version in _all:
            return True
        return False

    @classmethod
    def bip(cls, version):
        if version in cls.bip44_data().values():
            return Bip.BIP44.value
        elif version in cls.bip49_data().values():
            return Bip.BIP49.value
        elif version in cls.bip84_data().values():
            return Bip.BIP84.value
        else:
            return Bip.BIP44.value

    @classmethod
    def bip44_data(cls):
        return {
            "xprv": cls.main[Key.PRV.name][Bip.BIP44.name],
            "xpub": cls.main[Key.PUB.name][Bip.BIP44.name],
            "tprv": cls.test[Key.PRV.name][Bip.BIP44.name],
            "tpub": cls.test[Key.PUB.name][Bip.BIP44.name],
        }

    @classmethod
    def bip49_data(cls):
        return {
            "yprv": cls.main[Key.PRV.name][Bip.BIP49.name],
            "ypub": cls.main[Key.PUB.name][Bip.BIP49.name],
            "uprv": cls.test[Key.PRV.name][Bip.BIP49.name],
            "upub": cls.test[Key.PUB.name][Bip.BIP49.name],
        }

    @classmethod
    def bip84_data(cls):
        return {
            "zprv": cls.main[Key.PRV.name][Bip.BIP84.name],
            "zpub": cls.main[Key.PUB.name][Bip.BIP84.name],
            "vprv": cls.test[Key.PRV.name][Bip.BIP84.name],
            "vpub": cls.test[Key.PUB.name][Bip.BIP84.name],
        }

    @staticmethod
    def get_versions(dct):
        res = []
        for k, v in dct.items():
            res += v.values()
        return res

    @classmethod
    def key_versions(cls, key_type):
        return list(cls.test[key_type].values()) + \
               list(cls.main[key_type].values())

    @classmethod
    def mainnet_versions(cls):
        return cls.get_versions(cls.main)

    @classmethod
    def testnet_versions(cls):
        return cls.get_versions(cls.test)

    @classmethod
    def priv_versions(cls):
        return cls.key_versions(key_type=Key.PRV.name)

    @classmethod
    def pub_versions(cls):
        return cls.key_versions(key_type=Key.PUB.name)


class Bip32Path(object):

    __slots__ = (
        "purpose",
        "coin_type",
        "account",
        "chain",
        "addr_index",
        "private"
    )

    def __init__(self, purpose: int = None, coin_type: int = None,
                 account: int = None, chain: int = None, addr_index: int = None,
                 private=True):
        self.purpose = purpose
        self.coin_type = coin_type
        self.account = account
        self.chain = chain
        self.addr_index = addr_index
        self.private = private
        self.integrity_check()

    def integrity_check(self):
        none_found = False
        for item in self._to_list():
            if item is None:
                none_found = True
            else:
                if none_found:
                    raise RuntimeError("integrity check failure")
                if not isinstance(item, int):
                    raise ValueError("has to be int")

    def __repr__(self):
        items = [self.repr_hardened(i) for i in self.to_list() if i is not None]
        items = [self.m] + items
        return "/".join(items)

    def __eq__(self, other):
        return self.m == other.m and \
            self.purpose == other.purpose and \
            self.coin_type == other.coin_type and \
            self.account == other.account and \
            self.chain == other.chain and \
            self.addr_index == other.addr_index

    @property
    def m(self):
        return "m" if self.private else "M"

    @property
    def bitcoin_testnet(self):
        return self.coin_type == 0x80000001

    @property
    def bitcoin_mainnet(self):
        return self.coin_type == 0x80000000

    @property
    def external_chain(self):
        return self.chain == 0

    @property
    def bip44(self):
        return self.purpose == 44 + (2 ** 31)

    @property
    def bip49(self):
        return self.purpose == 49 + (2 ** 31)

    @property
    def bip84(self):
        return self.purpose == 84 + (2 ** 31)

    def bip(self):
        if self.bip44:
            return Bip.BIP44.value
        elif self.bip49:
            return Bip.BIP49.value
        elif self.bip84:
            return Bip.BIP84.value
        else:
            return Bip.BIP44.value

    @staticmethod
    def is_hardened(num: int):
        return num >= 2 ** 31

    @staticmethod
    def is_private(sign):
        return True if sign == "m" else False

    @staticmethod
    def convert_hardened(str_int: str) -> int:
        if str_int[-1] == "'":
            return int(str_int[:-1]) + (2 ** 31)
        return int(str_int)

    def repr_hardened(self, num: int):
        if self.is_hardened(num):
            return str(num - 2 ** 31) + "'"
        else:
            return str(num)

    def _to_list(self):
        return [
            self.purpose,
            self.coin_type,
            self.account,
            self.chain,
            self.addr_index
        ]

    def to_list(self):
        return [x for x in self._to_list() if x is not None]

    @classmethod
    def parse(cls, s: str):
        s_lst = s.split("/")
        if s_lst[0] not in ("m", "M"):
            raise ValueError("incorrect marker")
        purpose = list_get(s_lst, 1)
        coin_type = list_get(s_lst, 2)
        account = list_get(s_lst, 3)
        chain = list_get(s_lst, 4)
        addr_index = list_get(s_lst, 5)
        return cls(
            purpose=cls.convert_hardened(purpose) if purpose else None,
            coin_type=cls.convert_hardened(coin_type) if coin_type else None,
            account=cls.convert_hardened(account) if account else None,
            chain=cls.convert_hardened(chain) if chain else None,
            addr_index=cls.convert_hardened(addr_index) if addr_index else None,
            private=cls.is_private(sign=s_lst[0])
        )


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
        decoded = decode_base58_check(s=wif_str)
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

    def address(self, compressed=True, testnet=True, addr_type="p2pkh"):
        h160 = self.h160(compressed=compressed)
        if addr_type == "p2pkh":
            prefix = b"\x6f" if testnet else b"\x00"
            return encode_base58_checksum(prefix + h160)
        elif addr_type == "p2wpkh":
            return h160_to_p2wpkh_address(h160=h160, testnet=testnet)
        raise ValueError("Unsupported address type.")


class PubKeyNode(object):

    mark = "M"

    __slots__ = (
        "parent",
        "_key",
        "chain_code",
        "depth",
        "index",
        "_parent_fingerprint",
        "testnet",
        "children"
    )

    def __init__(self, key, chain_code, index=0, depth=0, testnet=False,
                 parent=None, parent_fingerprint=None):
        self.parent = parent
        self._key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self._parent_fingerprint = parent_fingerprint
        self.testnet = testnet
        self.children = []

    @property
    def public_key(self):
        return PublicKey.parse(key_bytes=self._key)

    @property
    def parent_fingerprint(self):
        if self.parent:
            fingerprint = self.parent.fingerprint()
        else:
            if self._parent_fingerprint is None:
                raise RuntimeError()
            fingerprint = self._parent_fingerprint
        return fingerprint

    def check_fingerprint(self):
        if self.parent and self._parent_fingerprint:
            return self.parent.fingerprint() == self._parent_fingerprint

    def __repr__(self):
        if self.is_master():
            return self.mark
        if self.is_hardened():
            index = str(self.index - 2**31) + "'"
        else:
            index = str(self.index)
        parent = str(self.parent) if self.parent else self.mark
        return parent + "/" + index

    def is_hardened(self):
        return self.index >= 2**31

    def is_master(self):
        return self.depth == 0 and self.index == 0 and self.parent is None

    def is_root(self):
        return self.parent is None

    def serialize_index(self):
        return int_to_big_endian(self.index, 4)

    def fingerprint(self):
        return hash160(self.public_key.sec())[:4]

    @classmethod
    def parse(cls, s):
        if isinstance(s, str):
            s = BytesIO(decode_base58_check(s=s))
        elif isinstance(s, bytes):
            s = BytesIO(s)
        elif isinstance(s, BytesIO):
            pass
        else:
            raise ValueError("has to be bytes, str or BytesIO")
        return cls._parse(s)

    @classmethod
    def _parse(cls, s):
        version = Version.parse(s=big_endian_to_int(s.read(4)))
        depth = big_endian_to_int(s.read(1))
        parent_fingerprint = s.read(4)
        index = big_endian_to_int(s.read(4))
        chain_code = s.read(32)
        key_bytes = s.read(33)
        return cls(
            key=key_bytes,
            chain_code=chain_code,
            index=index,
            depth=depth,
            testnet=version.testnet,
            parent_fingerprint=parent_fingerprint,
        )

    def _serialize(self, version, key):
        # 4 byte: version bytes
        result = int_to_big_endian(int(version), 4)
        # 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys
        result += int_to_big_endian(self.depth, 1)
        # 4 bytes: the fingerprint of the parent key (0x00000000 if master key)
        if self.is_master():
            result += int_to_big_endian(0x00000000, 4)
        else:
            result += self.parent_fingerprint
        # 4 bytes: child number. This is ser32(i) for i in xi = xpar/i,
        # with xi the key being serialized. (0x00000000 if master key)
        result += self.serialize_index()
        # 32 bytes: the chain code
        result += self.chain_code
        # 33 bytes: the public key serP(K)
        result += key
        return result

    def serialize_public(self, bip=None):
        path = Bip32Path.parse(str(self))
        version = Version(
            key_type=Key.PUB.value,
            bip=bip if bip else path.bip(),
            testnet=path.bitcoin_testnet
        )
        return self._serialize(
            version=int(version),
            key=self.public_key.sec()
        )

    def extended_public_key(self, bip=None) -> str:
        return encode_base58_checksum(self.serialize_public(bip=bip))

    def ckd(self, index):
        if index >= 2 ** 31:
            # (hardened child): return failure
            raise RuntimeError("failure: hardened child")
        I = hmac.new(
            key=self.chain_code,
            msg=self._key + int_to_big_endian(index, 4),
            digestmod=hashlib.sha512
        ).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            raise InvalidKeyError("greater or equal to curve order")
        point = PrivateKey.parse(IL).K.point + self.public_key.point
        if point == INFINITY:
            raise InvalidKeyError("point at infinity")
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

    def generate_children(self, interval: tuple = (0, 20)):
        return [self.ckd(index=i) for i in range(*interval)]


class PrivKeyNode(PubKeyNode):
    mark = "m"

    @property
    def private_key(self):
        return PrivateKey(sec_exp=big_endian_to_int(self._key))

    @property
    def public_key(self):
        return self.private_key.K

    @classmethod
    def master_key(cls, bip32_seed: bytes):
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
            raise InvalidKeyError("master key is greater/equal to curve order")
        # chain code
        IR = I[32:]
        return cls(
            key=IL,
            chain_code=IR
        )

    def serialize_private(self, bip=None):
        path = Bip32Path.parse(str(self))
        version = Version(
            key_type=Key.PRV.value,
            bip=bip if bip else path.bip(),
            testnet=path.bitcoin_testnet
        )
        return self._serialize(
            version=int(version),
            key=b"\x00" + bytes(self.private_key)
        )

    def extended_private_key(self, bip=None) -> str:
        return encode_base58_checksum(self.serialize_private(bip=bip))

    def ckd(self, index):
        if index >= 2**31:
            # hardened
            data = b"\x00" + bytes(self.private_key) + index.to_bytes(4, "big")
        else:
            data = self.public_key.sec() + index.to_bytes(4, "big")
        I = hmac.new(
            key=self.chain_code,
            msg=data,
            digestmod=hashlib.sha512
        ).digest()
        IL, IR = I[:32], I[32:]
        if big_endian_to_int(IL) >= CURVE_ORDER:
            InvalidKeyError("greater or equal to curve order")
        ki = (int.from_bytes(IL, "big") +
              big_endian_to_int(bytes(self.private_key))) % CURVE_ORDER
        if ki == 0:
            InvalidKeyError("is zero")
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

    @classmethod
    def by_path(cls, path: str, mnemonic: str, password: str = ""):
        seed = bip32_seed_from_mnemonic(mnemonic=mnemonic, password=password)
        m = cls.master_key(bip32_seed=seed)
        path = Bip32Path.parse(s=path)
        node = m
        for index in path.to_list():
            node = node.ckd(index=index)
        return node

    @classmethod
    def cold_wallet_bip49(cls, mnemonic: str, pwd: str = "", testnet: bool = False):
        path = "m/49'/0'/0'/0"
        res = []
        node = cls.by_path(mnemonic=mnemonic, password=pwd, path=path)
        node.generate_children()
        for child in node.children:
            res.append([
                str(child),
                h160_to_p2sh_address(
                    h160=hash160(
                        p2wpkh_script(
                            h160=hash160(child.public_key.sec())
                        ).raw_serialize()
                    ),
                    testnet=testnet
                ),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=testnet),

            ])
        return res

    @classmethod
    def cold_wallet_bip84(cls, mnemonic: str, pwd: str = "", testnet: bool = False):
        path = "m/84'/0'/0'/0"
        res = []
        node = cls.by_path(mnemonic=mnemonic, password=pwd, path=path)
        node.generate_children()
        for child in node.children:
            res.append([
                str(child),
                child.public_key.address(testnet=testnet, addr_type="p2wpkh"),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=testnet)
            ])
        return res

    @classmethod
    def cold_wallet_bip44(cls, mnemonic: str, pwd: str = "", testnet: bool = False):
        path = "m/44'/0'/0'/0"
        res = []
        node = cls.by_path(mnemonic=mnemonic, password=pwd, path=path)
        node.generate_children()
        for child in node.children:
            res.append([
                str(child),
                child.public_key.address(testnet=testnet),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=testnet)
            ])
        return res

    @classmethod
    def cold_wallet(cls, mnemonic: str, pwd: str = "", testnet: bool = False):
        return {
            "bip44": cls.cold_wallet_bip44(
                mnemonic=mnemonic,
                pwd=pwd,
                testnet=testnet
            ),
            "bip49": cls.cold_wallet_bip49(
                mnemonic=mnemonic,
                pwd=pwd,
                testnet=testnet
            ),
            "bip84": cls.cold_wallet_bip84(
                mnemonic=mnemonic,
                pwd=pwd,
                testnet=testnet
            ),
        }

