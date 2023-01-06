import enum
from typing import Any, List, Union


class Bip(enum.Enum):
    BIP44 = 0
    BIP49 = 1
    BIP84 = 2
    # when it is unknown bip - go with xprv xpub tprv tpub
    UNKNOWN = 0


class Key(enum.Enum):
    PRV = 0
    PUB = 1


def list_get(lst: list, i: int) -> Any:
    try:
        return lst[i]
    except IndexError:
        return None


class Version(object):

    __slots__ = (
        "key_type",
        "bip_type",
        "testnet"
    )

    main: dict = {
        Key.PUB.name: {
            # xpub
            Bip.BIP44.name: 0x0488B21E,
            # ypub
            Bip.BIP49.name: 0x049d7cb2,
            # zpub
            Bip.BIP84.name: 0x04b24746
        },
        Key.PRV.name: {
            # xprv
            Bip.BIP44.name: 0x0488ADE4,
            # yprv
            Bip.BIP49.name: 0x049d7878,
            # zprv
            Bip.BIP84.name: 0x04b2430c
        }
    }
    test: dict = {
        Key.PUB.name: {
            # tpub
            Bip.BIP44.name: 0x043587CF,
            # upub
            Bip.BIP49.name: 0x044a5262,
            # vpub
            Bip.BIP84.name: 0x045f1cf6
        },
        Key.PRV.name: {
            # tprv
            Bip.BIP44.name: 0x04358394,
            # uprv
            Bip.BIP49.name: 0x044a4e28,
            # vprv
            Bip.BIP84.name: 0x045f18bc
        }
    }

    def __init__(self, key_type: int, bip: int, testnet: bool):
        """
        Initializes version object.

        :param key_type: type of key PRV/PUB
        :param bip: bip number
        :param testnet: whether to choose from testnet versions
        """
        self.key_type = Key(key_type)
        self.bip_type = Bip(bip)
        self.testnet = testnet

    def __int__(self) -> int:
        """
        Returns correct extended key version based on key type, bip and network.

        :return: extended key version
        """
        if self.testnet:
            return self.test[self.key_type.name][self.bip_type.name]
        return self.main[self.key_type.name][self.bip_type.name]

    def __index__(self) -> int:
        return self.__int__()

    @classmethod
    def parse(cls, version_int: int) -> "Version":
        """
        Initializes version object from extended key version.

        :param version_int: extended key version
        :return: version object
        """
        if not isinstance(version_int, int):
            raise ValueError("has to be integer")
        if not cls.valid_version(version=version_int):
            raise ValueError("unsupported version")
        testnet = version_int in cls.testnet_versions()
        private = version_int in cls.prv_versions()
        return cls(
            key_type=Key.PRV.value if private else Key.PUB.value,
            bip=cls.bip(version=version_int),
            testnet=testnet
        )

    @classmethod
    def valid_version(cls, version: int) -> bool:
        """
        Checks whether version is valid version.

        Valid version means a version, that is recognized by this software.

        :param version: extended key version
        :return: True/False
        """
        _all = cls.testnet_versions() + cls.mainnet_versions()
        if version in _all:
            return True
        return False

    @classmethod
    def bip(cls, version: int) -> int:
        """
        Matches version to corresponding bip.

        :param version: extended key version
        :return: bip number
        """
        if version in cls.bip44_data().values():
            return Bip.BIP44.value
        elif version in cls.bip49_data().values():
            return Bip.BIP49.value
        elif version in cls.bip84_data().values():
            return Bip.BIP84.value
        else:
            return Bip.BIP44.value

    @classmethod
    def bip44_data(cls) -> dict:
        """
        Provides mapping with bip44 versions.

        :return: mapping from b58 encoded representation to extended key version
        """
        return {
            "xprv": cls.main[Key.PRV.name][Bip.BIP44.name],
            "xpub": cls.main[Key.PUB.name][Bip.BIP44.name],
            "tprv": cls.test[Key.PRV.name][Bip.BIP44.name],
            "tpub": cls.test[Key.PUB.name][Bip.BIP44.name],
        }

    @classmethod
    def bip49_data(cls) -> dict:
        """
        Provides mapping with bip49 versions.

        :return: mapping from b58 encoded representation to extended key version
        """
        return {
            "yprv": cls.main[Key.PRV.name][Bip.BIP49.name],
            "ypub": cls.main[Key.PUB.name][Bip.BIP49.name],
            "uprv": cls.test[Key.PRV.name][Bip.BIP49.name],
            "upub": cls.test[Key.PUB.name][Bip.BIP49.name],
        }

    @classmethod
    def bip84_data(cls) -> dict:
        """
        Provides mapping with bip84 versions.

        :return: mapping from b58 encoded representation to extended key version
        """
        return {
            "zprv": cls.main[Key.PRV.name][Bip.BIP84.name],
            "zpub": cls.main[Key.PUB.name][Bip.BIP84.name],
            "vprv": cls.test[Key.PRV.name][Bip.BIP84.name],
            "vpub": cls.test[Key.PUB.name][Bip.BIP84.name],
        }

    @staticmethod
    def get_versions(dct: dict) -> List[int]:
        """
        Gets versions from version mapping.

        :param dct: version mapping
        :return: sequence of versions
        """
        res = []
        for k, v in dct.items():
            res += v.values()
        return res

    @classmethod
    def key_versions(cls, key_type: str) -> List[int]:
        """
        Gets versions for specific key type.

        :param key_type: type of key PRV/PUB
        :return: sequence of version for specific key type
        """
        return list(cls.test[key_type].values()) + \
            list(cls.main[key_type].values())

    @classmethod
    def mainnet_versions(cls) -> List[int]:
        """
        Gets mainnet version.

        :return: sequence of mainnet versions
        """
        return cls.get_versions(cls.main)

    @classmethod
    def testnet_versions(cls) -> List[int]:
        """
        Gets testnet version.

        :return: sequence of testnet versions
        """
        return cls.get_versions(cls.test)

    @classmethod
    def prv_versions(cls) -> List[int]:
        """
        Gets private key versions.

        :return: sequence of private key versions
        """
        return cls.key_versions(key_type=Key.PRV.name)

    @classmethod
    def pub_versions(cls) -> List[int]:
        """
        Gets public key versions.

        :return: sequence of public key versions
        """
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
        """
        Initializes path object.

        :param purpose: bip44 purpose (default=None)
        :param coin_type: bip44 coin type (default=None)
        :param account: bip44 account (default=None)
        :param chain: bip44 chain (default=None)
        :param addr_index: bip44 address index (default=None)
        :param private: whether this path corresponds to private key
                        (default=True)
        """
        self.purpose = purpose
        self.coin_type = coin_type
        self.account = account
        self.chain = chain
        self.addr_index = addr_index
        self.private = private
        self.integrity_check()

    def integrity_check(self) -> None:
        """
        Assures that current path makes logical sense.

        Checks if no value has None on the left side. For example if account
        is given, both purpose and coin type has to be known too. If this
        is not the case - RuntimeError is raised.

        :return: None
        """
        none_found = False
        for item in self._to_list():
            if item is None:
                none_found = True
            else:
                if none_found:
                    raise RuntimeError("integrity check failure")
                if not isinstance(item, int):
                    raise ValueError("has to be int")

    def __repr__(self) -> str:
        items = [self.repr_hardened(i) for i in self.to_list()]
        items = [self.m] + items
        return "/".join(items)

    def __eq__(self, other: "Bip32Path") -> bool:
        """
        Checks whether two paths are equal.

        :param other: other path
        """
        return self.m == other.m and \
            self.purpose == other.purpose and \
            self.coin_type == other.coin_type and \
            self.account == other.account and \
            self.chain == other.chain and \
            self.addr_index == other.addr_index

    @property
    def m(self) -> str:
        """
        Chooses correct mark. M for public key and m for private key.

        :return: correct mark
        """
        return "m" if self.private else "M"

    @property
    def bitcoin_testnet(self) -> bool:
        """
        Testnet path.

        :return: whether this path is testnet path
        """
        return self.coin_type == 0x80000001

    @property
    def bitcoin_mainnet(self) -> bool:
        """
        Mainnet path.

        :return: whether this path is mainnet path
        """
        return self.coin_type == 0x80000000

    @property
    def external_chain(self) -> bool:
        """
        External chain path.

        :return: whether this path is external chain path
        """
        return self.chain == 0

    @property
    def bip44(self) -> bool:
        """
        Bip44 path.

        :return: whether this path is bip44 path
        """
        return self.purpose == 44 + (2 ** 31)

    @property
    def bip49(self) -> bool:
        """
        bip49 path.

        :return: whether this path is bip49 path
        """
        return self.purpose == 49 + (2 ** 31)

    @property
    def bip84(self) -> bool:
        """
        Bip84 path.

        :return: whether this path is bip84 path
        """
        return self.purpose == 84 + (2 ** 31)

    def bip(self) -> int:
        """
        Check current object purpose path and returns bip value.

        :return: bip number
        """
        if self.bip44:
            return Bip.BIP44.value
        elif self.bip49:
            return Bip.BIP49.value
        elif self.bip84:
            return Bip.BIP84.value
        else:
            return Bip.BIP44.value

    @staticmethod
    def is_hardened(num: int) -> bool:
        """
        Checks whether num is hardened i.e. bigger or equal than
        2 to the power of 31.

        :param num: number
        :return: whether num is hardened
        """
        return num >= 2 ** 31

    @staticmethod
    def is_private(sign) -> bool:
        """
        Check whether mark/sign is for private key.

        :param sign: mark M/m
        :return: whether is private
        """
        return True if sign == "m" else False

    @staticmethod
    def convert_hardened(str_int: str) -> int:
        """
        Converts hardened string representation to integer.

        :param str_int: string representation of number
        :return: number
        """
        if str_int[-1] in ("'", "h"):
            return int(str_int[:-1]) + (2 ** 31)
        return int(str_int)

    def repr_hardened(self, num: int) -> str:
        """
        Converts integer to hardened string representation .

        :param num: number
        :return: string representation of number
        """
        if self.is_hardened(num):
            return str(num - 2 ** 31) + "'"
        else:
            return str(num)

    def _to_list(self) -> List[Union[int, None]]:
        """
        Converts path to sequence.

        :return: sequence of numbers
        """
        return [
            self.purpose,
            self.coin_type,
            self.account,
            self.chain,
            self.addr_index
        ]

    def to_list(self) -> List[int]:
        """
        Converts path to sequence.

        :return: sequence of numbers
        """
        return [x for x in self._to_list() if x is not None]

    @classmethod
    def parse(cls, s: str) -> "Bip32Path":
        """
        Initializes path from its string representation.

        :param s: path
        :return: path object
        """
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
