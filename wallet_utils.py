import enum


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


class Version(object):

    __slots__ = (
        "key_type",
        "bip",
        "testnet"
    )

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
