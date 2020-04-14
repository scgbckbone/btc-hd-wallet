from bip32_hd_wallet import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, PrivKeyNode, PubKeyNode,
    bip32_seed_from_mnemonic
)
from helper import hash160, h160_to_p2sh_address, p2wpkh_script_raw_serialize
from wallet_utils import Bip32Path, Version, Key


# m/44'/0'/0'/0
BIP44_PATH = [44 + 2**31, 2**31, 2**31, 0]
# m/49'/0'/0'/0
BIP49_PATH = [49 + 2**31, 2**31, 2**31, 0]
# m/84'/0'/0'/0
BIP84_PATH = [84 + 2**31, 2**31, 2**31, 0]


class PaperWallet(object):

    __slots__ = (
        "mnemonic",
        "testnet",
        "password",
        "master"
    )

    def __init__(self, testnet=False, entropy=None, entropy_bits=256,
                 mnemonic=None, password="", master=None):
        self.testnet = testnet
        if master is None:
            if mnemonic is None:
                if entropy is None:
                    self.mnemonic = mnemonic_from_entropy_bits(
                        entropy_bits=entropy_bits
                    )
                else:
                    self.mnemonic = mnemonic_from_entropy(entropy=entropy)
            else:
                self.mnemonic = mnemonic

            self.password = password
            self.master = PrivKeyNode.master_key(
                bip32_seed=bip32_seed_from_mnemonic(
                    mnemonic=self.mnemonic,
                    password=self.password,
                ),
                testnet=testnet
            )
        else:
            self.master = master

    def __eq__(self, other):
        return self.master == other.master

    @property
    def watch_only(self):
        return False if type(self.master) == PrivKeyNode else True

    @classmethod
    def from_mnemonic(cls, mnemonic: str, password: str = "", testnet=False):
        return cls(
            mnemonic=mnemonic,
            password=password,
            testnet=testnet
        )

    @classmethod
    def from_extended_key(cls, extended_key: str) -> "PaperWallet":
        # just need version, key type does not matter in here
        version_int = PrivKeyNode.parse(s=extended_key).parsed_version
        version = Version.parse(s=version_int)
        if version.key_type == Key.PRV:
            node = PrivKeyNode.parse(extended_key, testnet=version.testnet)
        else:
            # is this just assuming? or really pub if not priv
            node = PubKeyNode.parse(extended_key, testnet=version.testnet)
        return cls(testnet=version.testnet, master=node)

    def _from_pub_key(self, children, addr_type):
        # TODO this routine has to be renamed
        return [
            [
                str(child),
                child.public_key.address(
                    testnet=self.testnet,
                    addr_type=addr_type
                ),
                child.public_key.sec().hex(),
                None if self.watch_only else child.private_key.wif(
                    testnet=self.testnet
                )
            ]
            for child in children
        ]

    def _bip44(self, children):
        return self._from_pub_key(children=children, addr_type="p2pkh")

    def bip44(self, interval=(0, 20)):
        res = []
        index_list = BIP44_PATH
        if self.testnet:
            index_list[1] += 1
        node = self.master.derive_path(index_list=index_list)
        for child in node.generate_children(interval=interval):
            res.append([
                str(child),
                child.public_key.address(testnet=self.testnet),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet)
            ])
        return res

    def _bip49(self, children):
        return [
            [
                str(child),
                h160_to_p2sh_address(
                    h160=hash160(
                        p2wpkh_script_raw_serialize(child.public_key.h160())
                    ),
                    testnet=self.testnet
                ),
                child.public_key.sec().hex(),
                None if self.watch_only else child.private_key.wif(
                    testnet=self.testnet
                )
            ]
            for child in children
        ]

    def bip49(self, interval=(0, 20)):
        res = []
        index_list = BIP49_PATH
        if self.testnet:
            index_list[1] += 1
        node = self.master.derive_path(index_list=index_list)
        for child in node.generate_children(interval=interval):
            res.append([
                str(child),
                h160_to_p2sh_address(
                    h160=hash160(
                        p2wpkh_script_raw_serialize(child.public_key.h160())
                    ),
                    testnet=self.testnet
                ),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet),

            ])
        return res

    def _bip84(self, children):
        return self._from_pub_key(children=children, addr_type="p2wpkh")

    def bip84(self, interval=(0, 20)):
        index_list = BIP84_PATH
        if self.testnet:
            index_list[1] += 1
        node = self.master.derive_path(index_list=index_list)
        return self._bip84(children=node.generate_children(interval=interval))

    def generate(self):
        return {
            "bip44": self.bip44(),
            "bip49": self.bip49(),
            "bip84": self.bip84(),
        }

    def by_path(self, path: str):
        path = Bip32Path.parse(s=path)
        return self.master.derive_path(index_list=path.to_list())
