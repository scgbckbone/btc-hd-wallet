from bip32_hd_wallet import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, PrivKeyNode,
    bip32_seed_from_mnemonic
)
from helper import hash160, h160_to_p2sh_address, p2wpkh_script_serialized

# m/44'/0'/0'/0
BIP44_PATH = [44 + 2**31, 2**31, 2**31, 0]
# m/49'/0'/0'/0
BIP49_PATH = [49 + 2**31, 2**31, 2**31, 0]
# m/84'/0'/0'/0
BIP84_PATH = [84 + 2**31, 2**31, 2**31, 0]


class ColdWallet(object):

    __slots__ = (
        "mnemonic",
        "testnet",
        "password",
        "master"
    )

    def __init__(self, testnet=False, entropy=None, entropy_bits=256,
                 mnemonic=None, password=""):
        if mnemonic is None:
            if entropy is None:
                self.mnemonic = mnemonic_from_entropy_bits(
                    entropy_bits=entropy_bits
                )
            else:
                self.mnemonic = mnemonic_from_entropy(entropy=entropy)
        else:
            self.mnemonic = mnemonic

        self.testnet = testnet
        self.password = password
        self.master = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(
                mnemonic=self.mnemonic,
                password=password
            )
        )

    def __eq__(self, other):
        return self.mnemonic == other.mnemonic \
               and self.password == other.password

    @classmethod
    def from_mnemonic(cls, mnemonic: str, password: str = "", testnet=False):
        return cls(
            mnemonic=mnemonic,
            password=password,
            testnet=testnet
        )

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
                        p2wpkh_script_serialized(child.public_key.h160())
                    ),
                    testnet=self.testnet
                ),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet),

            ])
        return res

    def bip84(self, interval=(0, 20)):
        res = []
        index_list = BIP84_PATH
        if self.testnet:
            index_list[1] += 1
        node = self.master.derive_path(index_list=index_list)
        for child in node.generate_children(interval=interval):
            res.append([
                str(child),
                child.public_key.address(
                    testnet=self.testnet,
                    addr_type="p2wpkh"
                ),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet)
            ])
        return res

    def generate(self):
        return {
            "bip44": self.bip44(),
            "bip49": self.bip49(),
            "bip84": self.bip84(),
        }

