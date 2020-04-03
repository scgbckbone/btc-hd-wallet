from bip32_hd_wallet import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, PrivKeyNode,
    bip32_seed_from_mnemonic
)
from helper import hash160, h160_to_p2sh_address

# m/44'/0'/0'/0
BIP44_PATH = (44 + 2**31, 2**31, 2**31, 0)
# m/49'/0'/0'/0
BIP49_PATH = (49 + 2**31, 2**31, 2**31, 0)
# m/84'/0'/0'/0
BIP84_PATH = (84 + 2**31, 2**31, 2**31, 0)


class ColdWallet(object):
    def __init__(self, testnet=False, entropy=None, entropy_bits=256, password=""):
        self.testnet = testnet
        if entropy is None:
            self.mnemonic = mnemonic_from_entropy_bits(entropy_bits=entropy_bits)
        else:
            self.mnemonic = mnemonic_from_entropy(entropy=entropy)
        self.master = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(
                mnemonic=self.mnemonic,
                password=password
            )
        )

    @classmethod
    def from_mnemonic(cls):
        pass

    def bip44(self, index_list=BIP44_PATH, interval=(0, 20)):
        res = []
        node = self.master
        for i in index_list:
            node = node.ckd(index=i)
        for child in node.generate_children(interval=interval):
            res.append([
                str(child),
                child.public_key.address(testnet=self.testnet),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet)
            ])
        return res

    def bip49(self, index_list=BIP49_PATH, interval=(0, 20)):
        res = []
        node = self.master
        for i in index_list:
            node = node.ckd(index=i)
        for child in node.generate_children(interval=interval):
            res.append([
                str(child),
                h160_to_p2sh_address(
                    h160=hash160(
                        p2wpkh_script(
                            h160=hash160(child.public_key.sec())
                        ).raw_serialize()
                    ),
                    testnet=self.testnet
                ),
                child.public_key.sec().hex(),
                child.private_key.wif(testnet=self.testnet),

            ])
        return res

    def bip84(self, index_list=BIP84_PATH, interval=(0, 20)):
        res = []
        node = self.master
        for i in index_list:
            node = node.ckd(index=i)
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

