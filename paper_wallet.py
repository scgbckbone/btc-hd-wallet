from bip32_hd_wallet import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, PrivKeyNode, PubKeyNode,
    bip32_seed_from_mnemonic, Priv_or_PubKeyNode
)
from helper import hash160, h160_to_p2sh_address, p2wpkh_script_raw_serialize
from wallet_utils import Bip32Path, Version, Key


HARDENED = 2 ** 31


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

    def determine_node_version_int(self,
                                   node: Priv_or_PubKeyNode,
                                   key_type: Key) -> Version:
        bip = Bip32Path.parse(str(node))
        version = Version(
            key_type=key_type.value,
            testnet=self.testnet,
            bip=bip.bip()
        )
        return version

    def node_extended_public_key(self, node) -> str:
        version = self.determine_node_version_int(node=node, key_type=Key.PUB)
        return node.extended_public_key(version=int(version))

    def node_extended_private_key(self, node) -> str:
        if type(node) == PubKeyNode:
            raise ValueError("wallet is watch only")
        version = self.determine_node_version_int(node=node, key_type=Key.PRV)
        return node.extended_private_key(version=int(version))

    def node_extended_keys(self, node):
        return {
            "pub": self.node_extended_public_key(node=node),
            "prv": self.node_extended_private_key(node=node)
        }

    def triad_from_pub_key(self, children, addr_type):
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
        return self.triad_from_pub_key(children=children, addr_type="p2pkh")

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

    def _bip84(self, children):
        return self.triad_from_pub_key(children=children, addr_type="p2wpkh")

    def bip44(self, account=0, interval=(0, 20)):
        path = Bip32Path(
            purpose=44 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self._bip44(
            children=external_chain_node.generate_children(interval=interval)
        )

    def bip49(self, account=0, interval=(0, 20)):
        path = Bip32Path(
            purpose=49 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self._bip49(
            children=external_chain_node.generate_children(interval=interval)
        )

    def bip84(self, account=0, interval=(0, 20)):
        path = Bip32Path(
            purpose=84 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self._bip84(
            children=external_chain_node.generate_children(interval=interval)
        )

    def generate(self, account=0, interval=(0, 20)):
        acct_ext44, triads44 = self.bip44(account=account, interval=interval)
        acct_ext49, triads49 = self.bip49(account=account, interval=interval)
        acct_ext84, triads84 = self.bip84(account=account, interval=interval)
        return {
            "bip44": {"account_extended_keys": acct_ext44, "triads": triads44},
            "bip49": {"account_extended_keys": acct_ext49, "triads": triads49},
            "bip84": {"account_extended_keys": acct_ext84, "triads": triads84},
        }

    def by_path(self, path: str):
        path = Bip32Path.parse(s=path)
        return self.master.derive_path(index_list=path.to_list())

