from typing import List, Callable

from bip32_hd_wallet import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, PrivKeyNode, PubKeyNode,
    bip32_seed_from_mnemonic, Priv_or_PubKeyNode
)
from helper import hash160, sha256, h160_to_p2sh_address, h256_to_p2wsh_address
from wallet_utils import Bip32Path, Version, Key
from script import Script, p2wpkh_script, p2wsh_script


HARDENED = 2 ** 31


class PaperWallet(object):

    __slots__ = (
        "mnemonic",
        "testnet",
        "password",
        "master"
    )

    def __init__(self, testnet: bool = False, entropy: str = None,
                 entropy_bits: int = 256, mnemonic: str = None,
                 password: str = "", master: Priv_or_PubKeyNode = None):
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

    def __eq__(self, other: "PaperWallet") -> bool:
        return self.master == other.master

    @property
    def watch_only(self) -> bool:
        return type(self.master) == PubKeyNode

    @classmethod
    def from_mnemonic(cls, mnemonic: str, password: str = "",
                      testnet: bool = False) -> "PaperWallet":
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

    def node_extended_public_key(self, node: Priv_or_PubKeyNode) -> str:
        version = self.determine_node_version_int(node=node, key_type=Key.PUB)
        return node.extended_public_key(version=int(version))

    def node_extended_private_key(self, node: Priv_or_PubKeyNode) -> str:
        if type(node) == PubKeyNode:
            raise ValueError("wallet is watch only")
        version = self.determine_node_version_int(node=node, key_type=Key.PRV)
        return node.extended_private_key(version=int(version))

    def node_extended_keys(self, node: Priv_or_PubKeyNode) -> dict:
        prv = None if self.watch_only else self.node_extended_private_key(
            node=node
        )
        return {
            "pub": self.node_extended_public_key(node=node),
            "prv": prv
        }

    def p2pkh_address(self, node: Priv_or_PubKeyNode) -> str:
        return node.public_key.address(testnet=self.testnet, addr_type="p2pkh")

    def p2wpkh_address(self, node: Priv_or_PubKeyNode) -> str:
        return node.public_key.address(testnet=self.testnet, addr_type="p2wpkh")

    def p2sh_p2wpkh_address(self, node: Priv_or_PubKeyNode) -> str:
        return h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script(h160=node.public_key.h160()).raw_serialize()
            ),
            testnet=self.testnet
        )

    def p2wsh_address(self, node: Priv_or_PubKeyNode) -> str:
        # TODO remove one of 1of1 multisig and provide rather simple
        # TODO singlesig script
        # TODO [sec, OP_CHECKSIG]
        # TODO witness_script = Script([node.public_key.sec(), 0xac])
        # [OP_1, sec, OP_1, OP_CHECKMULTISIG]
        witness_script = Script([0x51, node.public_key.sec(), 0x51, 0xae])
        sha256_witness_script = sha256(witness_script.raw_serialize())
        return h256_to_p2wsh_address(
            h256=sha256_witness_script,
            testnet=self.testnet
        )

    def p2sh_p2wsh_address(self, node: Priv_or_PubKeyNode) -> str:
        # [OP_1, sec, OP_1, OP_CHECKMULTISIG]
        witness_script = Script([0x51, node.public_key.sec(), 0x51, 0xae])
        sha256_witness_script = sha256(witness_script.raw_serialize())
        redeem_script = p2wsh_script(h256=sha256_witness_script).raw_serialize()
        return h160_to_p2sh_address(
            h160=hash160(redeem_script),
            testnet=self.testnet
        )

    def bip44_triad(self, nodes: List[Priv_or_PubKeyNode]) -> List[List[str]]:
        return self.triad(nodes=nodes, addr_fnc=self.p2pkh_address)

    def bip49_triad(self, nodes: List[Priv_or_PubKeyNode]) -> List[List[str]]:
        return self.triad(nodes=nodes, addr_fnc=self.p2sh_p2wpkh_address)

    def bip84_triad(self, nodes: List[Priv_or_PubKeyNode]) -> List[List[str]]:
        return self.triad(nodes=nodes, addr_fnc=self.p2wpkh_address)

    def triad(self, nodes: List[Priv_or_PubKeyNode],
              addr_fnc: Callable[[Priv_or_PubKeyNode], str]) -> List[List[str]]:
        return [
            [
                str(node),
                addr_fnc(node),
                node.public_key.sec().hex(),
                None if self.watch_only else node.private_key.wif(
                    testnet=self.testnet
                )
            ]
            for node in nodes
        ]

    def bip44(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        path = Bip32Path(
            purpose=44 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self.bip44_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip49(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        path = Bip32Path(
            purpose=49 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self.bip49_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip84(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        path = Bip32Path(
            purpose=84 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_extended_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_extended_keys, self.bip84_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def generate(self, account: int = 0, interval: tuple = (0, 20)) -> dict:
        acct_ext44, triads44 = self.bip44(account=account, interval=interval)
        acct_ext49, triads49 = self.bip49(account=account, interval=interval)
        acct_ext84, triads84 = self.bip84(account=account, interval=interval)
        return {
            "bip44": {"account_extended_keys": acct_ext44, "triads": triads44},
            "bip49": {"account_extended_keys": acct_ext49, "triads": triads49},
            "bip84": {"account_extended_keys": acct_ext84, "triads": triads84},
        }

    def by_path(self, path: str) -> Priv_or_PubKeyNode:
        path = Bip32Path.parse(s=path)
        return self.master.derive_path(index_list=path.to_list())

    def pretty_print(self):
        for bip_name, bip_dct in self.generate().items():
            print(bip_name.upper(), 182 * "=")
            print("\taccount extended keys:")
            print("\t\t" + bip_dct["account_extended_keys"]["prv"])
            print("\t\t" + bip_dct["account_extended_keys"]["pub"])
            print()
            for triad in bip_dct["triads"]:
                print("\t\t", "%16s %s %s %s" % tuple(triad))
