import sys
import json
from typing import List, Callable

from btc_hd_wallet.bip32 import Prv_or_PubKeyNode, HARDENED
from btc_hd_wallet.wallet_utils import Bip32Path
from btc_hd_wallet.base_wallet import BaseWallet


class PaperWallet(BaseWallet):

    def bip44_group(self, nodes: List[Prv_or_PubKeyNode]) -> List[List[str]]:
        """
        Generates bip44 groups (path, address, sec, wif) from nodes.

        :param nodes: nodes for group generation
        :return: generated groups
        """
        return self.group(nodes=nodes, addr_fnc=self.p2pkh_address)

    def bip49_group(self, nodes: List[Prv_or_PubKeyNode]) -> List[List[str]]:
        """
        Generates bip49 groups (path, address, sec, wif) from nodes.

        :param nodes: nodes for group generation
        :return: generated groups
        """
        return self.group(nodes=nodes, addr_fnc=self.p2sh_p2wpkh_address)

    def bip84_group(self, nodes: List[Prv_or_PubKeyNode]) -> List[List[str]]:
        """
        Generates bip84 groups (path, address, sec, wif) from nodes.

        :param nodes: nodes for group generation
        :return: generated groups
        """
        return self.group(nodes=nodes, addr_fnc=self.p2wpkh_address)

    def group(self, nodes: List[Prv_or_PubKeyNode],
              addr_fnc: Callable[[Prv_or_PubKeyNode], str]) -> List[List[str]]:
        """
        Generates groups (path, address, sec, wif) from nodes.

        :param nodes: nodes for group generation
        :param addr_fnc: function to use for address generation
        :return: generated groups
        """
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
        """
        Generates bip44 account keys and groups (address, sec, wif)

        :param account: bip44 account number (default=0)
        :param interval: specific interval of integers
                        from which to generate children (default=(0, 20))
        :return: account keys and groups
        """
        path = Bip32Path(
            purpose=44 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip44_group(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip49(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        """
        Generates bip49 account keys and groups (address, sec, wif)

        :param account: bip44 account number (default=0)
        :param interval: specific interval of integers
                        from which to generate children (default=(0, 20))
        :return: account keys and groups
        """
        path = Bip32Path(
            purpose=49 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip49_group(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip84(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        """
        Generates bip84 account keys and group (address, sec, wif)

        :param account: bip44 account number (default=0)
        :param interval: specific interval of integers
                        from which to generate children (default=(0, 20))
        :return: account keys and groups
        """
        path = Bip32Path(
            purpose=84 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip84_group(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip85_data(self):
        """
        Produces BIP85 additional wallet secrets from deterministic entropy.

        :return: BIP85 mapping
        """
        return {
            "m/83696968'/39'/0'/24'/0'": self.bip85.bip39_mnemonic(
                word_count=24, index=0
            ),
            "m/83696968'/39'/0'/18'/0'": self.bip85.bip39_mnemonic(
                word_count=18, index=0
            ),
            "m/83696968'/39'/0'/12'/0'": self.bip85.bip39_mnemonic(
                word_count=12, index=0
            ),
            "m/83696968'/2'/0'": self.bip85.wif(index=0),
            "m/83696968'/2'/1'": self.bip85.wif(index=1),
            "m/83696968'/2'/2'": self.bip85.wif(index=2),
            "m/83696968'/32'/0'": self.bip85.xprv(index=0),
            "m/83696968'/32'/1'": self.bip85.xprv(index=1),
            "m/83696968'/32'/2'": self.bip85.xprv(index=2),
        }

    def master_data(self) -> dict:
        return {
            "mnemonic": self.mnemonic,
            "password": self.password
        }

    def generate(self, account: int = 0, interval: tuple = (0, 20)) -> dict:
        """
        Generates wallet mapping.

        :param account: bip44 account number (default=0)
        :param interval: specific interval of integers
                        from which to generate children (default=(0, 20))
        :return: wallet mapping
        """
        acct_ext44, groups44 = self.bip44(account=account, interval=interval)
        acct_ext49, groups49 = self.bip49(account=account, interval=interval)
        acct_ext84, groups84 = self.bip84(account=account, interval=interval)
        return {
            "MASTER": self.master_data(),
            "BIP85": self.bip85_data(),
            "BIP44": {"account_extended_keys": acct_ext44, "groups": groups44},
            "BIP49": {"account_extended_keys": acct_ext49, "groups": groups49},
            "BIP84": {"account_extended_keys": acct_ext84, "groups": groups84},
        }

    def json(self, data: dict = None, indent: int = None) -> str:
        """
        JSON representation of data dictionary.

        :param data: source dictionary
        :param indent: indent width
        :return: JSON string
        """
        data = data if data else self.generate()
        return json.dumps(data, indent=indent)

    def pprint(self, data: dict = None, indent: int = 4) -> None:
        """
        Emit JSON representation of data dictionary to standard output.

        :param data: source dictionary
        :param indent: indent width
        :return: None
        """
        data = data if data else self.generate()
        sys.stdout.write(self.json(data=data, indent=indent))

    @staticmethod
    def export_to_file(file_path: str, contents: str) -> None:
        """
        Export contents to file at file path.

        :param file_path: path to target file
        :param contents: contents
        :return: None
        """
        with open(file_path, "w") as f:
            f.write(contents)

    def wasabi_json(self, indent: int = None):
        """
        Wasabi wallet JSON import format.

        :param indent: indent width
        :return: JSON string
        """
        node = self.by_path("m/84'/0'/0'")
        return self.json({
            "ExtPubKey": node.extended_public_key(),
            "MasterFingerprint": self.master.fingerprint().hex().upper()
        }, indent=indent)

    def export_wasabi(self, file_path: str, indent: int = None) -> None:
        """
        Wasabi wallet JSON import format dumped to file at file path.

        :param file_path: path to target file
        :param indent: indent width
        :return: None
        """
        self.export_to_file(
            file_path=file_path,
            contents=self.wasabi_json(indent=indent)
        )



