import csv
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
            "bip44": {"acct_ext_keys": acct_ext44, "groups": groups44},
            "bip49": {"acct_ext_keys": acct_ext49, "groups": groups49},
            "bip84": {"acct_ext_keys": acct_ext84, "groups": groups84},
        }

    @staticmethod
    def extended_keys_to_csv_format(ext_keys: dict) -> List[List[str]]:
        """
        Convert extended keys mapping to csv exportable format.

        :param ext_keys: extended keys mapping
        :return: extended keys in csv exportable format
        """
        return [
            [ext_keys["path"], ext_keys["prv"]],
            [ext_keys["path"].replace("m", "M"), ext_keys["pub"]]
        ]

    def export_to_csv(self, file_path: str, wallet_dict: dict = None) -> None:
        """
        Exports wallet to file in csv format.

        :param file_path: path to file that will be created
        :param wallet_dict: wallet mapping (default=self.generate)
        :return: None
        """
        wallet_dict = wallet_dict or self.generate()
        with open(file_path, "w", newline='') as f:
            writer = csv.writer(f)
            for bip_name, bip_obj in wallet_dict.items():
                ext = self.extended_keys_to_csv_format(bip_obj["acct_ext_keys"])
                res = ext + bip_obj["groups"]
                writer.writerows(res)
                writer.writerow([])

    def pretty_print(self, wallet_dict: dict = None) -> None:
        """
        Prints wallet to the console.

        :param wallet_dict: wallet mapping (default=self.generate)
        :return: None
        """
        fmt = "%19s %34s %68s %54s"
        wallet_dict = wallet_dict or self.generate()
        for bip_name, bip_dct in wallet_dict.items():
            ext_keys = self.extended_keys_to_csv_format(bip_dct["acct_ext_keys"])
            print(bip_name.upper())
            print("\taccount extended keys:")
            print("\t\t{},{}".format(ext_keys[0][0], ext_keys[0][1]))
            print("\t\t{},{}".format(ext_keys[1][0], ext_keys[1][1]))
            print()
            print(fmt % ("bip32_path", "address",
                         "public_key(sec)", "private_key(wif)"))
            for group in bip_dct["groups"]:
                print(fmt % tuple(group))
            print()
