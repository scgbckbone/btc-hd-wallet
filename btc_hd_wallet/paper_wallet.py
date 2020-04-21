import csv
from typing import List, Callable

from btc_hd_wallet.bip32_hd_wallet import Priv_or_PubKeyNode, HARDENED
from btc_hd_wallet.wallet_utils import Bip32Path
from btc_hd_wallet.base_wallet import BaseWallet


class PaperWallet(BaseWallet):

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
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip44_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip49(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        path = Bip32Path(
            purpose=49 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip49_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def bip84(self, account: int = 0, interval: tuple = (0, 20)) -> tuple:
        path = Bip32Path(
            purpose=84 + HARDENED,
            coin_type=1 + HARDENED if self.testnet else HARDENED,
            account=account + HARDENED
        )
        acct_node = self.master.derive_path(index_list=path.to_list())
        acct_ext_keys = self.node_extended_keys(node=acct_node)
        external_chain_node = acct_node.derive_path(index_list=[0])
        return acct_ext_keys, self.bip84_triad(
            nodes=external_chain_node.generate_children(interval=interval)
        )

    def generate(self, account: int = 0, interval: tuple = (0, 20)) -> dict:
        acct_ext44, triads44 = self.bip44(account=account, interval=interval)
        acct_ext49, triads49 = self.bip49(account=account, interval=interval)
        acct_ext84, triads84 = self.bip84(account=account, interval=interval)
        return {
            "bip44": {"acct_ext_keys": acct_ext44, "triads": triads44},
            "bip49": {"acct_ext_keys": acct_ext49, "triads": triads49},
            "bip84": {"acct_ext_keys": acct_ext84, "triads": triads84},
        }

    @staticmethod
    def extended_keys_to_csv_format(ext_keys: dict) -> List[List[str]]:
        return [
            [ext_keys["path"], ext_keys["prv"]],
            [ext_keys["path"].replace("m", "M"), ext_keys["pub"]]
        ]

    def export_to_csv(self, file_path: str, wallet_dict: dict = None) -> None:
        wallet_dict = wallet_dict or self.generate()
        with open(file_path, "w", newline='') as f:
            writer = csv.writer(f)
            for bip_name, bip_obj in wallet_dict.items():
                ext = self.extended_keys_to_csv_format(bip_obj["acct_ext_keys"])
                res = ext + bip_obj["triads"]
                writer.writerows(res)
                writer.writerow([])

    def pretty_print(self, wallet_dict: dict = None) -> None:
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
            for triad in bip_dct["triads"]:
                print(fmt % tuple(triad))
            print()
