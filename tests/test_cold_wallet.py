import csv
import unittest
from cold_wallet import ColdWallet


class TestColdWallet(unittest.TestCase):
    mnemonic = (
        "vast tell razor drip stick one engine action "
        "width sport else try scare phone blouse view "
        "program ketchup pole rapid use length student raven"
    )
    cold_wallet = ColdWallet(mnemonic=mnemonic)
    cold_wallet_testnet = ColdWallet(mnemonic=mnemonic, testnet=True)

    @staticmethod
    def load_csv_file(_file):
        with open(_file, "r") as f:
            csv_f = list(csv.reader(f, delimiter=','))
        return csv_f

    def test_from_mnemonic(self):
        cw = ColdWallet(entropy="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd")
        self.assertEqual(cw, self.cold_wallet)
        cw = ColdWallet(entropy="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd", testnet=True)
        self.assertEqual(cw, self.cold_wallet_testnet)

    def test_bip44(self):
        m44h0h0h0 = "xprvA1mabSEXaAzXuw9xhUB3J4p82KpeQoaYWWv7S2ZMiYc9oLUq3mSCe6pPxT1nhh1LAtx9Zb7vAk3Bx6ChXAwtZf32g7dWPGxLiSd3KyVGv4D"
        M44h0h0h0 = "xpub6EkvzwmRQYYq8RERoVi3fCkraMf8pGJPsjqiEQxyGt98g8oybJkTBu8soiUJM76gtQtGx1ZKU7y6CwbVFeCER3q95MVbNRquYCfyPLzbdpF"
        wallet = self.cold_wallet.bip44()
        csv_f = self.load_csv_file(
            _file="tests/data/bip44_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m44h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip44(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M44h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip44(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            # paths differ -> as imported key is treated as root
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            # private key - last element in the list - is None --> watch only
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip49(self):
        m49h0h0h0 = "yprvAKVruDeCuwumJdxruoUR3f8jQhqumzuQiF7oZknYNEZbFSzYweJFJ2oSfKLj2MNvhr5xzK2iiyQyLjtrLXUVRvVAKQbW197f48rFtHTQi29"
        M49h0h0h0 = "ypub6YVDJjB6kKU4X83L1q1RQo5TxjgQBTdG5U3QN9C9va6a8FKhVBcVqq7vWayS3iDNdKj9siFtDuhjJ9KJatTFjtiZ9HLEbhYBeRz7TsKmmz1"
        wallet = self.cold_wallet.bip49()
        csv_f = self.load_csv_file(
            _file="tests/data/bip49_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m49h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip49(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M49h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip49(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip84(self):
        m84h0h0h0 = "zprvAeUnGUuaxCMJRxeYeKBtSABd2VcK7QNVxzETexpoAr9htSeXgGDcd6ooD7umSXuvSCuFSp3NM82x26da1Sh72tBi3FiEc4HMmpkoJd423DF"
        M84h0h0h0 = "zpub6sU8fzSUnZubeSj1kLitoJ8MaXSoWs6MLDA4TMEQjBggmEygDoXsAu8H4Qk5mvh4qL6QCi97z7EmAytC7CZe1q2Z6HnMje2ibgEctsit7zV"
        wallet = self.cold_wallet.bip84()
        csv_f = self.load_csv_file(
            _file="tests/data/bip84_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m84h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip84(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M84h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip84(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip44_testnet(self):
        m44h1h0h0 = "tprv8htjzxdtooRZnSeSzKZX1s1Ln4VxCpawvMXhiHsHy7knBtRvty8YLkzuUqoRKQa8kngdtyUNYhEdE5wtywK45XDn1QXcWJ4sZRviQTVbgJP"
        M44h1h0h0 = "tpubDEan9Ng8xB7EfugEsyE7RGfTM61tN9mrVf8UzoubPPZB2NghXMx8XFcmexNZRUCQ5iZXMbYGtJAbgKW8rpcrSvscgFv1cJxqixRrkdjufFV"
        node_m44h1h0h0 = self.cold_wallet_testnet.by_path(path="m/44'/1'/0'/0")
        self.assertEqual(node_m44h1h0h0.extended_private_key(), m44h1h0h0)
        self.assertEqual(node_m44h1h0h0.extended_public_key(), M44h1h0h0)
        wallet = self.cold_wallet_testnet.bip44()
        csv_f = self.load_csv_file(
            _file="tests/data/bip44_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m44h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip44(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M44h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip44(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            # paths differ -> as imported key is treated as root
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            # private key - last element in the list - is None --> watch only
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip49_testnet(self):
        m49h1h0h0 = "uprv92pZMtfPEtUTs1XYUGr3HATLzbz5GT6Ta9ikE7PcsUKaRaGEVDJLXSRjfVwwh2TooCEYsFFtXEan9reH7hwXFokaLLir5fEp1Ju6e1zW5mg"
        M49h1h0h0 = "upub5FoumQCH5G2m5Vc1aJP3eJQ5YdpZfupJwNeM2VoERorZJNbP2kcb5EkDWor7CCFSnmYhXGu47xRfhxZ1dBc9H3ssrCMaJpdNzSkk2X8Kz6m"
        wallet = self.cold_wallet_testnet.bip49()
        csv_f = self.load_csv_file(
            _file="tests/data/bip49_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m49h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip49(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M49h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip49(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip84_testnet(self):
        m84h1h0h0 = "vprv9N1iPx69wSwyn7tHjf3E5e7fGyXGBst9ZHe96k8UnPJtVLyNyaFkNptLAYf8UST9nWT8T42p3ogH7YBGD69PvggXib3wnLCpS6h1eFZMFDD"
        M84h1h0h0 = "vpub5b14oTd3mpWGzbxkqgaESn4Pq1MkbLbzvWZju8Y6LiqsN9JXX7ZzvdCp1qDDxLqeHGr6BUssz2yFmUDm5Fp9jTdz4madyxK6mwgsCvYdK5S"
        wallet = self.cold_wallet_testnet.bip84()
        csv_f = self.load_csv_file(
            _file="tests/data/bip84_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m84h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip84(children=wallet0.master.generate_children())

        wallet1 = ColdWallet.from_extended_key(extended_key=M84h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip84(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

