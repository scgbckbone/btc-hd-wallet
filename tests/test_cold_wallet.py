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
        wallet = self.cold_wallet.bip44()
        csv_f = self.load_csv_file(
            _file="data/bip44_vast_tell_razor_drip_stick_one_engine"
        )
        self.assertEqual(len(wallet), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])

    def test_bip49(self):
        wallet = self.cold_wallet.bip49()
        csv_f = self.load_csv_file(
            _file="data/bip49_vast_tell_razor_drip_stick_one_engine"
        )
        self.assertEqual(len(wallet), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])

    def test_bip84(self):
        wallet = self.cold_wallet.bip84()
        csv_f = self.load_csv_file(
            _file="data/bip84_vast_tell_razor_drip_stick_one_engine"
        )
        self.assertEqual(len(wallet), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])

    def test_bip44_testnet(self):
        m44h1h0h0 = "tprv8htjzxdtooRZnSeSzKZX1s1Ln4VxCpawvMXhiHsHy7knBtRvty8YLkzuUqoRKQa8kngdtyUNYhEdE5wtywK45XDn1QXcWJ4sZRviQTVbgJP"
        # node_m44h1h0h0 = self.cold_wallet_testnet.by_path(path="m/44'/1'/0'/0")
        # self.assertEqual(node_m44h1h0h0.extended_private_key(), m44h1h0h0)
        wallet = self.cold_wallet_testnet.bip44()
        csv_f = self.load_csv_file(
            _file="data/bip44_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = ColdWallet.from_extended_key(extended_key=m44h1h0h0)
        wallet0 = wallet0._bip44(children=wallet0.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])

    def test_bip49_testnet(self):
        wallet = self.cold_wallet_testnet.bip49()
        csv_f = self.load_csv_file(
            _file="data/bip49_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        self.assertEqual(len(wallet), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])

    def test_bip84_testnet(self):
        wallet = self.cold_wallet_testnet.bip84()
        csv_f = self.load_csv_file(
            _file="data/bip84_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        self.assertEqual(len(wallet), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])

