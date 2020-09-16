import unittest
from io import StringIO
from unittest.mock import patch
from argparse import Namespace, ArgumentParser

from btc_hd_wallet.__main__ import parse_args, paranoia_mode
from btc_hd_wallet.bip39 import CORRECT_ENTROPY_BITS, CORRECT_MNEMONIC_LENGTH
from btc_hd_wallet.paper_wallet import PaperWallet


class TestArgumentParsing(unittest.TestCase):

    def test_parser(self):
        expected = Namespace(
            file="wallet.json",
            testnet=True,
            paranoia=True,
            account=1100,
            interval=[0, 150],
            command="new",
            password="secret_bip39_password",
            mnemonic_len=12
        )
        parser, ns_obj = parse_args([
            "--file", "wallet.json",
            "--testnet", "--paranoia",
            "--account", "1100",
            "--interval", "0", "150",
            "new",
            "--password", "secret_bip39_password",
            "--mnemonic-len", "12"
        ])
        self.assertIsInstance(parser, ArgumentParser)
        self.assertEqual(ns_obj, expected)

        expected = Namespace(
            file=None,
            testnet=False,
            paranoia=False,
            account=0,
            interval=[0, 20],
            command="new",
            password="",
            mnemonic_len=24
        )
        parser, ns_obj = parse_args(["new"])
        self.assertIsInstance(parser, ArgumentParser)
        self.assertEqual(ns_obj, expected)

    def test_valid_mnemonic(self):
        for mnemonic in [
            "smart cherry rail elder minor audit prison sadness alter share duck park",
            "accident bag atom detect barely only scheme relief usual city taste health elder mask coil",
            "domain auction wool cloud era thrive vivid vital outdoor brass tilt domain fossil produce kidney virtual skill truly",
            "depend sight forest novel cargo version wave fragile across saddle robot blush mouse theme elephant grass ladder height violin tattoo marriage",
            "wait turn enough worth gasp close chest mobile syrup trend safe maximum lamp liberty cross myself embark engage moral brief student waste medal celery",
        ]:
            _, ns_obj = parse_args(["from-mnemonic", mnemonic])
            self.assertEqual(ns_obj.mnemonic, mnemonic)

    def test_valid_bip39_seed(self):
        valid_bip39_seed = "50078fb4145d0e18c75c8d3b9506c8893656743246b755a0cef67771c4bf3653b40af3b88a4207726196f345917887d6cb1a67964a722f41d36ed153a511894d"
        _, ns_obj = parse_args(["from-bip39-seed", valid_bip39_seed])
        self.assertEqual(ns_obj.seed_hex, valid_bip39_seed)

    def test_valid_entropy_lengths(self):
        for ent_bit_length in CORRECT_ENTROPY_BITS:
            dummy_hex = int(ent_bit_length / 4) * "a"
            _, ns_obj = parse_args(["from-entropy-hex", dummy_hex])
            self.assertEqual(ns_obj.entropy_hex, dummy_hex)

    def test_valid_mnemonic_length(self):
        for mnemonic_len in CORRECT_MNEMONIC_LENGTH:
            _, ns_obj = parse_args(["new", "--mnemonic-len", str(mnemonic_len)])
            self.assertEqual(ns_obj.mnemonic_len, mnemonic_len)

    def test_valid_master_xprv(self):
        master_xprv = "xprv9s21ZrQH143K3U7uugCebovaDpB2s5mLC1F1vuwUQryJeoWez4QFB8xhxrSvtxAQaNAjjqB9ohW9u9LTYJsA1bBVF62JfoVN6PB3dqaEEZ1"
        _, ns_obj = parse_args(["from-master-xprv", master_xprv])
        self.assertEqual(ns_obj.master_xprv, master_xprv)

    @patch('sys.stderr', new_callable=StringIO)
    def test_required_args_not_provided(self, mock_stderr):
        for cmd, err_msg in (
            ("from-master-xprv", r"required: master_xprv"),
            ("from-mnemonic", r"required: mnemonic"),
            ("from-bip39-seed", r"required: seed_hex"),
            ("from-entropy-hex", r"required: entropy_hex"),
        ):
            with self.assertRaises(SystemExit):
                parse_args([cmd])
            self.assertRegexpMatches(
                mock_stderr.getvalue(), err_msg
            )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_mnemonic_length(self, mock_stderr):
        with self.assertRaises(SystemExit):
            parse_args(["new", "--mnemonic-len", "25"])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"invalid choice")

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_account_index(self,  mock_stderr):
        with self.assertRaises(SystemExit):
            parse_args(["--account", "-1", "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"Account index has to be between 0 inclusive and 2147483647"
        )

        with self.assertRaises(SystemExit):
            parse_args(["--account", "2147483647", "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"Account index has to be between 0 inclusive and 2147483647"
        )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_address_index(self,  mock_stderr):
        with self.assertRaises(SystemExit):
            parse_args(["--interval", "-1", "100", "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"Address index has to be between 0 inclusive and 4294967295"
        )

        with self.assertRaises(SystemExit):
            parse_args(["--interval", "4294967290", "4294967295", "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"Address index has to be between 0 inclusive and 4294967295"
        )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_extended_key(self, mock_stderr):
        invalid_xprv = "xprv9yg2hgdKSVridAPC7kYvC3nYXZZoSMfLnQHFrsmKiC4m9ywrLS59suprG9CiMmtna6up5RKXou8rALdaDxvkjxJ2wrXGCpN3U5Lujx5JyPj00"
        with self.assertRaises(SystemExit):
            parse_args(["from-master-xprv", invalid_xprv])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"Extended key has to be 111 characters long"
        )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_bip39_seed(self, mock_stderr):
        invalid_bip39_seed_values = [
            "0e375829f511f9671c1e3127f838e88cebcde8dc2ddf88c87afac9738b7456c9977918cfa35020755f9b8f9f051aad2deef3cadabb0d8a3746784bc51f76e7e5ff",
            "0e375829f511f9671c1e3127f838e88cebcde8dc2ddf88c87afac9738b7456c9977918cfa35020755f9b8f9f051aad2deef3cadabb",
            "9738b7456c9977918cfa3502"
        ]
        for invalid_bip39_seed in invalid_bip39_seed_values:
            with self.assertRaises(SystemExit):
                parse_args(["from-bip39-seed", invalid_bip39_seed])
            self.assertRegexpMatches(
                mock_stderr.getvalue(),
                r"BIP39 seed has to be 64 bytes long - 128 characters"
            )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_entropy_hex(self, mock_stderr):
        invalid_entropy_values = [
            "b469f65def45c7224f0011af7023349f332b76a089f27d865a9e268cbc665",
            "1af7023349f332b76a089f27d8",
            "45c7224f0011af7023"
        ]
        for invalid_entropy_hex in invalid_entropy_values:
            with self.assertRaises(SystemExit):
                parse_args(["from-entropy-hex", invalid_entropy_hex])
            self.assertRegexpMatches(
                mock_stderr.getvalue(),
                r"Entropy hex has to have one of "
                r"128, 160, 192, 224, 256 bit lengths"
            )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_mnemonic(self, mock_stderr):
        invalid_mnemonic_values = [
            "elephant wrong ship tray tennis mirror blood chief define taste long",
            "table power gown butter label outer kingdom hobby fee clean domain envelope sick glove",
            "menu lift speak mansion game elder vapor answer nuclear girl pluck hand tool soda surge member cancel",
            "uniform razor scheme pluck march weather tip entry shadow team diagram usual inside cream sadness unhappy nothing gesture minimum shuffle",
            "rocket village shiver scissors buddy lazy combine sail maid gown surround skull index ramp wait brisk olympic possible bitter reform member program boat",
            "rocket village shiver scissors buddy lazy combine sail maid gown surround skull index ramp wait brisk olympic possible bitter reform member program boat between reform"
        ]
        for invalid_mnemonic in invalid_mnemonic_values:
            with self.assertRaises(SystemExit):
                parse_args(["from-mnemonic", invalid_mnemonic])
            self.assertRegexpMatches(
                mock_stderr.getvalue(),
                r"Mnemonic sentence length has to be one of 12, 15, 18, 21, 24"
            )

    @patch('sys.stderr', new_callable=StringIO)
    def test_invalid_file_argument(self, mock_stderr):
        non_writable_path = "/etc/more"
        with self.assertRaises(SystemExit):
            parse_args(["--file", non_writable_path, "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"not writable"
        )
        directory_path = "/"
        with self.assertRaises(SystemExit):
            parse_args(["--file", directory_path, "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"is directory"
        )
        existing_file = "tests/test_parser.py"
        with self.assertRaises(SystemExit):
            parse_args(["--file", existing_file, "new"])
        self.assertRegexpMatches(
            mock_stderr.getvalue(),
            r"already exists"
        )

    def test_paranoia_mode(self):
        w = PaperWallet.new_wallet()
        data = w.generate()
        self.assertTrue("MASTER" in data)
        self.assertTrue("BIP85" in data)
        for bip in ["BIP44", "BIP49", "BIP84"]:
            self.assertTrue("prv" in data[bip]["account_extended_keys"])
            for group in data[bip]["groups"]:
                self.assertEqual(len(group), 4)

        data = paranoia_mode(data=data)
        self.assertFalse("MASTER" in data)
        self.assertFalse("BIP85" in data)
        for bip in ["BIP44", "BIP49", "BIP84"]:
            self.assertFalse("prv" in data[bip]["account_extended_keys"])
            for group in data[bip]["groups"]:
                self.assertEqual(len(group), 3)
