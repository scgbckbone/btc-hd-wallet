import os
import unittest

from btc_hd_wallet.bip39_wordlist import get_word_list


class TestBip39WordList(unittest.TestCase):

    word_list_path = "btc_hd_wallet/bip39_wordlist/english.txt"
    word_list_bak_path = word_list_path + ".bak"

    def setUp(self) -> None:
        if os.path.exists(self.word_list_bak_path):
            os.remove(self.word_list_bak_path)
        if os.path.exists(self.word_list_path):
            os.rename(self.word_list_path, self.word_list_bak_path)

    def tearDown(self) -> None:
        if os.path.exists(self.word_list_path):
            os.remove(self.word_list_bak_path)
        else:
            os.rename(self.word_list_bak_path, self.word_list_path)

    def test_download(self):
        word_list = get_word_list()
        self.assertIsInstance(word_list, list)
        self.assertEqual(len(word_list), 2048)
        self.assertEqual(word_list[0], "abandon")
        self.assertEqual(word_list[1145], "monkey")
        self.assertEqual(word_list[2047], "zoo")
