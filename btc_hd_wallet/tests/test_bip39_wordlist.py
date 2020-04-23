import os
import unittest

from btc_hd_wallet.bip39_wordlist import get_word_list


class TestBip39WordList(unittest.TestCase):

    word_list_path = "btc_hd_wallet/bip39_wordlist/english.txt"

    def remove_word_list_file(self):
        os.remove(self.word_list_path)

    def test_download(self):
        self.remove_word_list_file()
        word_list = get_word_list()
        self.assertIsInstance(word_list, list)
        self.assertEqual(len(word_list), 2048)
        self.assertEqual(word_list[0], "abandon")
        self.assertEqual(word_list[1145], "monkey")
        self.assertEqual(word_list[2047], "zoo")
