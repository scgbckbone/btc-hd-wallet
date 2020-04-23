import os
import requests
from typing import List


WORD_LIST_FILE_PATH = "btc_hd_wallet/bip39_wordlist/english.txt"
URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"


def save_word_list(word_lst):
    with open(WORD_LIST_FILE_PATH, "w") as f:
        f.write(word_lst)


def local_get_word_list() -> List[str]:
    with open(WORD_LIST_FILE_PATH, "r") as f:
        res = f.read().split()
    return res


def net_get_word_list() -> List[str]:
    resp = requests.get(URL)
    resp.raise_for_status()
    word_lst = resp.text
    save_word_list(word_lst=word_lst)
    return word_lst.split()


def get_word_list() -> List[str]:
    if os.path.isfile(WORD_LIST_FILE_PATH):
        return local_get_word_list()
    return net_get_word_list()


word_list = get_word_list()
