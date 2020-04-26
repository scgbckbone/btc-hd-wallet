import re
import random
import hashlib
import unicodedata

from btc_hd_wallet.bip39_wordlist import word_list
from btc_hd_wallet.helper import big_endian_to_int, int_to_big_endian, sha256


random = random.SystemRandom()
CORRECT_ENTROPY_BITS = [128, 160, 192, 224, 256]
PBKDF2_ROUNDS = 2048


def correct_entropy_bits_value(entropy_bits: int) -> None:
    """
    Checks if correct value for entropy bits argument is provided. Otherwise
    Value error is thrown.

    :param entropy_bits: number of entropy bits
    :type entropy_bits: int
    :return: nothing
    :rtype: None
    """
    if entropy_bits not in CORRECT_ENTROPY_BITS:
        raise ValueError("incorrect entropy bits")


def checksum_length(entropy_bits: int) -> int:
    """
    Calculates length of checksum based on entropy bits.

    :param entropy_bits: number of entropy bits
    :type entropy_bits: int
    :return: checksum length
    :rtype: int
    """
    return int(entropy_bits / 32)


def mnemonic_sentence_length(entropy_bits: int) -> int:
    """
    Calculates length of mnemonic sentence based on entropy bits.

    :param entropy_bits: number of entropy bits
    :type entropy_bits: int
    :return: mnemonic sentence length
    :rtype: int
    """
    return int((entropy_bits + checksum_length(entropy_bits)) / 11)


def mnemonic_from_entropy_bits(entropy_bits: int = 256) -> str:
    """
    Generate mnemonic sentence from random bits.

    :param entropy_bits: number of entropy bits (default=256)
    :type entropy_bits: int
    :return: mnemonic sentence
    :rtype: str
    """
    correct_entropy_bits_value(entropy_bits=entropy_bits)
    entropy_int = random.getrandbits(entropy_bits)
    entropy_bytes = int_to_big_endian(entropy_int, int(entropy_bits / 8))
    return mnemonic_from_entropy(entropy_bytes.hex())


def mnemonic_from_entropy(entropy: str) -> str:
    """
    Generates mnemonic sentence from entropy hex.

    :param entropy: entropy hex
    :type entropy: str
    :return: mnemonic sentence
    :rtype: str
    """
    entropy_bits = len(entropy) * 4
    entropy_bytes = bytes.fromhex(entropy)
    entropy_int = big_endian_to_int(entropy_bytes)
    sha256_entropy_bytes = sha256(entropy_bytes)
    sha256_entropy_int = big_endian_to_int(sha256_entropy_bytes)
    checksum_bit_length = checksum_length(entropy_bits=entropy_bits)
    checksum = bin(sha256_entropy_int)[2:].zfill(256)[:checksum_bit_length]
    entropy_checksum = bin(entropy_int)[2:] + checksum
    entropy_checksum = entropy_checksum.zfill(
        entropy_bits + checksum_bit_length
    )
    bin_indexes = re.findall("." * 11, entropy_checksum)
    indexes = [int(index, 2) for index in bin_indexes]
    mnemonic_lst = [word_list[index] for index in indexes]
    mnemonic_sentence = " ".join(mnemonic_lst)
    return mnemonic_sentence


def bip39_seed_from_mnemonic(mnemonic: str, password: str = "") -> bytes:
    """
    Generates bip39 seed from mnemonic (and optional password).

    :param mnemonic: mnemonic sentence
    :type mnemonic: str
    :param password: password (default="")
    :return: bip39 seed
    :rtype: bytes
    """
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    password = unicodedata.normalize("NFKD", password)
    passphrase = unicodedata.normalize("NFKD", "mnemonic") + password
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        passphrase.encode("utf-8"),
        PBKDF2_ROUNDS
    )
    return seed
