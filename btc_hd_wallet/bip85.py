import base64

from btc_hd_wallet.bip32 import PrvKeyNode, InvalidKeyError, CURVE_ORDER
from btc_hd_wallet.wallet_utils import Bip32Path
from btc_hd_wallet.helper import hmac_sha512, big_endian_to_int
from btc_hd_wallet.keys import PrivateKey
from btc_hd_wallet.bip39 import mnemonic_from_entropy, CORRECT_MNEMONIC_LENGTH


class BIP85DeterministicEntropy(object):

    KEY = b"bip-entropy-from-k"

    def __init__(self, master_node: PrvKeyNode, testnet=False):
        self.master_node = master_node
        self.testnet = testnet

    def __eq__(self, other: "BIP85DeterministicEntropy") -> bool:
        """
        Checks whether two deterministic entropy objects are equal.

        :param other: another deterministic entropy object
        """
        return self.master_node == other.master_node and \
            self.testnet == other.testnet

    @classmethod
    def from_xprv(cls, xprv: str, testnet=False) -> "BIP85DeterministicEntropy":
        """
        Creates new deterministic entropy object from extended private key.

        :param xprv: extended private key
        :param testnet: is testnet? (default=False)
        :return: deterministic entropy object
        """
        return cls(
            master_node=PrvKeyNode.parse(s=xprv, testnet=testnet),
            testnet=testnet
        )

    def _hmac_sha512(self, msg: bytes) -> bytes:
        """
        Hash-based message authentication code with sha512
        with hardcoded secret key 'bip-entropy-from-k'.

        :param msg: message
        :return: digest bytes
        """
        return hmac_sha512(key=self.KEY, msg=msg)

    def entropy(self, path: str) -> bytes:
        """
        Generates 512 bits of entropy from child specified by path.

        :param path: path to child node
        :return: 64 bytes of entropy
        """
        path = Bip32Path.parse(path)
        node = self.master_node.derive_path(index_list=path.to_list())
        return self._hmac_sha512(msg=bytes(node.private_key))

    @staticmethod
    def byte_count_from_word_count(word_count: int) -> int:
        """
        Determines correct byte length from mnemonic word count.

        :param word_count: mnemonic word count
        :return: correct byte length
        """
        if word_count not in CORRECT_MNEMONIC_LENGTH:
            raise ValueError(
                "Incorrect word count! Allowed {}".format(
                    CORRECT_MNEMONIC_LENGTH
                )
            )
        return (word_count - 1) * 11 // 8 + 1

    @staticmethod
    def correct_key(key: int) -> None:
        """
        Checks key validity. Invalid key: parse256(IL) ≥ n or is 0

        :param key: secret exponent
        :return: None
        """
        if key == 0:
            raise InvalidKeyError("key is zero")
        if key >= CURVE_ORDER:
            raise InvalidKeyError(
                "key {} is greater/equal to curve order".format(
                    key
                )
            )

    def bip39_mnemonic(self, word_count: int = 24, index: int = 0) -> str:
        """
        Create BIP39 mnemonic sentence of length word count
        from deterministic entropy specified by path.

        :param word_count: desired number of words in mnemonic (default=24)
        :param index: derivation index (default=0)
        :return: mnemonic sentence
        """
        # for now (and maybe forever) only supported language is english
        path = "m/83696968'/39'/0'/{}'/{}'".format(word_count, index)
        entropy = self.entropy(path=path)
        width = self.byte_count_from_word_count(word_count=word_count)
        return mnemonic_from_entropy(entropy=entropy[:width].hex())

    def wif(self, index: int = 0) -> str:
        """
        Create WIF private key from deterministic entropy
        specified by path.

        :param index: derivation index (default=0)
        :return: WIF private key
        """
        path = "m/83696968'/2'/{}'".format(index)
        entropy = self.entropy(path=path)
        key_int = big_endian_to_int(entropy[:32])
        self.correct_key(key=key_int)
        prv_key = PrivateKey(sec_exp=key_int)
        return prv_key.wif()

    def xprv(self, index: int = 0) -> str:
        """
        Create extended private key from deterministic entropy
        specified by path.

        :param index: derivation index (default=0)
        :return: extended private key (XPRV)
        """
        path = "m/83696968'/32'/{}'".format(index)
        entropy = self.entropy(path=path)
        left, right = entropy[:32], entropy[32:]
        self.correct_key(big_endian_to_int(right))
        prv_node = PrvKeyNode(key=right, chain_code=left)
        return prv_node.extended_private_key()

    def hex(self, num_bytes: int = 32, index: int = 0) -> str:
        """
        Create hex private key of byte length num bytes
        from deterministic entropy specified by path.

        :param num_bytes: desired number of bytes (default=32)
        :param index: derivation index (default=0)
        :return: hex
        """
        if not 16 <= num_bytes <= 64:
            raise ValueError("Incorrect number of bytes specified."
                             " Has to be in closed interval <16-64>")
        path = "m/83696968'/128169'/{}'/{}'".format(num_bytes, index)
        entropy = self.entropy(path=path)
        return entropy[:num_bytes].hex()

    def pwd(self, num_bytes: int = 17, index: int = 0) -> str:
        if not 16 <= num_bytes <= 64:
            raise ValueError("Incorrect number of bytes specified."
                             " Has to be in closed interval <16-64>")
        path = "m/83696968'/707764'/{}'/{}'".format(num_bytes, index)
        entropy = self.entropy(path=path)
        return base64.b64encode(entropy[:num_bytes]).decode().strip()