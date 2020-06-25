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
            raise RuntimeError(
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

    def bip39_mnemonic(self, path: str) -> str:
        """
        Create BIP39 mnemonic sentence from deterministic entropy
        specified by path.

        :param path: path to child node
        :return: mnemonic sentence
        """
        entropy = self.entropy(path=path)
        word_count = int(path.split("/")[4][:-1])
        width = self.byte_count_from_word_count(word_count=word_count)
        return mnemonic_from_entropy(entropy=entropy[:width].hex())

    def wif(self, path: str) -> str:
        """
        Create WIF private key from deterministic entropy
        specified by path.

        :param path: path to child node
        :return: WIF private key
        """
        entropy = self.entropy(path=path)
        key_int = big_endian_to_int(entropy[:32])
        self.correct_key(key=key_int)
        prv_key = PrivateKey(sec_exp=key_int)
        return prv_key.wif()

    def xprv(self, path: str) -> str:
        """
        Create extended private key from deterministic entropy
        specified by path.

        :param path: path to child node
        :return: extended private key (XPRV)
        """
        entropy = self.entropy(path=path)
        left, right = entropy[:32], entropy[32:]
        self.correct_key(big_endian_to_int(right))
        prv_node = PrvKeyNode(key=right, chain_code=left)
        return prv_node.extended_private_key()

    def hex(self, path: str) -> str:
        """
        Create hex private key from deterministic entropy
        specified by path.

        :param path: path to child node
        :return: hex
        """
        entropy = self.entropy(path=path)
        num_bytes = int(path.split("/")[3][:-1])
        if not 16 <= num_bytes <= 64:
            raise RuntimeError("Incorrect number of bytes specified."
                               " Has to be in closed interval <16-64>")
        return entropy[:num_bytes].hex()




