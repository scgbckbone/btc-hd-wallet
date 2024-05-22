import base64
from btc_hd_wallet.bip32 import PrvKeyNode, InvalidKeyError
from btc_hd_wallet.wallet_utils import Bip32Path
from btc_hd_wallet.helper import hmac_sha512, big_endian_to_int
from btc_hd_wallet.keys import PrivateKey
from btc_hd_wallet.bip39 import mnemonic_from_entropy, CORRECT_MNEMONIC_LENGTH
try:
    from pysecp256k1 import ec_seckey_verify
except ImportError:
    from btc_hd_wallet.keys import CURVE_ORDER


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
    def correct_key(key_bytes: bytes) -> None:
        """
        Checks key validity. Invalid key: parse256(IL) ≥ n or is 0

        :param key: key_bytes
        :return: None
        """
        try:
            ec_seckey_verify(key_bytes)
        except NameError:
            key = big_endian_to_int(key_bytes)
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
        self.correct_key(key_bytes=entropy[:32])
        prv_key = PrivateKey(sec_exp=entropy[:32])
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
        self.correct_key(right)
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

    def pwd(self, pwd_len: int = 21, index: int = 0) -> str:
        """
        Entropy calculated log2(64 ** pwd_len)

        pwd_len, pwd_entropy
        ====================
        20       120.0
        21       126.0
        22       132.0
        23       138.0
        24       144.0
        25       150.0
        26       156.0
        27       162.0
        28       168.0
        29       174.0
        30       180.0
        31       186.0
        32       192.0
        33       198.0
        34       204.0
        35       210.0
        36       216.0
        37       222.0
        38       228.0
        39       234.0
        40       240.0
        41       246.0
        42       252.0
        43       258.0
        44       264.0
        45       270.0
        46       276.0
        47       282.0
        48       288.0
        49       294.0
        50       300.0
        51       306.0
        52       312.0
        53       318.0
        54       324.0
        55       330.0
        56       336.0
        57       342.0
        58       348.0
        59       354.0
        60       360.0
        61       366.0
        62       372.0
        63       378.0
        64       384.0
        65       390.0
        66       396.0
        67       402.0
        68       408.0
        69       414.0
        70       420.0
        71       426.0
        72       432.0
        73       438.0
        74       444.0
        75       450.0
        76       456.0
        77       462.0
        78       468.0
        79       474.0
        80       480.0
        81       486.0
        82       492.0
        83       498.0
        84       504.0
        85       510.0
        86       516.0
        """
        if not 20 <= pwd_len <= 86:
            raise ValueError("Incorrect password length specified."
                             " Has to be in closed interval <20-86>")
        path = "m/83696968'/707764'/{}'/{}'".format(pwd_len, index)
        entropy = self.entropy(path=path)
        entropy_b64 = base64.b64encode(entropy).decode().strip()
        pwd = entropy_b64[:pwd_len]
        return pwd
