from typing import Callable, Generator

from btc_hd_wallet.bip32 import (
    PrvKeyNode, PubKeyNode, Prv_or_PubKeyNode
)
from btc_hd_wallet.bip39 import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, bip39_seed_from_mnemonic,
    MNEMONIC_LENGTH_TO_ENTROPY_BITS
)
from btc_hd_wallet.helper import (
    hash160, sha256, h160_to_p2sh_address, h256_to_p2wsh_address
)
from btc_hd_wallet.wallet_utils import Bip32Path, Version, Key
from btc_hd_wallet.script import Script, p2wpkh_script, p2wsh_script
from btc_hd_wallet.bip85 import BIP85DeterministicEntropy


class BaseWallet(object):

    __slots__ = (
        "mnemonic",
        "testnet",
        "password",
        "master",
        "bip85"
    )

    def __init__(self, master: Prv_or_PubKeyNode, testnet: bool = False):
        """
        Initializes wallet object.

        :param master: master node
        :param testnet: whether this node is testnet node (default=False)
        """
        self.master = master
        self.testnet = testnet
        self.mnemonic = None
        self.password = None
        self.bip85 = BIP85DeterministicEntropy(
            master_node=self.master,
            testnet=self.testnet
        ) if not self.watch_only else None

    def __eq__(self, other: "BaseWallet") -> bool:
        """
        Checks whether two wallet objects are equal.

        :param other: other base wallet
        """
        return self.master == other.master and self.testnet == other.testnet

    @property
    def watch_only(self) -> bool:
        """
        Checks whether this wallet is watch only wallet.

        :return: whether is watch only
        """
        return type(self.master) == PubKeyNode

    @classmethod
    def new_wallet(cls, mnemonic_length: int = 24, password: str = "",
                   testnet: bool = False):
        """
        Creates new wallet.

        :param mnemonic_length: length of mnemonic sentence (default=24)
        :param password: optional passphrase (default="")
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        return cls.from_entropy_bits(
            entropy_bits=MNEMONIC_LENGTH_TO_ENTROPY_BITS[mnemonic_length],
            password=password,
            testnet=testnet
        )

    @classmethod
    def from_entropy_bits(cls, entropy_bits: int = 256, password: str = "",
                          testnet: bool = False):
        """
        Creates new wallet.

        :param entropy_bits: number of entropy bits (default=256)
        :param password: optional passphrase (default="")
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        mnemonic = mnemonic_from_entropy_bits(entropy_bits=entropy_bits)
        return cls.from_mnemonic(
            mnemonic=mnemonic,
            password=password,
            testnet=testnet
        )

    @classmethod
    def from_entropy_hex(cls, entropy_hex: str, password: str = "",
                         testnet: bool = False):
        """
        Creates new wallet from entropy hex.

        :param entropy_hex: entropy hex
        :param password: optional passphrase (default="")
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        mnemonic = mnemonic_from_entropy(entropy=entropy_hex)
        return cls.from_mnemonic(
            mnemonic=mnemonic,
            password=password,
            testnet=testnet
        )

    @classmethod
    def from_bip39_seed_hex(cls, bip39_seed: str, testnet: bool = False):
        """
        creates new wallet from bip39 seed hex.

        :param bip39_seed: bip39 seed
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        seed_bytes = bytes.fromhex(bip39_seed)
        return cls.from_bip39_seed_bytes(
            bip39_seed=seed_bytes,
            testnet=testnet
        )

    @classmethod
    def from_bip39_seed_bytes(cls, bip39_seed: bytes, testnet: bool = False):
        """
        creates new wallet from bip39 seed.

        :param bip39_seed: bip39 seed
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        return cls(
            master=PrvKeyNode.master_key(
                bip39_seed=bip39_seed,
                testnet=testnet
            ),
            testnet=testnet
        )

    @classmethod
    def from_mnemonic(cls, mnemonic: str, password: str = "",
                      testnet: bool = False) -> "BaseWallet":
        """
        Creates new wallet from mnemonic sentence.

        :param mnemonic: mnemonic sentence
        :param password: optional passphrase (default="")
        :param testnet: whether this node is testnet node (default=False)
        :return: wallet
        """
        bip39_seed = bip39_seed_from_mnemonic(
            mnemonic=mnemonic,
            password=password
        )
        wallet = cls.from_bip39_seed_bytes(
            bip39_seed=bip39_seed,
            testnet=testnet
        )
        wallet.mnemonic = mnemonic
        wallet.password = password
        return wallet

    @classmethod
    def from_extended_key(cls, extended_key: str) -> "BaseWallet":
        """
        Creates new wallet from extended key.

        :param extended_key: extended public or private key
        :return: wallet
        """
        # just need version, key type does not matter in here
        version_int = PrvKeyNode.parse(s=extended_key).parsed_version
        version = Version.parse(version_int=version_int)
        if version.key_type == Key.PRV:
            node = PrvKeyNode.parse(extended_key, testnet=version.testnet)
        else:
            # is this just assuming? or really pub if not priv
            node = PubKeyNode.parse(extended_key, testnet=version.testnet)
        return cls(testnet=version.testnet, master=node)

    def determine_node_version_int(self,
                                   node: Prv_or_PubKeyNode,
                                   key_type: Key) -> Version:
        """
        Determines node version.

        :param node: key node
        :param key_type: type of key private/public
        :return: version object
        """
        bip = Bip32Path.parse(str(node))
        version = Version(
            key_type=key_type.value,
            testnet=self.testnet,
            bip=bip.bip()
        )
        return version

    def node_extended_public_key(self, node: Prv_or_PubKeyNode) -> str:
        """
        Gets node's extended public key.

        :param node: key node
        :return: extended public key
        """
        version = self.determine_node_version_int(node=node, key_type=Key.PUB)
        return node.extended_public_key(version=int(version))

    def node_extended_private_key(self, node: Prv_or_PubKeyNode) -> str:
        """
        Gets node's extended private key.

        :param node: key node
        :return: extended private key
        """
        if type(node) == PubKeyNode:
            raise ValueError("wallet is watch only")
        version = self.determine_node_version_int(node=node, key_type=Key.PRV)
        return node.extended_private_key(version=int(version))

    def node_extended_keys(self, node: Prv_or_PubKeyNode) -> dict:
        """
        Gets node's extended keys.

        :param node: key node
        :return: extended keys mapping
        """
        prv = None if self.watch_only else self.node_extended_private_key(
            node=node
        )
        return {
            "path": str(node),
            "pub": self.node_extended_public_key(node=node),
            "prv": prv
        }

    def p2pkh_address(self, node: Prv_or_PubKeyNode) -> str:
        """
        Generates p2pkh address from node.

        :param node: key node
        :return: p2pkh address
        """
        return node.public_key.address(testnet=self.testnet, addr_type="p2pkh")

    def p2wpkh_address(self, node: Prv_or_PubKeyNode) -> str:
        """
        Generates p2wpkh address from node.

        :param node: key node
        :return: p2wpkh address
        """
        return node.public_key.address(testnet=self.testnet, addr_type="p2wpkh")

    def p2sh_p2wpkh_address(self, node: Prv_or_PubKeyNode) -> str:
        """
        Generates p2wpkh wrapped in p2sh address from node.

        :param node: key node
        :return: p2sh-p2wpkh address
        """
        return h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script(h160=node.public_key.h160()).raw_serialize()
            ),
            testnet=self.testnet
        )

    def p2wsh_address(self, node: Prv_or_PubKeyNode) -> str:
        """
        Generates p2wsh address from node.

        :param node: key node
        :return: p2wsh address
        """
        # TODO remove one of 1of1 multisig and provide rather simple
        # TODO singlesig script
        # TODO [sec, OP_CHECKSIG]
        # TODO witness_script = Script([node.public_key.sec(), 0xac])
        # [OP_1, sec, OP_1, OP_CHECKMULTISIG]
        witness_script = Script([0x51, node.public_key.sec(), 0x51, 0xae])
        sha256_witness_script = sha256(witness_script.raw_serialize())
        return h256_to_p2wsh_address(
            h256=sha256_witness_script,
            testnet=self.testnet
        )

    def p2sh_p2wsh_address(self, node: Prv_or_PubKeyNode) -> str:
        """
        Generates p2wsh wrapped in p2sh address from node.

        :param node: key node
        :return: p2sh-p2wsh address
        """
        # [OP_1, sec, OP_1, OP_CHECKMULTISIG]
        witness_script = Script([0x51, node.public_key.sec(), 0x51, 0xae])
        sha256_witness_script = sha256(witness_script.raw_serialize())
        redeem_script = p2wsh_script(h256=sha256_witness_script).raw_serialize()
        return h160_to_p2sh_address(
            h160=hash160(redeem_script),
            testnet=self.testnet
        )

    def address_generator(self, node: Prv_or_PubKeyNode,
                          addr_fnc: Callable[[Prv_or_PubKeyNode], str] = None
                          ) -> Generator[str, int, None]:
        """
        Address generator.

        :param node: key node
        :param addr_fnc: function to use for address generation
                            (default=self.p2wpkh_address)
        :return: address generator
        """
        index = 0
        addr_fnc = addr_fnc or self.p2wpkh_address
        while True:
            child = node.ckd(index=index)
            adder = yield str(child), addr_fnc(child)
            index += adder or 1

    def by_path(self, path: str) -> Prv_or_PubKeyNode:
        """
        Generate child node from master node by path.

        :param path: bip32 path
        :return: child node
        """
        path = Bip32Path.parse(s=path)
        return self.master.derive_path(index_list=path.to_list())
