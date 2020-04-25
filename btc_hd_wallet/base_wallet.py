from typing import Callable, Generator

from btc_hd_wallet.bip32 import (
    PrivKeyNode, PubKeyNode, Priv_or_PubKeyNode
)
from btc_hd_wallet.bip39 import (
    mnemonic_from_entropy, mnemonic_from_entropy_bits, bip39_seed_from_mnemonic
)
from btc_hd_wallet.helper import (
    hash160, sha256, h160_to_p2sh_address, h256_to_p2wsh_address
)
from btc_hd_wallet.wallet_utils import Bip32Path, Version, Key
from btc_hd_wallet.script import Script, p2wpkh_script, p2wsh_script


class BaseWallet(object):

    __slots__ = (
        "mnemonic",
        "testnet",
        "password",
        "master"
    )

    def __init__(self, master: Priv_or_PubKeyNode, testnet: bool = False):
        """
        Initializes wallet object.

        :param master: master node
        :type master: Union[PrivKeyNode, PubKeyNode]
        :param testnet: whether this node is testnet node
        :type testnet: bool
        """
        self.master = master
        self.testnet = testnet
        self.mnemonic = None
        self.password = None

    def __eq__(self, other: "BaseWallet") -> bool:
        """
        Checks whether two wallet objects are equal.

        :param other: other base wallet
        :type other: BaseWallet
        :rtype: bool
        """
        return self.master == other.master and self.testnet == other.testnet

    @property
    def watch_only(self) -> bool:
        """
        Checks whether this wallet is watch only wallet.

        :return: whether is watch only
        :rtype: bool
        """
        return type(self.master) == PubKeyNode

    @classmethod
    def new_wallet(cls, entropy_bits: int = 256, password: str = "",
                   testnet: bool = False):
        """
        Creates new wallet.

        :param entropy_bits: how much entropy bits to use
        :type entropy_bits: int
        :param password: optional passphrase (default="")
        :type password: str
        :param testnet: whether this node is testnet node
        :type testnet: bool
        :return: wallet
        :rtype: BaseWallet
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
        :type entropy_hex: str
        :param password: optional passphrase (default="")
        :type password: str
        :param testnet: whether this node is testnet node
        :type testnet: bool
        :return: wallet
        :rtype: BaseWallet
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
        :type bip39_seed: str
        :param testnet: whether this node is testnet node
        :type testnet: bool
        :return: wallet
        :rtype: BaseWallet
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
        :type bip39_seed: bytes
        :param testnet: whether this node is testnet node
        :type testnet: bool
        :return: wallet
        :rtype: BaseWallet
        """
        return cls(
            master=PrivKeyNode.master_key(
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
        :type mnemonic: str
        :param password: optional passphrase (default="")
        :type password: str
        :param testnet: whether this node is testnet node
        :type testnet: bool
        :return: wallet
        :rtype: BaseWallet
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
        :type extended_key: str
        :return: wallet
        :rtype: BaseWallet
        """
        # just need version, key type does not matter in here
        version_int = PrivKeyNode.parse(s=extended_key).parsed_version
        version = Version.parse(version_int=version_int)
        if version.key_type == Key.PRV:
            node = PrivKeyNode.parse(extended_key, testnet=version.testnet)
        else:
            # is this just assuming? or really pub if not priv
            node = PubKeyNode.parse(extended_key, testnet=version.testnet)
        return cls(testnet=version.testnet, master=node)

    def determine_node_version_int(self,
                                   node: Priv_or_PubKeyNode,
                                   key_type: Key) -> Version:
        """
        Determines node version.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :param key_type: type of key private/public
        :type key_type: Key
        :return: version object
        :rtype: Version
        """
        bip = Bip32Path.parse(str(node))
        version = Version(
            key_type=key_type.value,
            testnet=self.testnet,
            bip=bip.bip()
        )
        return version

    def node_extended_public_key(self, node: Priv_or_PubKeyNode) -> str:
        """
        Gets node's extended public key.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: extended public key
        :rtype: str
        """
        version = self.determine_node_version_int(node=node, key_type=Key.PUB)
        return node.extended_public_key(version=int(version))

    def node_extended_private_key(self, node: Priv_or_PubKeyNode) -> str:
        """
        Gets node's extended private key.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: extended private key
        :rtype: str
        """
        if type(node) == PubKeyNode:
            raise ValueError("wallet is watch only")
        version = self.determine_node_version_int(node=node, key_type=Key.PRV)
        return node.extended_private_key(version=int(version))

    def node_extended_keys(self, node: Priv_or_PubKeyNode) -> dict:
        """
        Gets node's extended keys.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: extended keys mapping
        :rtype: dict
        """
        prv = None if self.watch_only else self.node_extended_private_key(
            node=node
        )
        return {
            "path": str(node),
            "pub": self.node_extended_public_key(node=node),
            "prv": prv
        }

    def p2pkh_address(self, node: Priv_or_PubKeyNode) -> str:
        """
        Generates p2pkh address from node.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: p2pkh address
        :rtype: str
        """
        return node.public_key.address(testnet=self.testnet, addr_type="p2pkh")

    def p2wpkh_address(self, node: Priv_or_PubKeyNode) -> str:
        """
        Generates p2wpkh address from node.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: p2wpkh address
        :rtype: str
        """
        return node.public_key.address(testnet=self.testnet, addr_type="p2wpkh")

    def p2sh_p2wpkh_address(self, node: Priv_or_PubKeyNode) -> str:
        """
        Generates p2wpkh wrapped in p2sh address from node.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: p2sh-p2wpkh address
        :rtype: str
        """
        return h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script(h160=node.public_key.h160()).raw_serialize()
            ),
            testnet=self.testnet
        )

    def p2wsh_address(self, node: Priv_or_PubKeyNode) -> str:
        """
        Generates p2wsh address from node.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: p2wsh address
        :rtype: str
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

    def p2sh_p2wsh_address(self, node: Priv_or_PubKeyNode) -> str:
        """
        Generates p2wsh wrapped in p2sh address from node.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :return: p2sh-p2wsh address
        :rtype: str
        """
        # [OP_1, sec, OP_1, OP_CHECKMULTISIG]
        witness_script = Script([0x51, node.public_key.sec(), 0x51, 0xae])
        sha256_witness_script = sha256(witness_script.raw_serialize())
        redeem_script = p2wsh_script(h256=sha256_witness_script).raw_serialize()
        return h160_to_p2sh_address(
            h160=hash160(redeem_script),
            testnet=self.testnet
        )

    def address_generator(self, node: Priv_or_PubKeyNode = None,
                          addr_fnc: Callable[[Priv_or_PubKeyNode], str] = None
                          ) -> Generator[str]:
        """
        Address generator.

        :param node: key node
        :type node: Union[PrivKeyNode, PubKeyNode]
        :param addr_fnc: function to use for address generation
        :type addr_fnc: Callable[Union[PrivKeyNode, PubKeyNode], str]
        :return: address generator
        :rtype: Generator[str]
        """
        index = 0
        addr_fnc = addr_fnc or self.p2wpkh_address
        while True:
            child = node.ckd(index=index)
            adder = yield str(child), addr_fnc(child)
            index += adder or 1

    def by_path(self, path: str) -> Priv_or_PubKeyNode:
        """
        Generate child node from master node by path.

        :param path: bip32 path
        :type path: str
        :return: child node
        :rtype: Union[PrivKeyNode, PubKeyNode]
        """
        path = Bip32Path.parse(s=path)
        return self.master.derive_path(index_list=path.to_list())
