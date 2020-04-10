from bip32 import PubKeyNode, PrivKeyNode


class Bip84PrivateNode(PrivKeyNode):
    testnet_version = 0x045f18bc
    mainnet_version = 0x04b2430c

    @property
    def priv_version(self):
        if self.testnet:
            return Bip84PrivateNode.testnet_version
        return Bip84PrivateNode.mainnet_version

    @property
    def pub_version(self):
        if self.testnet:
            return Bip84PublicNode.testnet_version
        return Bip84PublicNode.mainnet_version


class Bip84PublicNode(PubKeyNode):
    testnet_version = 0x045f1cf6
    mainnet_version = 0x04b24746

    @property
    def pub_version(self):
        if self.testnet:
            return Bip84PublicNode.testnet_version
        return Bip84PublicNode.mainnet_version
