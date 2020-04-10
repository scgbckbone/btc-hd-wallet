from bip32 import PubKeyNode, PrivKeyNode


class Bip49PrivateNode(PrivKeyNode):
    testnet_version = 0x044a4e28
    mainnet_version = 0x049d7878

    @property
    def priv_version(self):
        if self.testnet:
            return Bip49PrivateNode.testnet_version
        return Bip49PrivateNode.mainnet_version

    @property
    def pub_version(self):
        if self.testnet:
            return Bip49PublicNode.testnet_version
        return Bip49PublicNode.mainnet_version


class Bip49PublicNode(PubKeyNode):
    testnet_version = 0x044a5262
    mainnet_version = 0x049d7cb2

    @property
    def pub_version(self):
        if self.testnet:
            return Bip49PublicNode.testnet_version
        return Bip49PublicNode.mainnet_version
