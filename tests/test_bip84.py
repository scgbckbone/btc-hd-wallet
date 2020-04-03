import unittest
from more import PrivKeyNode, bip32_seed_from_mnemonic, Bip
from helper import hash160, h160_to_p2wpkh_address


class TestBip84(unittest.TestCase):
    def test_vector_1(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        root_prv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
        root_pub = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(node.extended_public_key(bip=Bip.BIP84.value), root_pub)
        self.assertEqual(node.extended_private_key(bip=Bip.BIP84.value), root_prv)

        privkey = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"
        pubkey = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        # Account 0, first receiving address = m/84'/0'/0'/0/0
        node = PrivKeyNode.by_path(path="m/84'/0'/0'/0/0", mnemonic=mnemonic)
        self.assertEqual(node.private_key.wif(), privkey)
        self.assertEqual(node.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(node.public_key.sec())),
            address
        )

        privkey = "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy"
        pubkey = "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"
        address = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        # Account 0, second receiving address = m/84'/0'/0'/0/1
        node = PrivKeyNode.by_path(path="m/84'/0'/0'/0/1", mnemonic=mnemonic)
        self.assertEqual(node.private_key.wif(), privkey)
        self.assertEqual(node.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(node.public_key.sec())),
            address
        )

        privkey = "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF"
        pubkey = "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6"
        address = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        # Account 0, first change address = m/84'/0'/0'/1/0
        node = PrivKeyNode.by_path(path="m/84'/0'/0'/1/0", mnemonic=mnemonic)
        self.assertEqual(node.private_key.wif(), privkey)
        self.assertEqual(node.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(node.public_key.sec())),
            address
        )
