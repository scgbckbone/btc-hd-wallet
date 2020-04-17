import unittest
from btc_hd_wallet.bip32_hd_wallet import PrivKeyNode, bip32_seed_from_mnemonic


class TestBip44(unittest.TestCase):
    def test_vector_1(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        root_prv = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"

        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(node.extended_private_key(), root_prv)
        privkey = "L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf"
        pubkey = "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e"
        address = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        # Account 0, first receiving address = m/44'/0'/0'/0/0
        child = node.derive_path(index_list=[44 + 2**31, 2**31, 2**31, 0, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

        privkey = "KzJgGiEeGUVWmPR97pVWDnCVraZvM2fnrCVrg2irV4353HciE6Un"
        pubkey = "02dfcaec532010d704860e20ad6aff8cf3477164ffb02f93d45c552dadc70ed24f"
        address = "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP"
        # Account 0, second receiving address = m/44'/0'/0'/0/1
        child = node.derive_path(index_list=[44 + 2**31, 2**31, 2**31, 0, 1])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

        privkey = "L1GfmUBVD88haCukMzGtmR5B5zuQVxd6cmUVe85d66Uq2V13orj3"
        pubkey = "03498b3ac8e882c5d693540c49adf22b7a1b99c1bb8047966739bfe8cdeb272e64"
        address = "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH"
        # Account 0, first change address = m/44'/0'/0'/1/0
        child = node.derive_path(index_list=[44 + 2**31, 2**31, 2**31, 1, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

    def test_vector_2(self):
        mnemonic = "banner list crush drill oxygen grit donate chair expect cloud artist window dignity company salad clinic follow drive narrow crater enlist tortoise stay rain"
        root_prv = "xprv9s21ZrQH143K427wU7WXG3doLsxkVbzVubaGShVYLHnYgb6EiiEyhhr2GEzz6UDNFrhNk9s6Ms9iPzA6xz2t6VjmGtQmATGSXDEJyGLGmbT"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(node.extended_private_key(), root_prv)
        privkey = "L2qaW9UoXt7vthCD7p1fk7NxFkw5gzR774L1vWyMQSdwgKspgUeu"
        pubkey = "0374b1b783ce4e78486ae54642a41732bb5a8980d4c50a688ad2faddcdb405b826"
        address = "19k8j3qbqshC7rEaeyq4SCtp2mYzTRsErk"
        # Account 0, first receiving address = m/44'/0'/0'/0/0
        child = node.derive_path(index_list=[44 + 2 ** 31, 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

        privkey = "L5UMLuwuAqjzZUPxhqLoxNdACD1h9V4E4csMNnLadRN7F5aEqo7a"
        pubkey = "03fc56445a29609e96e9f0715462493e0e7541d07ec45880bd878b5715e150d89b"
        address = "1F4dQThjuxNPmBkVgZLayjCMsQLGciEw7f"
        # Account 0, second receiving address = m/44'/0'/0'/0/1
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

        privkey = "KwPm4hYMLzraakKBthL2zN5VQTRQzWmwmh8SvLhBEro3EvsuziRT"
        pubkey = "02335d60362f168c567da9258c1366499d8bee2bf3425fa3b90a3ddedfddec89e2"
        address = "1Y8pXXGJMD5ZW4A3kbxCroxaf7xiFo4yp"
        # Account 0, first change address = m/44'/0'/0'/1/0
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh"),
            address
        )

    def test_vector_3(self):
        mnemonic = "alone process notice pool egg gift foster session code bright service change"
        root_prv = "tprv8ZgxMBicQKsPf4hvHELfyj2nzS7kiqu9fzi2rzHzEnTbcNSE7pEn47TDt2s8ZdD3jN6GkwbuX4W5jqSy1JvPbAdNLYRkh2jvC3WVWe9hxQr"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(node.extended_private_key(), root_prv)
        privkey = "cNutGXgQKYVrw9JJV6Fws7Js9SMojfpbxFaiF5cjeLrrkHbAhKTb"
        pubkey = "0381da8a81de5c2a42bc60bc0a649e2f08f53b594721da9ac2d212e0c3b7730edd"
        address = "mgLhaL9WAHMjxo2nQxTXb4uKQohkSDovwQ"
        # Account 0, first receiving address = m/44'/1'/0'/0/0
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

        privkey = "cNhtxSzH1upG3PDFHvYdJsm5kdDWEJpQxENJNwbtRRMcopCc336c"
        pubkey = "02c5859beb5bee582fe3a15f4515c3895d92034668748d8ced281ead49b5bb0449"
        address = "moGvMt2EbR3BkAhbbjpg1qKt11ioKJ9tox"
        # Account 0, second receiving address = m/44'/1'/0'/0/1
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

        privkey = "cVb5BXW3tJ1gFuBmEH9HaV4CZE1SESTnaptqvgkqvpYF9w7abcmi"
        pubkey = "02104bdf90bbfbb3a34e96cf1152368bd492309f7808cb2f5f63173c2a8ab46002"
        address = "mxCa2PGGeUZbFvA1upGk4D1cn4DgXAhiLX"
        # Account 0, first change address = m/44'/0'/0'/1/0
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

    def test_vector_4(self):
        mnemonic = "fence test aunt appear calm supreme february fortune dog lunch dose volume envelope path must will vanish indicate switch click brush boy negative skate"
        root_prv = "tprv8ZgxMBicQKsPdNyrMJQzmyixu2wVHYhBC4BqFuCywjPP5QQYY7mqU1FMHF8cvvnC891zhihDeTji9s9DumwWG6fiU5vDs65n7BbgECfeGwP"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(node.extended_private_key(), root_prv)
        privkey = "cVjV1Ndx6LtrHMxbsYDv3q2CLXJNqYRiG9cwodx4v7mcwXrG8iSD"
        pubkey = "03f1a036d901530e56c6a6176ad36f3d1e1b9b8a916c2ed151b3935183c44e5393"
        address = "n1W8Lo4xzjSXhV2fEzTn2tRDsDcojmVG7G"
        # Account 0, first receiving address = m/44'/1'/0'/0/0
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

        privkey = "cPpJHF6ibT1GFncfmNHvtSYS3r97X3eFtN25vm2EGbTJuiEfzh4k"
        pubkey = "03995043232281e3b07c94607fe83850be854242446233a9343dd4416980c0ac49"
        address = "miomtTdPdDF7vkqaPYvQnmabQt4U1EiQbD"
        # Account 0, second receiving address = m/44'/1'/0'/0/1
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

        privkey = "cN29ySsZcGfnzwjjW1SDRHXskZu74LCEFroYUncg36Z4cc7asN9b"
        pubkey = "0200d38aa76fd2b4c8cec5df529e9690ee911646c7879d35c2f11267efbca9b0ec"
        address = "mvgHvHAi5RYexicFmpvWKs8weiYFCdMkEH"
        # Account 0, first change address = m/44'/0'/0'/1/0
        child = node.derive_path(
            index_list=[44 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            child.public_key.address(addr_type="p2pkh", testnet=True),
            address
        )

