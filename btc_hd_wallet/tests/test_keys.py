import unittest
from btc_hd_wallet.keys import PrivateKey, PublicKey


class TestPrivateKey(unittest.TestCase):
    def test_wif(self):
        pk = PrivateKey(sec_exp=2 ** 256 - 2 ** 199)
        expected = 'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'
        self.assertEqual(PrivateKey.from_wif(expected), pk)
        self.assertEqual(pk.wif(compressed=True, testnet=False), expected)
        pk = PrivateKey(sec_exp=2 ** 256 - 2 ** 201)
        expected = '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'
        self.assertEqual(PrivateKey.from_wif(expected), pk)
        self.assertEqual(pk.wif(compressed=False, testnet=True), expected)
        pk = PrivateKey(
            0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d
        )
        expected = '5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty'
        self.assertEqual(PrivateKey.from_wif(expected), pk)
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)
        pk = PrivateKey(
            0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f
        )
        expected = 'cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg'
        self.assertEqual(PrivateKey.from_wif(expected), pk)
        self.assertEqual(pk.wif(compressed=True, testnet=True), expected)

        key = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
        pk = PrivateKey.parse(key_bytes=bytes.fromhex(key))
        expected = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        self.assertEqual(PrivateKey.from_wif(expected), pk)
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)

        secret = 4226949130810261207757751156156787536530387212321569115516465271662024001999
        sk0 = PrivateKey(sec_exp=secret)
        sk1 = PrivateKey.from_wif(
            'KwXsoVsi9NxKKYYgVc6J8JzWRucM6RfPE41bjCuX7tXUDuiRYCvC'
        )
        self.assertEqual(sk0, sk1)

        secret = 0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        sk0 = PrivateKey(sec_exp=secret)
        self.assertEqual(
            sk0.wif(compressed=False),
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        )
        sk1 = PrivateKey.from_wif(
            wif_str="5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        )
        self.assertEqual(sk0, sk1)

    def test_privkey_to_p2wpkh_mainnet(self):
        data = [
            (
                "bc1qmptratgp4thd6y66fam79vewuwm5sdefh84u70",
                "L3VVdf8UXRYunf5BqmabR8XGdQ73B59nmUDi915rLE2fAMPJqSbB"
            ),
            (
                "bc1qzz7w3p6yz2zf2htdl4svgm64hnv6wyut5dsas4",
                "L5aMh2zkXjqMUMfo5Grmzad9pYUviN4dirN5XHA4jKqZTWSQ3U6N"
            ),
            (
                "bc1qe099fhp9e5jn3yva55j3yefcv4alw2reqqj06x",
                "KzPBBhUWQDw3Dg5tLDVQmJgLGBxPqUr6ngprNGaSJuVQs2Rf88Aj"
            ),
            (
                "bc1qh2lxehe06p995gem7jqc98pxhpjau67q56zh9p",
                "Kx98aWvjQMNbzkcFT4MAMTpNqbtpqrrKzgvDpHRzfYsW6bx5CGT1"
            ),
            (
                "bc1qwcvgf9szncgwmesqfgr99t5dm8mc3dznvtshw4",
                "Ky9y95vgKg511Yb3ZycdbSGjNapGd6U67t57cWWQtnB3BYpUpfVV"
            ),
            (
                "bc1qkpfpkjdkdz968t8qw0a2r4tsdpk678t9pmd3yn",
                "Kwuy3WpCs7YzxAHn9hizS9XtppgPk9fggGk5Zd4g4fnHqiMwrEQw"
            ),
        ]
        for address, key_wif in data:
            self.assertEqual(
                PrivateKey.from_wif(wif_str=key_wif).K.address(
                    addr_type="p2wpkh"
                ),
                address
            )

    def test_privkey_to_p2wpkh_testnet(self):
        data = [
            (
                "tb1qlwypq44kdfwggmjgxv7cypsy7rwvf8w00j029t",
                "cTTxoGWS7pijV49btqYyUquziwMHovzkkCpVo96Dh162QoFMQnR8"
            ),
            (
                "tb1q3cas2qqp9vt37mfuy2pp67nepjt20qf7pv89r2",
                "cUFaKjRgUGnKFwvFNyHBbWqZaZtQHza1YPGLbaDR1RTrK31oTo8U"
            ),
            (
                "tb1q770cafdm70kqvd55r9zxkg5w5q0zal4xylnp8c",
                "cV2hAjyg4fYo5XujEozNEdCJjYbdXXEAcRUnUDp9p3JckHnUAmYG"
            ),
            (
                "tb1qd5lr773njn98n8hwnx2ztq2j25540rvzgmq5nn",
                "cVwaEkzaQkHgzoLorNUmUZvBkM17JcKXdVVJZKU4so9aZB5wDNfD"
            ),
            (
                "tb1qtkqwqg9afhthv6c2f9cfkagfz660pg074kgfnt",
                "cPACpn3PNM5Q9dByB3ZCbgxzJ4EYbqEqC2p8S1hkSCRNqTANW8Cv"
            ),
            (
                "tb1qgq2fq3g765c9cg4xym5rna5w6njgzlxy5mvs2y",
                "cNYq9wavxSW5G6KRqokwwd4LzJrhpmVtkjzH6XEWwDMNzNdGtNFY"
            )
        ]
        for address, key_wif in data:
            self.assertEqual(
                PrivateKey.from_wif(wif_str=key_wif).K.address(
                    addr_type="p2wpkh",
                    testnet=True
                ),
                address
            )


class TestPublicKey(unittest.TestCase):
    def test_sec(self):
        data = [
            (
                999 ** 3,
                '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9',
                '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
            ),
            (
                123,
                '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b',
                '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
            ),
            (
                42424242,
                '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3',
                '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'
            )
        ]
        for secret, uncompressed, compressed in data:
            pubkey = PrivateKey(sec_exp=secret).K
            self.assertEqual(
                pubkey.sec(compressed=False),
                bytes.fromhex(uncompressed)
            )
            self.assertEqual(
                pubkey.point,
                PublicKey.parse(bytes.fromhex(uncompressed)).point
            )
            self.assertEqual(
                pubkey.sec(compressed=True),
                bytes.fromhex(compressed)
            )
            self.assertEqual(
                pubkey.point,
                PublicKey.parse(bytes.fromhex(compressed)).point
            )

    def test_incorrect_address_type(self):
        pubkey = PrivateKey(sec_exp=6516151654156).K
        with self.assertRaises(ValueError):
            pubkey.address(addr_type="p2sh")
        with self.assertRaises(ValueError):
            pubkey.address(addr_type="p2ep")
        with self.assertRaises(ValueError):
            pubkey.address(addr_type="incorrect")

    def test_address(self):
        data = [
            {
                "secret": 888 ** 3,
                "p2pkh": {
                    "main": {
                        "addr": '148dY81A9BmdpMhvYEVznrM45kWN32vSCN',
                        "data": {"addr_type": "p2pkh", "compressed": True, "testnet": False}
                    },
                    "test": {
                        "addr": 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP',
                        "data": {"addr_type": "p2pkh", "compressed": True, "testnet": True}
                    }
                },
                "p2wpkh": {
                    "main": {
                        "addr": 'bc1qyfvunnpszmjwcqgfk9dsne6j4edq3fglx9y5x7',
                        "data": {"addr_type": "p2wpkh", "testnet": False}
                    },
                    "test": {
                        "addr": 'tb1qyfvunnpszmjwcqgfk9dsne6j4edq3fglvrl8ad',
                        "data": {"addr_type": "p2wpkh", "testnet": True}
                    }
                }
            },
            {
                "secret": 321,
                "p2pkh": {
                    "main": {
                        "addr": '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj',
                        "data": {"addr_type": "p2pkh", "compressed": False, "testnet": False}
                    },
                    "test": {
                        "addr": 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP',
                        "data": {"addr_type": "p2pkh", "compressed": False, "testnet": True}
                    }
                },
                "p2wpkh": {
                    "main": {
                        "addr": 'bc1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mrssamm',
                        "data": {"addr_type": "p2wpkh", "testnet": False}
                    },
                    "test": {
                        "addr": 'tb1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mfktwqg',
                        "data": {"addr_type": "p2wpkh", "testnet": True}
                    }
                }
            },
            {
                "secret": 4242424242,
                "p2pkh": {
                    "main": {
                        "addr": '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb',
                        "data": {"addr_type": "p2pkh", "compressed": False, "testnet": False}
                    },
                    "test": {
                        "addr": 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s',
                        "data": {"addr_type": "p2pkh", "compressed": False, "testnet": True}
                    }
                },
                "p2wpkh": {
                    "main": {
                        "addr": 'bc1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9xa6f6e',
                        "data": {"addr_type": "p2wpkh", "testnet": False}
                    },
                    "test": {
                        "addr": 'tb1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9vmp6p2',
                        "data": {"addr_type": "p2wpkh", "testnet": True}
                    }
                }
            },
        ]
        for obj in data:
            pubkey = PrivateKey(sec_exp=obj["secret"]).K
            # p2pkh
            self.assertEqual(
                pubkey.address(**obj["p2pkh"]["main"]["data"]),
                obj["p2pkh"]["main"]["addr"]
            )
            self.assertEqual(
                pubkey.address(**obj["p2pkh"]["test"]["data"]),
                obj["p2pkh"]["test"]["addr"]
            )
            # p2wpkh
            self.assertEqual(
                pubkey.address(**obj["p2wpkh"]["main"]["data"]),
                obj["p2wpkh"]["main"]["addr"]
            )
            self.assertEqual(
                pubkey.address(**obj["p2wpkh"]["test"]["data"]),
                obj["p2wpkh"]["test"]["addr"]
            )

    def test_equality(self):
        sk = PrivateKey(sec_exp=1256615165161)
        sk1 = PrivateKey(sec_exp=1256615165161)

        pk = PublicKey.parse(key_bytes=bytes.fromhex(
            "0311f16bf6194093aea6bde62a44ffe7ca054daa4e779e6f427e100eff578bc4fd"
        ))
        pk1 = PublicKey.parse(key_bytes=bytes.fromhex(
            "0311f16bf6194093aea6bde62a44ffe7ca054daa4e779e6f427e100eff578bc4fd"
        ))
        self.assertEqual(pk, pk1)

        pk = PublicKey.from_point(point=pk.point)
        pk1 = PublicKey.from_point(point=pk1.point)

        self.assertEqual(pk, pk1)
        self.assertEqual(sk.K, sk1.K)

        pk2 = PublicKey.parse(key_bytes=bytes.fromhex(
            "033c47bf0f7c18ed18f49efd78cfb14138e673eea135ccf0779f22c46c93ac2b2f"
        ))
        self.assertNotEqual(pk1, pk2)
