import unittest
from keys import PrivateKey


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
        pk = PrivateKey.parse(byte_str=bytes.fromhex(key))
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
