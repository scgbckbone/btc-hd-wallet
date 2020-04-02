import unittest
from more import PrivateKey


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
