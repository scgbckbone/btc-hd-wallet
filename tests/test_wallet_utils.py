import unittest
from wallet_utils import Bip, Version, Key, Bip32Path


class TestVersion(unittest.TestCase):
    def test_parse(self):
        with self.assertRaises(ValueError):
            Version.parse(s=152110212)

        v = Version.parse(s=0x043587CF)
        self.assertEqual(int(v), 0x043587CF)
        self.assertEqual(v.testnet, True)
        self.assertEqual(v.key_type, Key.PUB)
        self.assertEqual(v.bip, Bip.BIP44)

        v = Version.parse(s=0x04b2430c)
        self.assertEqual(int(v), 0x04b2430c)
        self.assertEqual(v.testnet, False)
        self.assertEqual(v.key_type, Key.PRV)
        self.assertEqual(v.bip, Bip.BIP84)

        v = Version.parse(s=0x049d7cb2)
        self.assertEqual(int(v), 0x049d7cb2)
        self.assertEqual(v.testnet, False)
        self.assertEqual(v.key_type, Key.PUB)
        self.assertEqual(v.bip, Bip.BIP49)


class TestBip32Path(unittest.TestCase):
    def test_integrity_check(self):
        m = Bip32Path()
        self.assertEqual(str(m), "m")
        m = Bip32Path(purpose=0)
        self.assertEqual(str(m), "m/0")
        m = Bip32Path(purpose=0, coin_type=0)
        self.assertEqual(str(m), "m/0/0")
        m = Bip32Path(purpose=0, coin_type=0, account=0)
        self.assertEqual(str(m), "m/0/0/0")
        m = Bip32Path(purpose=0, coin_type=0, account=0, chain=0)
        self.assertEqual(str(m), "m/0/0/0/0")
        m = Bip32Path(purpose=0, coin_type=0, account=0, chain=0, addr_index=0)
        self.assertEqual(str(m), "m/0/0/0/0/0")

        with self.assertRaises(RuntimeError):
            Bip32Path(addr_index=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(chain=0, addr_index=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(account=0, chain=0, addr_index=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(coin_type=0, account=0, chain=0, addr_index=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(coin_type=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(coin_type=0, addr_index=0)

        with self.assertRaises(ValueError):
            Bip32Path(purpose=0, coin_type=0, account=0, chain=0, addr_index="v")
        with self.assertRaises(ValueError):
            Bip32Path(purpose=Bip32Path)
        with self.assertRaises(RuntimeError):
            Bip32Path(purpose=0, account=0)
        with self.assertRaises(RuntimeError):
            Bip32Path(purpose=0, account=[])

    def test_general(self):
        purpose = (2 ** 31) + 44
        coin_type = (2 ** 31) + 0
        account = (2 ** 31) + 0
        chain = 0
        addr_index = 0
        path = Bip32Path(
            # purpose according to bip44
            purpose=purpose,
            coin_type=coin_type,
            account=account,
            # external chain -> 0
            chain=chain,
            addr_index=addr_index
        )
        self.assertEqual(str(path), "m/44'/0'/0'/0/0")
        self.assertTrue(path.external_chain)
        self.assertTrue(path.bitcoin_mainnet)
        self.assertFalse(path.bitcoin_testnet)
        self.assertEqual(
            path.to_list(),
            [purpose, coin_type, account, chain, addr_index]
        )
        self.assertEqual(Bip32Path.parse(s=str(path)), path)
        self.assertTrue(path.bip44)

    def test_parse(self):
        with self.assertRaises(ValueError):
            Bip32Path.parse("")
        with self.assertRaises(ValueError):
            Bip32Path.parse("s")

        self.assertEqual(Bip32Path(), Bip32Path.parse("m"))
        self.assertEqual(
            Bip32Path(private=False),
            Bip32Path.parse("M")
        )
        self.assertEqual(
            Bip32Path(purpose=0, private=False),
            Bip32Path.parse("M/0")
        )
        self.assertEqual(
            Bip32Path(purpose=0),
            Bip32Path.parse("m/0")
        )
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0),
            Bip32Path.parse("m/0/0")
        )
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0, account=0),
            Bip32Path.parse("m/0/0/0")
        )
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0, account=0, chain=0),
            Bip32Path.parse("m/0/0/0/0")
        )
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0, account=0, chain=0, addr_index=0),
            Bip32Path.parse("m/0/0/0/0/0")
        )
        # following 2 cases shows that anything behind address index position
        # is happily ignored
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0, account=0, chain=0, addr_index=0),
            Bip32Path.parse("m/0/0/0/0/0/")
        )
        self.assertEqual(
            Bip32Path(purpose=0, coin_type=0, account=0, chain=0, addr_index=0),
            Bip32Path.parse("m/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0")
        )
        # following raises as only int literals with base 10 are accepted
        with self.assertRaises(ValueError):
            Bip32Path.parse("m/0/0/0xff/0/0")
        with self.assertRaises(ValueError):
            Bip32Path.parse("m/0/0/0b01010101/0/0")
        with self.assertRaises(ValueError):
            Bip32Path.parse("m/0/0/None/0/0")

    def test_bip(self):
        path = Bip32Path(purpose=44 + (2 ** 31))
        self.assertEqual(path.bip(), 0)
        path = Bip32Path(purpose=49 + (2 ** 31))
        self.assertEqual(path.bip(), 1)
        path = Bip32Path(purpose=84 + (2 ** 31))
        self.assertEqual(path.bip(), 2)
