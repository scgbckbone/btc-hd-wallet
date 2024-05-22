import unittest
from btc_hd_wallet.helper import int_to_big_endian
try:
    from pysecp256k1.low_level.secp256k1 import Libsecp256k1Exception
    exc0 = Libsecp256k1Exception
except ImportError:
    from btc_hd_wallet.bip32 import InvalidKeyError
    exc0 = InvalidKeyError
from btc_hd_wallet.base_wallet import BaseWallet
from btc_hd_wallet.bip85 import BIP85DeterministicEntropy
from btc_hd_wallet.bip39 import CORRECT_MNEMONIC_LENGTH


CURVE_ORDER = int_to_big_endian(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 32)


class TestBIP85DeterministicEntropy(unittest.TestCase):
    XPRV = 'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'
    w = BaseWallet.from_extended_key(extended_key=XPRV)
    bip85 = BIP85DeterministicEntropy(master_node=w.master)

    def test_incorrect_key(self):
        with self.assertRaises(exc0):
            self.bip85.correct_key(key_bytes=b"\x00" * 32)

        with self.assertRaises(exc0):
            self.bip85.correct_key(key_bytes=CURVE_ORDER)

    def test_byte_count_from_word_count(self):
        for wc, expected in zip(CORRECT_MNEMONIC_LENGTH, [16, 20, 24, 28, 32]):
            self.assertEqual(expected, self.bip85.byte_count_from_word_count(wc))

        with self.assertRaises(ValueError):
            self.bip85.byte_count_from_word_count(11)

        with self.assertRaises(ValueError):
            self.bip85.byte_count_from_word_count(25)

    def test_from_xprv(self):
        self.assertEqual(
            self.bip85,
            BIP85DeterministicEntropy.from_xprv(xprv=self.XPRV)
        )

    def test_entropy(self):
        expected = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
        result = self.bip85.entropy(path="m/83696968'/0'/0'").hex()
        self.assertEqual(expected, result)

        expected = "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
        result = self.bip85.entropy(path="m/83696968'/0'/1'").hex()
        self.assertEqual(expected, result)

    def test_mnemonic_to_entropy(self):
        PATH = "m/83696968'/0'/0'"
        mnemonic = "install scatter logic circle pencil average fall shoe quantum disease suspect usage"
        w = BaseWallet.from_mnemonic(mnemonic=mnemonic)
        bip85 = BIP85DeterministicEntropy(master_node=w.master)
        entropy = bip85.entropy(path=PATH)
        expected = 'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7'
        self.assertEqual(expected, entropy.hex())

        w = BaseWallet.from_mnemonic(mnemonic=mnemonic, password="TREZOR")
        bip85 = BIP85DeterministicEntropy(master_node=w.master)
        entropy = bip85.entropy(path=PATH)
        expected = 'd24cee04c61c4a47751658d078ae9b0cc9550fe43eee643d5c10ac2e3f5edbca757b2bd74d55ff5bcc2b1608d567053660d9c7447ae1eb84b6619282fd391844'
        self.assertEqual(expected, entropy.hex())

    def test_xprv_to_entropy(self):
        entropy = self.bip85.entropy(path="m/83696968'/0'/0'")
        expected = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
        self.assertEqual(expected, entropy.hex())

    def test_entropy_to_mnemonic(self):
        words12 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
        self.assertEqual(words12, self.bip85.bip39_mnemonic(word_count=12, index=0))

        word15 = "aerobic able grant hobby uncle boss filter auction tip exact mixed again soda race absorb"
        self.assertEqual(word15, self.bip85.bip39_mnemonic(word_count=15, index=0))

        words18 = "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
        self.assertEqual(words18, self.bip85.bip39_mnemonic(word_count=18, index=0))

        word21 = "feed excite donkey pepper enhance box stock asset submit tomorrow quick divert frost setup cream elder unable harbor enlist fabric this"
        self.assertEqual(word21, self.bip85.bip39_mnemonic(word_count=21, index=0))

        words24 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
        self.assertEqual(words24, self.bip85.bip39_mnemonic(word_count=24, index=0))

    def test_entropy_to_wif(self):
        expected = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
        self.assertEqual(expected, self.bip85.wif())

    def test_entropy_to_xprv(self):
        expected = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
        self.assertEqual(expected, self.bip85.xprv())

    def test_entropy_to_hex(self):
        expected = "ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc"
        self.assertEqual(expected, self.bip85.hex(num_bytes=32, index=0))

        expected = "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
        self.assertEqual(expected, self.bip85.hex(num_bytes=64, index=0))

        expected = "61d3c182f7388268463ef327c454a10bc01b3992fa9d2ee1b3891a6b487a5248793e61271066be53660d24e8cb76ff0cfdd0e84e478845d797324c195df9ab8e"
        self.assertEqual(expected, self.bip85.hex(num_bytes=64, index=1234))

        with self.assertRaises(ValueError):
            self.bip85.hex(15)

        with self.assertRaises(ValueError):
            self.bip85.hex(65)

    def test_entropy_to_pwd(self):
        expected = "RrH7uVI0XlpddCbiuYV+"
        assert len(expected) == 20
        self.assertEqual(expected, self.bip85.pwd(pwd_len=20, index=0))

        expected = "dKLoepugzdVJvdL56ogNV"
        assert len(expected) == 21
        self.assertEqual(expected, self.bip85.pwd(pwd_len=21, index=0))

        expected = "vtV6sdNQTKpuefUMOHOKwUp1"
        assert len(expected) == 24
        self.assertEqual(expected, self.bip85.pwd(pwd_len=24, index=0))

        expected = "mBhJgXCJd6IpdOu1cc/D1wU+5sxj/1tK"
        assert len(expected) == 32
        self.assertEqual(expected, self.bip85.pwd(pwd_len=32, index=1234))

        expected = "HBqosVLBhKneX8ZCZgLdvmA8biOdUV2S/AteE5Rs8sMT0pfG3aItk/IrHGEpY9um"
        assert len(expected) == 64
        self.assertEqual(expected, self.bip85.pwd(pwd_len=64, index=1234))

        expected = "7n3VQ63qjgY6OJBQxqWYToNRfzzN5J8DwN1D8JqlZfnsF+1LdPXG3gkOXighX4iKyKip8nRIhVVVObh/G41F7g"
        assert len(expected) == 86
        self.assertEqual(expected, self.bip85.pwd(pwd_len=86, index=1234))

        with self.assertRaises(ValueError):
            self.bip85.pwd(pwd_len=19)

        with self.assertRaises(ValueError):
            self.bip85.pwd(pwd_len=87)
