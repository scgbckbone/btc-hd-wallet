import unittest
from helper import p2wpkh_script_raw_serialize, hash160, h160_to_p2sh_address
from bip32_hd_wallet import PrivKeyNode, bip32_seed_from_mnemonic


class TestBip49(unittest.TestCase):
    def test_vector_1(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        master_extended = "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd"
        m = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(m.extended_private_key(version=0x044a4e28), master_extended)
        xprv = "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n"
        xpub = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"
        m49h1h0h = m.derive_path(index_list=[49 + 2 ** 31, 1 + 2 ** 31, 2 ** 31])
        self.assertEqual(m49h1h0h.extended_private_key(version=0x044a4e28), xprv)
        self.assertEqual(m49h1h0h.extended_public_key(version=0x044a5262), xpub)

        private_key = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ"
        private_key_hex = "c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8"
        public_key_hex = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
        m49h1h0h00 = m49h1h0h.derive_path(index_list=[0, 0])
        self.assertEqual(bytes(m49h1h0h00.private_key).hex(), private_key_hex)
        self.assertEqual(m49h1h0h00.private_key.wif(testnet=True), private_key)
        self.assertEqual(m49h1h0h00.public_key.sec().hex(), public_key_hex)

        keyhash = "38971f73930f6c141d977ac4fd4a727c854935b3"
        scriptSig = "001438971f73930f6c141d977ac4fd4a727c854935b3"
        address_bytes = "336caa13e08b96080a32b5d818d59b4ab3b36742"
        addr = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"

        pub_key_hash = m49h1h0h00.public_key.h160()
        script_sig = p2wpkh_script_raw_serialize(h160=pub_key_hash)
        h160_script_sig = hash160(script_sig)
        address = h160_to_p2sh_address(h160=h160_script_sig, testnet=True)

        self.assertEqual(pub_key_hash.hex(), keyhash)
        self.assertEqual(script_sig.hex(), scriptSig)
        self.assertEqual(h160_script_sig.hex(), address_bytes)
        self.assertEqual(address, addr)
