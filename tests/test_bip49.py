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

    def test_vector_2(self):
        mnemonic = "goat trick april onion eight theory segment foil indicate smart submit replace used century acquire spray save helmet"
        master_extended = "yprvABrGsX5C9januNLW3qTv3oPvS7jBRxj2S36zQRTZvFg3CsE6tjFQ5WcraLVsMyvwtwhyGboKSLbBaz6osX5Az8SWc95afN2jCEWQKYHH2qZ"
        m = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(
            m.extended_private_key(version=0x049d7878),
            master_extended
        )
        xprv = "yprvAHwZEpBsVaP56tTDMErDZHZVNjGZyzigRmdHAoCLvTEbpWT4opUPhDRsJxZDaF9MNCYv4uVskR7P4NDjEHysmCQix3giBgEYaiRwGaN39po"
        xpub = "ypub6WvueKimKwwNKNXgTGPDvRWDvm74PTSXnzYsyBbxUnmahJnDMMneF1kMAFfb881mcVTQaR67y2xWSQEzzz1jRsCxBxJEjcLoa5yjfk6vS1c"
        m49h0h0h = m.derive_path(index_list=[49 + 2 ** 31, 2 ** 31, 2 ** 31])
        self.assertEqual(m49h0h0h.extended_private_key(version=0x049d7878), xprv)
        self.assertEqual(m49h0h0h.extended_public_key(version=0x049d7cb2), xpub)

        private_key = "L1sXXZNfFsUEEjKNHZ2eniuNvYGkkBbfV2ASRsJB9i6EHptjrLmR"
        public_key_hex = "021cecf2d58d3493df3567c84c8fd1899a13882dad2606db7cd48ff1e230e2c911"
        m49h0h0h00 = m49h0h0h.derive_path(index_list=[0, 0])
        self.assertEqual(m49h0h0h00.private_key.wif(), private_key)
        self.assertEqual(m49h0h0h00.public_key.sec().hex(), public_key_hex)

        addr = "3HFgoEnSu3CQsZ7G9x8gxQW9Kw7vSJL1mr"
        address = h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script_raw_serialize(
                    h160=m49h0h0h00.public_key.h160()
                )
            )
        )
        self.assertEqual(address, addr)

    def test_vector_3(self):
        mnemonic = "never beach drink duty chicken inject morning loop hundred sleep alcohol artwork distance quality anxiety bind wrestle broom"
        master_extended = "yprvABrGsX5C9jansmRNiPoZkRJ79TdprUga5HUUmzeUMesm1nMLUmMdQMvS7gXRzFeC8vS4CakXjeQYGgrPMyuJM1b7tSxR7X6KcAdd7rJ1mUy"
        m = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(
            m.extended_private_key(version=0x049d7878),
            master_extended
        )
        xprv = "yprvAJ4Ht8bxDX5e5CHfXNy6ah4haVWMfWjHmAr413xp8197hnSo4NwVpkxLepJwcEZ2qrmwewE1EZTWDYXVR3AdfG3NsECNAnqku4XhUEj1Krc"
        xpub = "ypub6X3eHe8r3tdwHgN8dQW6wq1S8XLr4yT98PmeoSNRgLg6aamwbvFkNZGpW6qaqbG74yzsR74DhWPaV91S7J6KvormDHifQqGYS9uXHTZ4pgK"
        m49h0h0h = m.derive_path(index_list=[49 + 2 ** 31, 2 ** 31, 2 ** 31])
        self.assertEqual(m49h0h0h.extended_private_key(version=0x049d7878), xprv)
        self.assertEqual(m49h0h0h.extended_public_key(version=0x049d7cb2), xpub)

        private_key = "L1RE5PhKibfRiM4wd6FJtU3srveNM2TUJmnkyxGwREU3nTcRHYNx"
        public_key_hex = "033277fbb2ec53186fcf4db16487be8a8caa47f4538fedaffa3867f98b264a203e"
        m49h0h0h00 = m49h0h0h.derive_path(index_list=[0, 0])
        self.assertEqual(m49h0h0h00.private_key.wif(), private_key)
        self.assertEqual(m49h0h0h00.public_key.sec().hex(), public_key_hex)

        addr = "3FQCg6Rh8d2L28UG3i23NjTzhXhHmRvmZy"
        address = h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script_raw_serialize(
                    h160=m49h0h0h00.public_key.h160()
                )
            )
        )
        self.assertEqual(address, addr)

    def test_vector_4(self):
        mnemonic = "decide crowd time timber switch rubber planet west all deal trick apology session barely reflect pupil blush laptop either eagle limit"
        master_extended = "uprv8tXDerPXZ1QsURvozt1czYYfwn7iGFpHdbMJpva9BgWGAKYGQBxJdyGgjfQUiiqRPd9WQ7GnrQ8TL7yNxMjjk7SsCMnBk9Pp6mgXYF5JrUx"
        m = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(
            m.extended_private_key(version=0x044a4e28),
            master_extended
        )
        xprv = "uprv8zsXUNfWwdJd7m3Swsg9oF7T33CUQeqKQQfoGSTnLNvDfV5noKD3XiiJabrsKSiR77NjMTtSnpY4qMSvc9XEkimGvQ6PA1upFKMM5KzwY1p"
        xpub = "upub5DrsstCQmzrvLF7v3uDAAP4Bb52xp7ZAmdbQ4psPtiTCYHQwLrXJ5X2nRsNumw36yWyTYbrXUZ2517LGEdqjijYJWUGKYQTkBquYnYanRYD"
        m49h1h0h = m.derive_path(index_list=[49 + 2 ** 31, 1 + 2 ** 31, 2 ** 31])
        self.assertEqual(m49h1h0h.extended_private_key(version=0x044a4e28), xprv)
        self.assertEqual(m49h1h0h.extended_public_key(version=0x044a5262), xpub)

        private_key = "cV2c5khhiDLDVnwjZFPrto9SR4rVzrBZpcPtRur6ddTbNnNdCm2T"
        public_key_hex = "02ab437184f8f960a25ca203e8b0c817a6fa6def4163a53b1aee42217006a7853f"
        m49h1h0h00 = m49h1h0h.derive_path(index_list=[0, 0])
        self.assertEqual(m49h1h0h00.private_key.wif(testnet=True), private_key)
        self.assertEqual(m49h1h0h00.public_key.sec().hex(), public_key_hex)

        addr = "2NBCPWjwJ5gKhBr1BpTsv8QVWq9vVqAvMB5"
        address = h160_to_p2sh_address(
            h160=hash160(
                p2wpkh_script_raw_serialize(
                    h160=m49h1h0h00.public_key.h160()
                )
            ),
            testnet=True
        )
        self.assertEqual(address, addr)
