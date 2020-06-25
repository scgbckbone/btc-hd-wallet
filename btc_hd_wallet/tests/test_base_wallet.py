import unittest
from btc_hd_wallet.base_wallet import BaseWallet


class TestBaseWallet(unittest.TestCase):
    mnemonic = (
        "vast tell razor drip stick one engine action "
        "width sport else try scare phone blouse view "
        "program ketchup pole rapid use length student raven"
    )
    wallet = BaseWallet.from_mnemonic(mnemonic=mnemonic)
    wallet_testnet = BaseWallet.from_mnemonic(mnemonic=mnemonic, testnet=True)

    def test_from_entropy_hex(self):
        w = BaseWallet.from_entropy_hex(entropy_hex="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd")
        self.assertEqual(w, self.wallet)
        w = BaseWallet.from_entropy_hex(entropy_hex="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd", testnet=True)
        self.assertEqual(w, self.wallet_testnet)

    def test_from_mnemonic(self):
        w = BaseWallet.new_wallet()
        self.assertEqual(w, BaseWallet.from_mnemonic(mnemonic=w.mnemonic))
        w = BaseWallet.new_wallet(mnemonic_length=12)
        self.assertEqual(w, BaseWallet.from_mnemonic(mnemonic=w.mnemonic))

    def test_from_bip39_seed_hex(self):
        w_main = BaseWallet.from_bip39_seed_hex(bip39_seed="3312a36ef723c00b9fe6cdebbf15d227de281bc9679a799014b772f465b93ea4b2914dbcd46e531a1cb2d222183b49f0334fb4a557d8fecdf7908c451e67c1a0")
        self.assertEqual(w_main, self.wallet)

        w_test = BaseWallet.from_bip39_seed_hex(bip39_seed="3312a36ef723c00b9fe6cdebbf15d227de281bc9679a799014b772f465b93ea4b2914dbcd46e531a1cb2d222183b49f0334fb4a557d8fecdf7908c451e67c1a0", testnet=True)
        self.assertEqual(w_test, self.wallet_testnet)

    def test_private_key_from_watch_only(self):
        xpub = "xpub6CEGxdGrXswtcL6Hqo1L3wwzDBuRzQvQfUa5PZponbX7ibNWUKkhp1LaNHMg9oJYjjRmbxArwDUjpudAvmNDRG8LGwYb9YvnkEfMY3eGdTP"
        w = BaseWallet.from_extended_key(extended_key=xpub)
        with self.assertRaises(ValueError):
            w.node_extended_private_key(node=w.master)

    def test_no_private_key_for_watch_only(self):
        xpub = "xpub6CEGxdGrXswwWNoqpBePNgiQhjBmcEZWoPfkGcLg7zEjBxrFBkSzcFGrkpPqvH7TJwkjyuGMShKuyU7VpjvKnUoTavL9xSaq3DvKCAgNhwM"
        w = BaseWallet.from_extended_key(extended_key=xpub)
        self.assertTrue(w.watch_only)
        ext_keys = w.node_extended_keys(node=w.master)
        self.assertIsNone(ext_keys["prv"])
        self.assertEqual(ext_keys["pub"], xpub)

    def test_no_bip85_for_watch_only(self):
        xpub = "xpub6CEGxdGrXswwWNoqpBePNgiQhjBmcEZWoPfkGcLg7zEjBxrFBkSzcFGrkpPqvH7TJwkjyuGMShKuyU7VpjvKnUoTavL9xSaq3DvKCAgNhwM"
        w = BaseWallet.from_extended_key(extended_key=xpub)
        self.assertTrue(w.watch_only)
        self.assertIsNone(w.bip85)

    def test_bip85_for_watch_only(self):
        self.assertFalse(self.wallet.watch_only)
        self.assertIsNotNone(self.wallet.bip85)

    def test_p2pkh_address(self):
        node = self.wallet.by_path(path="m/44'/0'/0'/0/100")
        self.assertEqual(
            self.wallet.p2pkh_address(node=node),
            "19LqfkDD8B3GY4KBeXAQeJYcpfMNzk6mRC"
        )
        node = self.wallet_testnet.by_path(path="m/44'/1'/0'/0/100")
        self.assertEqual(
            self.wallet_testnet.p2pkh_address(node=node),
            "mi4BXBhVtPEcfmAu2zNN2vESAm2XNgkZq8"
        )

    def test_p2wpkh_address(self):
        node = self.wallet.by_path(path="m/84'/0'/0'/0/100")
        self.assertEqual(
            self.wallet.p2wpkh_address(node=node),
            "bc1qkm0g4asrzhwsvsz7xvwrgxmxpu55kuj7mxmfsg"
        )
        node = self.wallet_testnet.by_path(path="m/84'/1'/0'/0/100")
        self.assertEqual(
            self.wallet_testnet.p2wpkh_address(node=node),
            "tb1qn336ejd8d8fv56pfd9k0jwmgmryapujqngjvzj"
        )

    def test_p2sh_p2wpkh_address(self):
        node = self.wallet.by_path(path="m/49'/0'/0'/0/100")
        self.assertEqual(
            self.wallet.p2sh_p2wpkh_address(node=node),
            "3Co7XvssENbYcJ11uBWyhFb2q1ZfsQ1bFj"
        )
        node = self.wallet_testnet.by_path(path="m/49'/1'/0'/0/100")
        self.assertEqual(
            self.wallet_testnet.p2sh_p2wpkh_address(node=node),
            "2N2LE6PHCptB1AxGbw27AZMxKTsBLFR68D8"
        )

    def test_p2wsh_address(self):
        target = [
            "bc1qnhamzwfwytllz9jmzztl29x9lp7zfgg2ap2zyw7w59jhfufc79uqm4cxdc",
            "bc1qtuqhjrwmyz8pm7d58mnznne0h4dkf9g7xpw2azuz2qant3959sus932ukh",
            "bc1q6q2ycfza9ud6492xyysmlpnnszzz0nkqjy7mztrk5mkcc2x6d0rqerfuqs",
            "bc1qv2mkla5smc5zfqxdvpfxcjnmdhwd6xp25j52cftwvn8fnl93rf6qfau0yf",
            "bc1qjlewzdxs5zvgvg8stu7wax56zarzanwvkn6yc9dtxehtp88v08qqfews4g",
            "bc1qg0ld7v0u77c9ppe06qmf366ld9v3zgnnp92fkqlxen6kdkuydgessufekx",
            "bc1qygyhepadhmae739knnacmpyvt5u0860v6ut6mvt558wl3qx4s3lq28s8ud",
            "bc1q6kqvrrt08vculgwfnpzml8wn7r7ka2jh5nch9g2wdg4n2sysrgusch86mk",
            "bc1qrd4ge3eq6amprtqefqq20rhvqdx83p4f54d0mycll6xs8clugxdsw57wwe",
            "bc1qj7x090ar4z9gkj40p5a9xfgkpl74exn3l7rv9djcwhnca9y0qfeqf8dc4h",
            "bc1qty3wu2gvl7g5qcfw45z5h89q7fvcnx4g9n9jujaatgampqcvc8xqtxdphz",
            "bc1qcr92g5ug2fz2vwwfhcech53wu4wquw8nfm070kk586qtc3s3rvgqx5j4wl",
            "bc1q4quu7asxxnzwd24a9gy8qs9gc0h65z03d4ggswaj6gecc4jca3hqe0tzy5",
            "bc1q8mqawelvxsdz2hkd8nnt4rlx89m8kky5qc7382wty237ymdneh8q2uh03l",
            "bc1qrha82s8ha73xlnskv5p29mypc5zz7pj4d3qkd3znrke56q2ncrxs885m6h",
            "bc1q0gvxdj23c34clmhkmx95dfhcujyll0fftm29uf7ptnz3svxmejfqj2ea5m",
            "bc1qwvrxmm9n5pdy7tllqdtwqq2swcm0dzdwg9dff667fsfl6ces2v4sqwfqve",
            "bc1qjad5gkcapq9nhpshtq0m5gr7lsy0ge3v64krcp2t2zvs3jp23h4qcxd2gu",
            "bc1qknxg650jffl6je8c0275nfw348gl9evxl9vnwfr5sp2vjn75usnqplaw50",
            "bc1qxse6lnmgc42349qgzf3909w7y3kdefc5a93tj3vm6xx7xlnxm98s9969fj",
        ]
        children = self.wallet.master.generate_children()
        addresses = [self.wallet.p2wsh_address(child) for child in children]
        self.assertEqual(addresses, target)

    def test_p2sh_p2wsh_address(self):
        target = [
            "39TkB2k8DXLEMtnF742kqs2NZGPY6TokmD",
            "39jE2B8wvBixa8ks3CgW1ibhUmCzLDZyi6",
            "3B9sfmxGgiqkAmsPRYHRLbiBoa3C9LxMdK",
            "31kMjsQZzCj6aXPdS1P9sCpaGCbcR4upcY",
            "3Ee7FB2XV6ZccqZTwG3FGNgJAFXREqBhRJ",
            "3BH4Zq6RgZ4A9rMciY9Ujb2AREd5VZHo9U",
            "3EMrcVpkAK8e2QnWi1D9JfEV54DsrK723p",
            "3J7VEkVDBEypn2Muia4a2NvGwxFxvrWvrd",
            "3MW9M26CVbEinoozYHKSMp5bjfzwz6Ke2M",
            "3GgCxKS4VVagoCA7s6Aqe1dV5bvWDs9Wqv",
            "3LKhqJis3LheiqFc8pKS6bp73Eodu7ye8H",
            "3ALX3CFat3woW2YCfLiyMYpr5P7W4VqKJv",
            "3MxASx83vYtAnYynY5YLZPu226yuQBGfe3",
            "3BBDk6x8VGrARB2rV2XyvDUJV2465RDoFX",
            "36397CrMhfKDwWEcfq9mkJeZDs7wA1UgGD",
            "3BhKvPtH8Yc9XkTbV79iePgZUcBRSh5ftA",
            "3Nh2cDEFDo6wS5TSm5Zg9dJ1x5F1zcHFxs",
            "32Sn1LHEU5kBZNo3P7fpN1o9WmSqy9khbN",
            "33dAZx5nZfiD5wx9zvMBNK1cFGqxirPiVz",
            "3Jvys66uDjTB9AYc6BtXUJBg29EdggJYyM",
        ]
        children = self.wallet.master.generate_children()
        addresses = [self.wallet.p2sh_p2wsh_address(child) for child in children]
        self.assertEqual(addresses, target)

    def test_address_generator(self):
        acct10_external_chain = self.wallet.master.derive_path(
            index_list=[84 + 2**31, 2**31, 10 + 2**31, 0]
        )
        gen = self.wallet.address_generator(node=acct10_external_chain)
        self.assertEqual(
            next(gen),
            ("m/84'/0'/10'/0/0", 'bc1qy57hege5tn2q95372e90jgnd6d8v6j7k4k67dm')
        )
        self.assertEqual(
            gen.send(5),
            ("m/84'/0'/10'/0/5", "bc1quu2q4g4cz52vgjx2d9t5t09tzn5k7sxgtxngnp")
        )
        self.assertEqual(
            gen.send(10),
            ("m/84'/0'/10'/0/15", "bc1qu20h7yqpn4fp2rnzmdye8knm35wa33wes4r4rz")
        )
        self.assertEqual(
            next(gen),
            ("m/84'/0'/10'/0/16", "bc1qlpaqw9shedqtf57wz4g696ra4msk9rq6f5yadg")
        )

        acct100_external_chain = self.wallet.master.derive_path(
            index_list=[49 + 2 ** 31, 2 ** 31, 99 + 2 ** 31, 0]
        )
        gen = self.wallet.address_generator(
            node=acct100_external_chain,
            addr_fnc=self.wallet.p2sh_p2wpkh_address
        )
        self.assertEqual(
            next(gen),
            ("m/49'/0'/99'/0/0", '3MvGtrmTNaw5iNCpLksD7Dw1e8hL6YFspe')
        )
        self.assertEqual(
            gen.send(100),
            ("m/49'/0'/99'/0/100", "3MH37PPpk8cA131Xtq3JHC8b4fXQfh3bZV")
        )
        self.assertEqual(
            gen.send(400),
            ("m/49'/0'/99'/0/500", "34VDMVeQX8Vek7TsA9hLZxAugkYsEp2QNs")
        )
        self.assertEqual(
            next(gen),
            ("m/49'/0'/99'/0/501", "3KcHPAEtC4N7AQrMh5smmFw9hdSD68Wkt7")
        )

