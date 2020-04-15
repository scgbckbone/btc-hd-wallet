import csv
import unittest
from paper_wallet import PaperWallet


class TestColdWallet(unittest.TestCase):
    mnemonic = (
        "vast tell razor drip stick one engine action "
        "width sport else try scare phone blouse view "
        "program ketchup pole rapid use length student raven"
    )
    cold_wallet = PaperWallet(mnemonic=mnemonic)
    cold_wallet_testnet = PaperWallet(mnemonic=mnemonic, testnet=True)

    @staticmethod
    def load_csv_file(_file):
        with open(_file, "r") as f:
            csv_f = list(csv.reader(f, delimiter=','))
        return csv_f

    def test_from_entropy_hex(self):
        w = PaperWallet(entropy="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd")
        self.assertEqual(w, self.cold_wallet)
        w = PaperWallet(entropy="f1bbdacaa19d5b35529814fada5520f4fc0547060f9fabef3e9e58fefb0035dd", testnet=True)
        self.assertEqual(w, self.cold_wallet_testnet)

    def test_from_mnemonic(self):
        w = PaperWallet()
        self.assertEqual(w, PaperWallet.from_mnemonic(mnemonic=w.mnemonic))
        w = PaperWallet(entropy_bits=128)
        self.assertEqual(w, PaperWallet.from_mnemonic(mnemonic=w.mnemonic))

    def test_private_key_from_watch_only(self):
        xpub = "xpub6CEGxdGrXswtcL6Hqo1L3wwzDBuRzQvQfUa5PZponbX7ibNWUKkhp1LaNHMg9oJYjjRmbxArwDUjpudAvmNDRG8LGwYb9YvnkEfMY3eGdTP"
        w = PaperWallet.from_extended_key(extended_key=xpub)
        with self.assertRaises(ValueError):
            w.node_extended_private_key(node=w.master)

    def test_bip44(self):
        m44h0h0h0 = "xprvA1mabSEXaAzXuw9xhUB3J4p82KpeQoaYWWv7S2ZMiYc9oLUq3mSCe6pPxT1nhh1LAtx9Zb7vAk3Bx6ChXAwtZf32g7dWPGxLiSd3KyVGv4D"
        M44h0h0h0 = "xpub6EkvzwmRQYYq8RERoVi3fCkraMf8pGJPsjqiEQxyGt98g8oybJkTBu8soiUJM76gtQtGx1ZKU7y6CwbVFeCER3q95MVbNRquYCfyPLzbdpF"
        acct_ext_keys, wallet = self.cold_wallet.bip44()
        acct_ext_prv = "xprv9yEvZ7jxhWPbPr1pjmUKgp1FfA4waxCZJFeUbBRCEFz8qo3MvnSTGD26X2Xm12ABiGLaHgUkNt1M4MoqXHqvE9mMa8jUJx5QtNwsz7bLSBu"
        acct_ext_pub = "xpub6CEGxdGrXswtcL6Hqo1L3wwzDBuRzQvQfUa5PZponbX7ibNWUKkhp1LaNHMg9oJYjjRmbxArwDUjpudAvmNDRG8LGwYb9YvnkEfMY3eGdTP"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip44_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m44h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip44(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M44h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip44(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            # paths differ -> as imported key is treated as root
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            # private key - last element in the list - is None --> watch only
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip49(self):
        m49h0h0h0 = "yprvAKVruDeCuwumJdxruoUR3f8jQhqumzuQiF7oZknYNEZbFSzYweJFJ2oSfKLj2MNvhr5xzK2iiyQyLjtrLXUVRvVAKQbW197f48rFtHTQi29"
        M49h0h0h0 = "ypub6YVDJjB6kKU4X83L1q1RQo5TxjgQBTdG5U3QN9C9va6a8FKhVBcVqq7vWayS3iDNdKj9siFtDuhjJ9KJatTFjtiZ9HLEbhYBeRz7TsKmmz1"
        acct_ext_keys, wallet = self.cold_wallet.bip49()
        acct_ext_prv = "yprvAHpZYMRQJE2joxtkfFFNH2ur4VAmEpdst8odf8UoYmAd1Fisi51fWpKcYwH5SXYzfpTmHks9vQg3JmmhcJw9qBze8BSwvFLPF8HG2oKxWi3"
        acct_ext_pub = "ypub6WouwrxJ8bb32SyDmGnNeAracX1FeHMjFMjETWtR76hbt442FcKv4ce6QEDWjQHEr5kr9fGziGETGgvLYayVGSWKLJGNuQahEoMBVDaEYsZ"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip49_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m49h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip49(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M49h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip49(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip84(self):
        m84h0h0h0 = "zprvAeUnGUuaxCMJRxeYeKBtSABd2VcK7QNVxzETexpoAr9htSeXgGDcd6ooD7umSXuvSCuFSp3NM82x26da1Sh72tBi3FiEc4HMmpkoJd423DF"
        M84h0h0h0 = "zpub6sU8fzSUnZubeSj1kLitoJ8MaXSoWs6MLDA4TMEQjBggmEygDoXsAu8H4Qk5mvh4qL6QCi97z7EmAytC7CZe1q2Z6HnMje2ibgEctsit7zV"
        acct_ext_keys, wallet = self.cold_wallet.bip84()
        acct_ext_prv = "zprvAdkP2X3WyRxRZhUQDCuGfhBboKqnJ34yRKZY7YYmQUMRnfmDeLLnJNATupocnLZiUKuDJmjKtb8iZNSvixfXurRRgsqv53YtSivXN3soPeQ"
        acct_ext_pub = "zpub6rjjS2aQooWinBYsKESH2q8LMMgGhVnpnYV8uvxNxotQfU6NBsf2rAUwm7AtMfBkVywW7baLLKcQ5CZ2vfGCCSpQ8gb2F9rkNUuEnFKmobk"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip84_vast_tell_razor_drip_stick_one_engine"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m84h0h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip84(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M84h0h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip84(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip44_testnet(self):
        m44h1h0h0 = "tprv8htjzxdtooRZnSeSzKZX1s1Ln4VxCpawvMXhiHsHy7knBtRvty8YLkzuUqoRKQa8kngdtyUNYhEdE5wtywK45XDn1QXcWJ4sZRviQTVbgJP"
        M44h1h0h0 = "tpubDEan9Ng8xB7EfugEsyE7RGfTM61tN9mrVf8UzoubPPZB2NghXMx8XFcmexNZRUCQ5iZXMbYGtJAbgKW8rpcrSvscgFv1cJxqixRrkdjufFV"
        node_m44h1h0h0 = self.cold_wallet_testnet.by_path(path="m/44'/1'/0'/0")
        self.assertEqual(node_m44h1h0h0.extended_private_key(), m44h1h0h0)
        self.assertEqual(node_m44h1h0h0.extended_public_key(), M44h1h0h0)
        acct_ext_keys, wallet = self.cold_wallet_testnet.bip44()
        acct_ext_prv = "tprv8h8nHUbrfPw4o9Kz9vxAvT5xbjCXP97huSD84TWFNfFBcUY5HnTEmPYNXAtCSidHEAhnpCVuyN9R1oURGX6aVHKHdgQcKxrQ3tJVfgeGbSZ"
        acct_ext_pub = "tpubDDppRte6omcjgcMn3acmKrk5AkiTYUJcUjouLyYYnw3aSxnqvBGpwtAEhJHm14fyqYMdm9pRuoxCRHzwaSaUWRXdi6QKQhoQ4HKZ2uNgRnJ"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip44_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m44h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip44(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M44h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip44(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            # paths differ -> as imported key is treated as root
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            # private key - last element in the list - is None --> watch only
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip49_testnet(self):
        m49h1h0h0 = "uprv92pZMtfPEtUTs1XYUGr3HATLzbz5GT6Ta9ikE7PcsUKaRaGEVDJLXSRjfVwwh2TooCEYsFFtXEan9reH7hwXFokaLLir5fEp1Ju6e1zW5mg"
        M49h1h0h0 = "upub5FoumQCH5G2m5Vc1aJP3eJQ5YdpZfupJwNeM2VoERorZJNbP2kcb5EkDWor7CCFSnmYhXGu47xRfhxZ1dBc9H3ssrCMaJpdNzSkk2X8Kz6m"
        acct_ext_keys, wallet = self.cold_wallet_testnet.bip49()
        acct_ext_prv = "uprv8zU71PBiC3U2AiafSLZJc9EujTA3kwiHU9XeTdhru8GxHmuayCgRYG9xEGMuFfjVC1vZ2jk4LbhvU94AYv8S2J8JUNJzWqye9Z742ep8hKv"
        acct_ext_pub = "upub5DTTQtic2R2KPCf8YN6JyHBeHUzYAQS8qNTFG27UTTowAaEjWjzg64US5Zrsip5sUtncanNNU4iYFy9Ten2rKhCi6QXNF7HZn5yrg21LRz7"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip49_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m49h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip49(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M49h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip49(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_bip84_testnet(self):
        m84h1h0h0 = "vprv9N1iPx69wSwyn7tHjf3E5e7fGyXGBst9ZHe96k8UnPJtVLyNyaFkNptLAYf8UST9nWT8T42p3ogH7YBGD69PvggXib3wnLCpS6h1eFZMFDD"
        M84h1h0h0 = "vpub5b14oTd3mpWGzbxkqgaESn4Pq1MkbLbzvWZju8Y6LiqsN9JXX7ZzvdCp1qDDxLqeHGr6BUssz2yFmUDm5Fp9jTdz4madyxK6mwgsCvYdK5S"
        acct_ext_keys, wallet = self.cold_wallet_testnet.bip84()
        acct_ext_prv = "vprv9LFibgTtfNsNtNY47JxpcD2m1WqVwiJqaFms8t14LjNtuqP1inE6yy4h7pBLGKDa33qURi2oxHMvrekZPzfrLDFNukmE3gQ2n7ryyyzdsXz"
        acct_ext_pub = "vpub5ZF51BznVkRg6rcXDLVpyLyVZYfzMB2gwUhTwGQfu4usndiAGKYMXmPAy7vKUJx2g6BNaeehHn93Z4fNH63sNUWQyKjb8Cx7GD3QJPsaEz7"
        self.assertEqual(acct_ext_prv, acct_ext_keys["prv"])
        self.assertEqual(acct_ext_pub, acct_ext_keys["pub"])
        csv_f = self.load_csv_file(
            _file="tests/data/bip84_vast_tell_razor_drip_stick_one_engine-testnet"
        )
        wallet0 = PaperWallet.from_extended_key(extended_key=m84h1h0h0)
        self.assertFalse(wallet0.watch_only)
        wallet0 = wallet0._bip84(children=wallet0.master.generate_children())

        wallet1 = PaperWallet.from_extended_key(extended_key=M84h1h0h0)
        self.assertTrue(wallet1.watch_only)
        wallet1 = wallet1._bip84(children=wallet1.master.generate_children())

        self.assertEqual(len(wallet), len(csv_f))
        self.assertEqual(len(wallet0), len(csv_f))
        self.assertEqual(len(wallet1), len(csv_f))
        for i in range(len(wallet)):
            self.assertEqual(wallet[i], csv_f[i])
            self.assertEqual(wallet0[i][1:], csv_f[i][1:])
            self.assertEqual(wallet1[i][1:-1], csv_f[i][1:-1])

    def test_generate_mainnet(self):
        pw = self.cold_wallet.generate(account=100)

        xpub = "xpub6CEGxdGrXswxydDQYESp5urwA35vxByZzHqgU5GZ3kMjeD9QkH2xx8kemZXMbxaQdjwFjgFVAADLooXS96m3mJmF5hZKTY2DPcCYdyA8Z5y"
        xprv = "xprv9yEvZ7jxhWPfm98wSCuoimvCc1FSYjFid4v5fgrwVQpkmQpGCjiiQLSAvJFgKxh3ak4Bcp9cjBE6PU1ub7f8UN9PKEEggRhipV7gXUWoVhf"
        ypub = "ypub6WouwrxJ8bb7QdjxPGNnEFGiPZeH1MxkxKTKtPhNwnedRLqxNv4Cm9jZCkGpPuKjEGWFnt7iA9zZBvqVAQHkDrFSapLxhBLMGUJHtct5CRP"
        yprv = "yprvAHpZYMRQJE2pC9fVHEqms7KyqXonbuEub6Xj61HmPT7eYYWoqNjxDMR5MU3VUWiV94Q6vt4YX85NfFx4X5ZNZPYaMLRcwRXrpt5Jn34icvs"
        zpub = "zpub6rjjS2aQooWoAWUtXrdfiNxz38iL9SxgMVo2W4SRhVMTrYnqkJ8oeTF951rcKriKKFdEKDcFFMZMMBspF257wQmQhDR6yjufpqFXJKr4e1m"
        zprv = "zprvAdkP2X3WyRxVx2QRRq6fMF2FV6sqjzEpzGsRhg2p99pUykThCkpZ6evfDi62aycv5soGZq25vd1puNSeju96NPzCtdrUAzX4xaGDTK7buQn"

        self.assertEqual(pw["bip44"]["account_extended_keys"]["pub"], xpub)
        self.assertEqual(pw["bip44"]["account_extended_keys"]["prv"], xprv)
        self.assertEqual(pw["bip49"]["account_extended_keys"]["pub"], ypub)
        self.assertEqual(pw["bip49"]["account_extended_keys"]["prv"], yprv)
        self.assertEqual(pw["bip84"]["account_extended_keys"]["pub"], zpub)
        self.assertEqual(pw["bip84"]["account_extended_keys"]["prv"], zprv)

        address = "13UkPjRAmH1sDWuoX1zeL8yCFWXdwPvGAE"
        pubkey = "03597d9a56c46c0e6e1827525bb517c5a8dfe21ace626f31a2e11c4e4e23cd353e"
        wif = "L5nBbbswFNu8wWP9VZY66Up4X3yNX7mcfArDHRQ5onMZhGC3qBZH"
        self.assertEqual(pw["bip44"]["triads"][19][1], address)
        self.assertEqual(pw["bip44"]["triads"][19][2], pubkey)
        self.assertEqual(pw["bip44"]["triads"][19][3], wif)

        address = "3EGt757gbPFn1z5uvrUMhTcwKmxK78jsvC"
        pubkey = "020a0aff849f9addb615ef67ada2dfddbc59c377ab5668f2713bb379cc9d0f287b"
        wif = "L2PRabCy4qhKJTYkbcA6MEm2hC6DyPqSFj7jsCvNpHkU8DpmDWJR"
        self.assertEqual(pw["bip49"]["triads"][19][1], address)
        self.assertEqual(pw["bip49"]["triads"][19][2], pubkey)
        self.assertEqual(pw["bip49"]["triads"][19][3], wif)

        address = "bc1q9gxcsd5wmdrg5909628kx96384h0w5dyyj82gz"
        pubkey = "03c66906128c24b82babeaea82205c10b0eeb09413da198ed8aa1337b82ac0d028"
        wif = "KzyLyHiys138p2EY4fPCV9JZfz6wVE4x6DeMg9HGM9eaXQkRENtF"
        self.assertEqual(pw["bip84"]["triads"][19][1], address)
        self.assertEqual(pw["bip84"]["triads"][19][2], pubkey)
        self.assertEqual(pw["bip84"]["triads"][19][3], wif)

    def test_generate_testnet(self):
        pw = self.cold_wallet_testnet.generate(account=66, interval=(0, 50))

        tpub = "tpubDDppRte6omcnc4M1W9frHBgnet6YyZoLrkSZhFZVJNnBA8EfEhrcoq2UQgPupd8DbJFm7sgi7y18ZtfGfTPas6DBcSjk9Pi2P7GDeZfegFx"
        tprv = "tprv8h8nHUbrfPw7ibKDcW1Fsn2g5racpEcSHSqnQjXBt6ynKdytcK32dLQcEYh328MGXeeSS2gGsQAioy84N1mfVN4K2rLgWATgWbGiAdcorBV"
        upub = "upub5DTTQtic2R2NHjnjkn6ZeaaQdxFF3uqnQVXAJsFpnEAHziiTeTFWfXUfaYQzk8cA7pnhpNsUUpgXY4KZ1NWqvyKYf8aQvwDQj3k8qYipjSg"
        uprv = "uprv8zU71PBiC3U55FiGekZZHSdg5vQkeT7w3GbZWUrDDtdK7vPK6uwG7jABjGVVqUBPjG3Z9JYzNGzW73Te5KtySwpvsWuUnA2TA5YpTUuZZ5u"
        vpub = "vpub5ZF51BznVkRj1LC7XDbJDJT1vNwpbWhx4p3Y1m1UpMhho5SPg4v7PLNatXNQ1dggtSyJoRN9tKsoXcJZamEai1dmy1wurF1rJbZAFBxqht4"
        vprv = "vprv9LFibgTtfNsRnr7eRC4HrAWHNM7LC3z6hb7wDNbsG2AivH7F8XbrqY473HJhZJ45d9waTjewHxRixpQsL7RceZwZ5dNkoJ4yNyEMNXowdoa"

        self.assertEqual(pw["bip44"]["account_extended_keys"]["pub"], tpub)
        self.assertEqual(pw["bip44"]["account_extended_keys"]["prv"], tprv)
        self.assertEqual(pw["bip49"]["account_extended_keys"]["pub"], upub)
        self.assertEqual(pw["bip49"]["account_extended_keys"]["prv"], uprv)
        self.assertEqual(pw["bip84"]["account_extended_keys"]["pub"], vpub)
        self.assertEqual(pw["bip84"]["account_extended_keys"]["prv"], vprv)

        address = "mjXHL5oujxymKFdRUpLbAxFGU9ZaGvhPQ4"
        pubkey = "03b0829cd964a0e1e716fae3bb83812087825d5aca3f102670d8449312ee5b6647"
        wif = "cUbsTivUmb1dcpGwbRMsCznmwLZMuT85akmScPtwEhco4EQ9xDtD"
        self.assertEqual(pw["bip44"]["triads"][49][1], address)
        self.assertEqual(pw["bip44"]["triads"][49][2], pubkey)
        self.assertEqual(pw["bip44"]["triads"][49][3], wif)

        address = "2N6yVCdJu6Z3o3mUQfQizeVi1yNYEXwYEVe"
        pubkey = "02e10c0eddc2456720e337359948204f5cdc0ca05da6a3b5ac48580316e7fc9278"
        wif = "cSDgEWgZxSHJq36H6ou4jwnEG14Qdx7QwdMvvgLREdE932DFbwT2"
        self.assertEqual(pw["bip49"]["triads"][49][1], address)
        self.assertEqual(pw["bip49"]["triads"][49][2], pubkey)
        self.assertEqual(pw["bip49"]["triads"][49][3], wif)

        address = "tb1q8fa5tlqsvs38knnn79y8lzduy7lznvhv74mvfs"
        pubkey = "03897e1a34923b60cf6ff25c60bc94fef9519c8e7f90fe7ce3db9faa9d9fd6cb22"
        wif = "cUpJB4hmzFgQL4oo33td3FYmGy3CatxWyPkSGtdrS4kfRRgPsqK9"
        self.assertEqual(pw["bip84"]["triads"][49][1], address)
        self.assertEqual(pw["bip84"]["triads"][49][2], pubkey)
        self.assertEqual(pw["bip84"]["triads"][49][3], wif)

