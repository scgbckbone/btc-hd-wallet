import unittest
from bip32_hd_wallet import PrivKeyNode, bip32_seed_from_mnemonic
from helper import hash160, h160_to_p2wpkh_address


class TestBip84(unittest.TestCase):
    def test_vector_1(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        root_prv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
        root_pub = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(node.extended_public_key(version=0x04b24746), root_pub)
        self.assertEqual(node.extended_private_key(version=0x04b2430c), root_prv)

        privkey = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"
        pubkey = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        # Account 0, first receiving address = m/84'/0'/0'/0/0
        child = node.derive_path(index_list=[84 + 2**31, 2**31, 2**31, 0, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

        privkey = "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy"
        pubkey = "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"
        address = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        # Account 0, second receiving address = m/84'/0'/0'/0/1
        child = node.derive_path(index_list=[84 + 2**31, 2**31, 2**31, 0, 1])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

        privkey = "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF"
        pubkey = "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6"
        address = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        # Account 0, first change address = m/84'/0'/0'/1/0
        child = node.derive_path(index_list=[84 + 2**31, 2**31, 2**31, 1, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

    def test_vector_2(self):
        mnemonic = "banner list crush drill oxygen grit donate chair expect cloud artist window dignity company salad clinic follow drive narrow crater enlist tortoise stay rain"
        root_prv = "zprvAWgYBBk7JR8GkcWB8q5mgDpogpFeNqyVjpci1VHK6JYJnnihE2a6wqAJJevA6HXD58vzF74DHBrpAZPEQNrugy6y1ZocLGuR4fMbkVtQBYJ"
        root_pub = "zpub6jftahH18ngZy6aeErcn3MmYEr68nJhM73YJosgvee5Hfb3qmZtMVdUn9vmFPn81ZLTMwbC6b2zLcw17wGfg97jjZMYftosaCFee3wNg4ih"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic)
        )
        self.assertEqual(node.extended_public_key(version=0x04b24746), root_pub)
        self.assertEqual(node.extended_private_key(version=0x04b2430c), root_prv)

        privkey = "KwPVPXy7HXg7h575VFENH8VEZedSNKmVEww9SBwVcY97oWf4iXZb"
        pubkey = "027b2dedd385c39132883a9ee31a4176fc7951a3ce61bfa9138c3eb9f818391b74"
        address = "bc1q0xc3z0qkux40884uqzan8ny4hmth4srl9fm5f3"
        # Account 0, first receiving address = m/84'/0'/0'/0/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

        privkey = "L3XXZ8mcJ4j2E39T6CC9GSk4coPKH6srRn9sGdj9UJahRfUasqNk"
        pubkey = "024c128fbc3d35d13de68fc6d641dd9a3f220117d2565546aeb9051c9f37617d14"
        address = "bc1qzhrav6ktxvgyet00uup8pw7lwr7s2p9z4p5uar"
        # Account 0, second receiving address = m/84'/0'/0'/0/1
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

        privkey = "L1tEGjKn8oCY5ZoAQFo9PQk9ttcidcV5qkwXsMZfum13LFizmdoQ"
        pubkey = "039d576e00f67c7953776d8bbd3f2f82b8eb139ab1251e284efb143a136be6c57b"
        address = "bc1qsr3a7v4cmnakvharlacssz034vjrqw8sd03cp9"
        # Account 0, first change address = m/84'/0'/0'/1/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec())),
            address
        )

    def test_vector_3(self):
        mnemonic = "alone process notice pool egg gift foster session code bright service change"
        root_prv = "vprv9DMUxX4ShgxMMf69wwuvPuDoLNQec5t9WDkURn5kzoDMia4gd8ZuJEmVvSnJZSWtYeKtFto2SPDBWQg6ShkRBdza5DpbrrNtjVdnHnscZaa"
        root_pub = "vpub5SLqN2bLY4Wea9Ad3ySvm3AXtQF91YbzsSg5EAVNZ8kLbNPqAft9r35ymifdRaDHzhqi3bQ3fWtbDLV6aUVVHzCmErvLYkA6uc8MxA88EDm"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(node.extended_public_key(version=0x045f1cf6), root_pub)
        self.assertEqual(node.extended_private_key(version=0x045f18bc), root_prv)

        privkey = "cUoZgoxZFeYqzs8iFaH7ENTb9NRVYNYYR9RT9s8EQdsiEN6miTna"
        pubkey = "02cbe61535f7b1730e0ca98ad845dbd3a3f79401104fc388971e32124b606cfb2c"
        address = "tb1qpfz8s3yzkph276vh0k3l72apgg5g4ptrvas0sf"
        # Account 0, first receiving address = m/84'/1'/0'/0/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

        privkey = "cSCJB57PH4DwNnNKkJabyJzAwG2kgwyP7RtVWXHnCcccHV9jBVpf"
        pubkey = "03a4495d811eb515cd047a304cb74708e7e9dc8d53359465f9c23a9bbb131b015b"
        address = "tb1q95pfzgslydz9mhl6ngjv74u5k74zg98ntc5ghe"
        # Account 0, second receiving address = m/84'/1'/0'/0/1
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

        privkey = "cV5iKGZAXmHJrb52DqiwaGvrFQboMBtu1yiR4uRGPApwTgq7jPu6"
        pubkey = "0348649e2c2623e62d7cbab33d02d15615528e31a09ea350ede98ba706ab72dc1a"
        address = "tb1qt52wa6r76n4evqps6a9wt30lh26ylpgnmddu6g"
        # Account 0, first change address = m/84'/0'/0'/1/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

    def test_vector_4(self):
        mnemonic = "fence test aunt appear calm supreme february fortune dog lunch dose volume envelope path must will vanish indicate switch click brush boy negative skate"
        root_prv = "vprv9DMUxX4ShgxMKyN621zFC9uyEyEPAngB2HEGpgzkhk99Bc313S6xi8ZdKf3nvk62wRFcCftLZnSovSNMMAmXra2vCmK52uikediy1Pspu3D"
        root_pub = "vpub5SLqN2bLY4WeYTSZ83XFZHrho14saFQ2PW9sd5QNG5g84QN9ayRDFvt7AvVCq9JDXJnsXhhn6Zh92fy3dExzMp2JTLpcD5P4mjPNHjHLNCa"
        node = PrivKeyNode.master_key(
            bip32_seed=bip32_seed_from_mnemonic(mnemonic=mnemonic),
            testnet=True
        )
        self.assertEqual(node.extended_public_key(version=0x045f1cf6), root_pub)
        self.assertEqual(node.extended_private_key(version=0x045f18bc), root_prv)

        privkey = "cNFqn4Rr13V6mgTArc274BoD4PFMnPDpK18ZF7Q9DjvFvGViJK2J"
        pubkey = "02b70bae290aa611cf617b6349869f9615c7afb92dc1deb6108178e3f291dd68a8"
        address = "tb1q83lcrth7dgl0fld22t0vkpa5wcejge7ja0nq4y"
        # Account 0, first receiving address = m/84'/1'/0'/0/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

        privkey = "cRkhE4yszcvpQFtjNc3t74268fbJf7EPtYLCTWstJU536GN1XPXG"
        pubkey = "03469b9a1520a0e9eb29879bc3c4c0e983991a2fa183535d2d2f0bc0007d1d3895"
        address = "tb1qtg7x8s5tfxjtrj476549p779a349f3mjvvv75c"
        # Account 0, second receiving address = m/84'/1'/0'/0/1
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 0, 1])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

        privkey = "cQi6GaKDy3StULmYnV3QvRRoLxCgNuwE3hsLRLUhN3R5pJtMu9U5"
        pubkey = "021b957ed3a3d15cd4083c415eb6ed7ea00d23d844d154ef950b5bcfcdf4c5766e"
        address = "tb1qtqtyxy2a6r2ulw468n9jzmqt2z8n9htkh7g3cp"
        # Account 0, first change address = m/84'/0'/0'/1/0
        child = node.derive_path(
            index_list=[84 + 2 ** 31, 1 + 2 ** 31, 2 ** 31, 1, 0])
        self.assertEqual(child.private_key.wif(testnet=True), privkey)
        self.assertEqual(child.public_key.sec().hex(), pubkey)
        self.assertEqual(
            h160_to_p2wpkh_address(hash160(child.public_key.sec()), testnet=True),
            address
        )

