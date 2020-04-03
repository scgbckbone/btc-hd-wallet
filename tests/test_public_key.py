import unittest
from keys import PublicKey, PrivateKey


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

    def test_address(self):
        data = [
            {
                "secret": 888 ** 3,
                "p2pkh": {
                    "main": {
                        "addr": '148dY81A9BmdpMhvYEVznrM45kWN32vSCN',
                        "data": {"compressed": True, "testnet": False}
                    },
                    "test": {
                        "addr": 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP',
                        "data": {"compressed": True, "testnet": True}
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
                        "data": {"compressed": False, "testnet": False}
                    },
                    "test": {
                        "addr": 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP',
                        "data": {"compressed": False, "testnet": True}
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
                        "data": {"compressed": False, "testnet": False}
                    },
                    "test": {
                        "addr": 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s',
                        "data": {"compressed": False, "testnet": True}
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
