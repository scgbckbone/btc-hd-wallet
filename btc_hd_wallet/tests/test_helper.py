import unittest
from io import BytesIO

from btc_hd_wallet.helper import (
    little_endian_to_int, int_to_little_endian, encode_base58_checksum,
    b58decode_addr, h160_to_p2pkh_address, h160_to_p2sh_address, merkle_root,
    merkle_parent, merkle_parent_level, big_endian_to_int, int_to_big_endian,
    encode_varint, read_varint
)


class HelperTest(unittest.TestCase):

    def test_little_endian_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 8), want)

    def test_big_endian_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 11079866634028974080
        self.assertEqual(big_endian_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 11616453601446068224
        self.assertEqual(big_endian_to_int(h), want)

    def test_int_to_big_endian(self):
        n = 1
        want = b'\x00\x00\x00\x01'
        self.assertEqual(int_to_big_endian(n, 4), want)
        n = 10011545
        want = b'\x00\x00\x00\x00\x00\x98\xc3\x99'
        self.assertEqual(int_to_big_endian(n, 8), want)

    def test_encode_varint(self):
        with self.assertRaises(ValueError):
            encode_varint(18446744073709551616)
        self.assertEqual(
            encode_varint(1152921504606846976),
            b'\xff\x00\x00\x00\x00\x00\x00\x00\x10'
        )
        self.assertEqual(encode_varint(268435456), b'\xfe\x00\x00\x00\x10')
        self.assertEqual(encode_varint(4096), b'\xfd\x00\x10')
        self.assertEqual(encode_varint(252), b'\xfc')
        self.assertEqual(encode_varint(1), b'\x01')

    def test_read_varint(self):
        self.assertEqual(
            read_varint(BytesIO(b'\xff\x00\x00\x00\x00\x00\x00\x00\x10')),
            1152921504606846976
        )
        self.assertEqual(read_varint(BytesIO(b'\xfe\x00\x00\x00\x10')), 268435456)
        self.assertEqual(read_varint(BytesIO(b'\xfd\x00\x10')), 4096)
        self.assertEqual(read_varint(BytesIO(b'\xfc')), 252)
        self.assertEqual(read_varint(BytesIO(b'\x01')), 1)

    def test_base58_invalid_checksum(self):
        with self.assertRaises(ValueError):
            b58decode_addr(s="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")

    def test_base58_invalid_char(self):
        with self.assertRaises(ValueError):
            b58decode_addr(s="1A1zP1eP5QGefi2DlPTfTL5SLmv7DivfNb")

    def test_address_base58_decode_testnet(self):
        data = [
            (
                b"\x6f",
                "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf",
                "507b27411ccf7f16f10297de6cef3f291623eddf",
            ),
            (
                b"\x6f",
                "n337594KZxc8CdCH8EzH4zkpqcQCSWwLUv",
                "ec0e72801d338d8bf3485addd59701d089d84019"
            ),
            (
                b"\xc4",
                "2MxZwbBQsdeF4RJj4pDeMav6KgkkcVdkUt7",
                "3a62d7f2da01f5baa5da704275ee849669b13300"
            ),
            (
                b"\xc4",
                "2NDMpG6PP1ka6h9VaEw8hfk6XE2qxBa2Knm",
                "dca19ee9e64d8479c094da2c9fc830e5898254c7"
            ),
            (
                b"\x00",
                "1GbU5hVBc2kKdiW7uMYGqaXM9GJc7ysSBJ",
                "ab0ea2b2a3fef9dd85d399380d698f647685f7ec",
            ),
            (
                b"\x05",
                "371LHnv92VQLHdkkbALU9CLzLzikAaXCJJ",
                "3a4f729c13c3af6853a1a758d95708ece0859381"
            )
        ]
        for prefix, address, h160_hex_target in data:
            h160 = b58decode_addr(address).hex()
            self.assertEqual(h160, h160_hex_target)
            got = encode_base58_checksum(prefix + bytes.fromhex(h160))
            self.assertEqual(got, address)

    def test_p2pkh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=False), want)
        want = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=True), want)

    def test_p2sh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=False), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=True), want)

    def test_merkle_parent(self):
        tx_hash0 = bytes.fromhex(
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        tx_hash1 = bytes.fromhex(
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        want = bytes.fromhex(
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
        self.assertEqual(merkle_parent(tx_hash0, tx_hash1), want)

    def test_merkle_parent_level(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
            '1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10',
        ]
        want_tx_hashes = [bytes.fromhex(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_parent_level_failure(self):
        hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd'
        ]
        hashes = [bytes.fromhex(h) for h in hashes]
        with self.assertRaises(ValueError):
            merkle_parent_level(hashes=hashes)

    def test_merkle_root(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hash = 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6'
        want_hash = bytes.fromhex(want_hex_hash)
        self.assertEqual(merkle_root(tx_hashes), want_hash)
