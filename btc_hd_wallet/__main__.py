import os
import sys
import pathlib
import argparse
from argparse import ArgumentParser, Namespace
from typing import List, Tuple

from btc_hd_wallet.bip39 import CORRECT_MNEMONIC_LENGTH, CORRECT_ENTROPY_BITS
from btc_hd_wallet.paper_wallet import PaperWallet


def value_in_interval(value: str, min_: int, max_: int, name: str) -> int:
    """
    Checks whether value of name is in interval.
    Closed interval minimum open and open interval maximum [min, max)

    :param value: user provided value
    :param min_: required minimum
    :param max_: required maximum
    :param name: name of value
    :return: integer
    """
    value = int(value)
    if min_ <= value < max_:
        return value
    raise argparse.ArgumentError(
        argument=None,
        message="{} has to be between {} inclusive and {}".format(
            name,
            min_,
            max_
        )
    )


def address_index(value: str) -> int:
    # BIP44 -> address index is not hardened so our max is whole range
    name = "Address index"
    min_address_index = 0
    max_address_index = (2 ** 32) - 1
    return value_in_interval(
        value=value,
        min_=min_address_index,
        max_=max_address_index,
        name=name
    )


def account_index(value: str) -> int:
    # BIP44 -> account index is hardened so our max is half the range
    name = "Account index"
    min_account_index = 0
    max_account_index = (2 ** 31) - 1
    return value_in_interval(
        value=value,
        min_=min_account_index,
        max_=max_account_index,
        name=name
    )


def extended_key(value: str) -> str:
    """
    Check whether extended key is 111 characters.

    :param value: extended key
    :return: extended key
    """
    if len(value) != 111:
        raise argparse.ArgumentError(
            argument=None,
            message="Extended key has to be 111 characters long"
        )
    return value


def mnemonic(value: str) -> str:
    """
    Check whether mnemonic is of correct length.

    :param value: mnemonic sentence string
    :return: mnemonic sentence
    """
    if len(value.split(" ")) not in CORRECT_MNEMONIC_LENGTH:
        raise argparse.ArgumentError(
            argument=None,
            message="Mnemonic sentence length has to be one of {}".format(
                ", ".join(str(i) for i in CORRECT_MNEMONIC_LENGTH)
            )
        )
    return value.strip()


def bip39_seed(value: str) -> str:
    """
    Checks whether BIP39 seed is 512 bites which is 64 bytes (128 characters).

    :param value: BIP39 seed string
    :return: BIP39 seed
    """
    if len(value) != 128:
        raise argparse.ArgumentError(
            argument=None,
            message="BIP39 seed has to be 64 bytes long - 128 characters"
        )
    return value


def entropy_hex(value: str) -> str:
    """
    Checks whether entropy hex has correct bit length.

    :param value: entropy hex string
    :return: entropy hex
    """
    if len(value) * 4 not in CORRECT_ENTROPY_BITS:
        raise argparse.ArgumentError(
            argument=None,
            message="Entropy hex has to have one of {} bit lengths".format(
                ", ".join(str(i) for i in CORRECT_ENTROPY_BITS)
            )
        )
    return value


def file_(value: str) -> str:
    """
    File related checks:
        1. fail if path exists
        2. fail if path is directory
        3. fail if parent directory is not writable

    :param value: file path
    :return: file path
    """
    error_msg = None
    path = pathlib.Path(value)
    if path.exists():
        error_msg = "File {} already exists".format(value)
    if path.is_dir():
        error_msg = "{} is directory".format(value)
    parent_dir_path = str(path.parent)
    if not os.access(parent_dir_path, os.W_OK):
        error_msg = "Parent directory {} not writable".format(parent_dir_path)
    if error_msg:
        raise argparse.ArgumentError(
            argument=None,
            message=error_msg
        )
    return value


def paranoia_mode(data: dict) -> dict:
    """
    Strips secret data (mnemonic, password, BIP85, private Keys)
    from wallet dict.

    :param data: source dictionary
    :return: stripped source dictionary
    """
    return {
        k: {
            "account_extended_keys": {
                "path": v["account_extended_keys"]["path"],
                "pub": v["account_extended_keys"]["pub"]
            },
            "groups": [group[:-1] for group in v["groups"]]
        }
        for k, v in data.items()
        if k in ["BIP44", "BIP49", "BIP84"]
    }


def parse_args(args: List[str]) -> Tuple[ArgumentParser, Namespace]:
    parser = argparse.ArgumentParser(
        description="Bitcoin paper wallet generator."
    )
    parser.add_argument(
        "-f", "--file", type=file_, required=False, help="save to FILE"
    )
    parser.add_argument(
        "--testnet", action="store_true", help="testnet network - default False"
    )
    parser.add_argument(
        "--paranoia", action="store_true",
        help=(
            "hide secret information from output "
            "(mnemonic, password, BIP85, private keys) - default False"
        )
    )
    parser.add_argument(
        "--account", type=account_index, default=0,
        help="account derivation index - default 0"
    )
    parser.add_argument(
        "--interval", nargs=2, type=address_index, default=[0, 20],
        metavar=("START", "END"),
        help="range of key pairs and addresses to generate - default [0-20]"
    )
    # new wallet
    subparsers = parser.add_subparsers(dest="command")
    parser_new_wallet = subparsers.add_parser(
        "new",
        help="create new wallet"
    )
    parser_new_wallet.add_argument(
        "--password", type=str, required=False, default="",
        help="optional BIP39 password"
    )
    parser_new_wallet.add_argument(
        "--mnemonic-len", type=int, required=False, default=24,
        choices=CORRECT_MNEMONIC_LENGTH,
        help="mnemonic sentence length"
    )

    # from extended key
    parser_from_master_xprv = subparsers.add_parser(
        "from-master-xprv",
        help="create wallet from extended key"
    )
    parser_from_master_xprv.add_argument(
        "master_xprv", type=extended_key, help="master extended private key"
    )

    # from mnemonic
    parser_from_mnemonic = subparsers.add_parser(
        "from-mnemonic",
        help="create wallet from mnemonic sentence"
    )
    parser_from_mnemonic.add_argument(
        "mnemonic", type=mnemonic, help="mnemonic sentence"
    )
    parser_from_mnemonic.add_argument(
        "--password", type=str, required=False, default="",
        help="optional BIP39 password"
    )

    # from bip39 seed
    parser_from_bip39_seed = subparsers.add_parser(
        "from-bip39-seed",
        help="create wallet from BIP39 seed hex"
    )
    parser_from_bip39_seed.add_argument(
        "seed_hex", type=bip39_seed, help="BIP39 seed hex"
    )

    # from entropy hex
    parser_from_entropy_hex = subparsers.add_parser(
        "from-entropy-hex",
        help="create wallet from entropy hex"
    )
    parser_from_entropy_hex.add_argument(
        "entropy_hex", type=entropy_hex, help="entropy hex"
    )
    parser_from_entropy_hex.add_argument(
        "--password", type=str, required=False, default="",
        help="optional BIP39 password"
    )
    return parser, parser.parse_args(args)


def main():
    parser, args = parse_args(sys.argv[1:])

    if args.command == "new":
        wallet = PaperWallet.new_wallet(
            mnemonic_length=args.mnemonic_len,
            password=args.password,
            testnet=args.testnet
        )
    elif args.command == "from-master-xprv":
        wallet = PaperWallet.from_extended_key(extended_key=args.master_xprv)
    elif args.command == "from-mnemonic":
        wallet = PaperWallet.from_mnemonic(
            mnemonic=args.mnemonic,
            password=args.password,
            testnet=args.testnet
        )
    elif args.command == "from-bip39-seed":
        wallet = PaperWallet.from_bip39_seed_hex(
            bip39_seed=args.seed_hex,
            testnet=args.testnet
        )
    elif args.command == "from-entropy-hex":
        wallet = PaperWallet.from_entropy_hex(
            entropy_hex=args.entropy_hex,
            password=args.password,
            testnet=args.testnet
        )
    else:
        wallet = None
        parser.print_help()
        parser.exit(status=1)

    data = wallet.generate(account=args.account, interval=args.interval)
    if args.paranoia:
        data = paranoia_mode(data=data)

    if args.file:
        wallet.export_wallet(file_path=args.file, data=data)
    else:
        wallet.pprint(data=data)


if __name__ == "__main__":
    main()
