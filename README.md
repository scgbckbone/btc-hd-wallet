# Installation
1. install python3.6 or higher for your OS
2. [install](https://www.linode.com/docs/development/version-control/how-to-install-git-on-linux-mac-and-windows/) git 
3. install btc_hd_wallet:

a.) via pypi 
`pip install btc_hd_wallet`

b.) from source
```shell script
# clone btc-hd-wallet repository
git clone https://github.com/scgbckbone/btc-hd-wallet.git
# change directory to project root
cd btc-hd-wallet
# create virtual environment
python3 -m venv btc-hd-wallet
# activate virtual environment
source btc-hd-wallet/bin/activate
# upgrade pip, setuptools and wheel (optional)
pip install -U pip setuptools wheel
# install project
python setup.py install
# run unittests (optional)
python setup.py test
# to run test without setup - run below command in project root (btc-hd-wallet)
python -m unittest -v
```

# CLI
Command line interface provides functions for generating paper wallets and saving
them into a file.

##### General help message
```shell script
python -m btc_hd_wallet --help
```
```text
usage: __main__.py [-h] [-f FILE] [--testnet] [--paranoia] [--account ACCOUNT]
                   [--interval START END]
                   {new,from-master-xprv,from-mnemonic,from-bip39-seed,from-entropy-hex}
                   ...

Bitcoin paper wallet generator.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  save to FILE
  --testnet             testnet network - default False
  --paranoia            hide secret information from output (mnemonic,
                        password, BIP85, private keys) - default False
  --account ACCOUNT     account derivation index - default 0
  --interval START END  range of key pairs and addresses to generate - default
                        [0-20]

commands:
  {new,from-master-xprv,from-mnemonic,from-bip39-seed,from-entropy-hex}
    new                 create new wallet
    from-master-xprv    create wallet from extended key
    from-mnemonic       create wallet from mnemonic sentence
    from-bip39-seed     create wallet from BIP39 seed hex
    from-entropy-hex    create wallet from entropy hex
```
##### Subcommand help messages
* new
```shell script
python -m btc_hd_wallet new --help
```
```text
usage: __main__.py new [-h] [--password PASSWORD]
                       [--mnemonic-len {12,15,18,21,24}]

optional arguments:
  -h, --help            show this help message and exit
  --password PASSWORD   optional BIP39 password
  --mnemonic-len {12,15,18,21,24}
                        mnemonic sentence length
```
* from-master-xprv
```shell script
python -m btc_hd_wallet from-master-xprv --help
```
```text
usage: __main__.py from-master-xprv [-h] master_xprv

positional arguments:
  master_xprv  master extended private key

optional arguments:
  -h, --help   show this help message and exit
```
* from-mnemonic
```shell script
python -m btc_hd_wallet from-mnemonic --help
```
```text
usage: __main__.py from-mnemonic [-h] [--password PASSWORD] mnemonic

positional arguments:
  mnemonic             mnemonic sentence

optional arguments:
  -h, --help           show this help message and exit
  --password PASSWORD  optional BIP39 password
```
* from-bip39-seed
```shell script
python -m btc_hd_wallet from-bip39-seed --help
```
```text
usage: __main__.py from-bip39-seed [-h] seed_hex

positional arguments:
  seed_hex    BIP39 seed hex

optional arguments:
  -h, --help  show this help message and exit
```
* from-entropy-hex
```shell script
python -m btc_hd_wallet from-entropy-hex --help
```
```text
usage: __main__.py from-entropy-hex [-h] [--password PASSWORD] entropy_hex

positional arguments:
  entropy_hex          entropy hex

optional arguments:
  -h, --help           show this help message and exit
  --password PASSWORD  optional BIP39 password
```

# API
##### Base Wallet
```python3
from btc_hd_wallet import BaseWallet

# many ways how to initialize BaseWallet object
# 1. totally new wallet
# this will generate new mainnet wallet with 24 words mnemonic
w = BaseWallet.new_wallet()

# you can also generate testnet wallet with different length mnemonic
w = BaseWallet.new_wallet(mnemonic_length=12, testnet=True)
assert len(w.mnemonic.split(" ")) == 12 and w.testnet

# you can also secure your wallet with optional passphrase
w = BaseWallet.new_wallet(mnemonic_length=18, password="optional_secret_pwd")
assert len(w.mnemonic.split(" ")) == 18 and not w.testnet and w.password == "optional_secret_pwd"

# 2. from entropy hex string 
w = BaseWallet.from_entropy_hex(
    entropy_hex="064338c5a50fcf96436142e164e005be3d0a51cb7bcc6050a6d0798e863c5b44"
)

# testnet with password
w = BaseWallet.from_entropy_hex(
    entropy_hex="1e0479633a5c856b88a78b1977d3c214",
    password="optional_super_secret_password",
    testnet=True
)

# 3. from bip39 seed hex
w = BaseWallet.from_bip39_seed_hex(
    bip39_seed="353cc8f20663196c2181b462e5d5d1a62192521b7604a578f87a3224a7ea9df91925c7e5b399094d996a2951acb1a95eba44b8293a5218bb6d964ba1def5f501",
    testnet=True
)
assert w.mnemonic is None and w.password is None

# 4. from mnemonic
w = BaseWallet.from_mnemonic(
    mnemonic="bulk cat flee input sign remind card vapor bonus salon vacuum cinnamon",
    password="optional_secret_pwd",
    testnet=False
)

# 5. from extended key
w = BaseWallet.from_extended_key(
    extended_key="xprv9s21ZrQH143K2n9ryKS5EXxvQaNSbCxrVHSUigxG9ywY6GVQYsrk6n8e9j6m9z9LvBULFnSyjcLFxbG6WtXoeYRF19f1FY23nni39XSLPWm"
)

# here you can also create watch only wallet from extended pub key
# for instance: generate wallet offline, derive external chain extended pub key
ew = BaseWallet.from_extended_key(
    extended_key="xpub6BvTr9tVPEDEDQ12sR7Ty4tVGnNGfDEeDg7dgmNkYzr3QXLS9amBxYHWRBbCJ2uD1RpVXZNkqXji2u3YE1bKxR7g6TUpxxB7C3Cx76i6wHL"
)
# this will pass just fine as wallet loaded from extended public key is watch only
assert ew.watch_only == True 

# 'ew' represents wallet which has as its master key external chain of 
# hundredth account of bip84 purpose bitcoin mainnet wallet (m/84'/0'/100'/0) 
# create generator
bip84_gen = ew.address_generator(node=ew.master)

# generate addresses
next(bip84_gen)

# yields tuple of path and address 
> ("m/84'/0'/100'/0/0", "bc1qqv548euf07gx0h87d4sjczn65t8wnlv5jshp0z")
```

##### Paper Wallet
```python3
from btc_hd_wallet import PaperWallet
w = PaperWallet.new_wallet()

# to display paper wallet in console
w.pprint()

# get python dictionary repsresentation of paper wallte
json_dct = w.generate()

# get json serialized string representation of paper wallet
json_str = w.json(indent=4)

# wasabi import file format (inspired by ColdCard)
file_path = "/home/john/wasabi0.json"
w.export_wasabi(file_path=file_path)
```

##### Private and Public keys
```python3
from btc_hd_wallet import PrivateKey, PublicKey

# initialize private key object from secret exponent
sk = PrivateKey(sec_exp=61513215313213513843213)

# from wif format
sk = PrivateKey.from_wif("KxNH4NuQoDJjA9LwvHXn5KBTDPSG9YeoA7RBed2LwLRNqd1Tc4Wv")

# from byte sequence
sk = PrivateKey.parse(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15&X\xc0\xe3\xee\\\r$bU\x18')

# secret exponent
secret_exponent = sk.sec_exp
# to wif
wif_str = sk.wif(testnet=False)
# to bytes
sk_bytes = bytes(sk)


# to access corresponding public key
pk = sk.K

# RIPEMD160(SHA256) of public key
h160 = pk.h160()

# p2pkh testnet address
p2pkh = pk.address(addr_type="p2pkh", testnet=True) 

# p2wpkh address (p2wpkh is default 'addr_type')
p2wpkh = pk.address()

# SEC encoding (bytes)
sec = pk.sec()

# elliptic curve point
point = pk.point

# public key can also be parsed from sec
sec_str = "030975d7fc3e27bcb3d37dd83a84f5ae2f48cec392e781e35ec849142bcc6e2cce"
pk = PublicKey.parse(bytes.fromhex(sec_str))

# or from ecdsa Point or PointJacobi
pk = PublicKey.from_point(point)
```

##### Bip39 related methods
```python3
from btc_hd_wallet import (
    bip39_seed_from_mnemonic, mnemonic_from_entropy_bits, mnemonic_from_entropy
)

# mnemonic from number of entropy bits (allowed entropy bits 128,160,192,224,256)
menmonic = mnemonic_from_entropy_bits(entropy_bits=256)

# mnemonic from entropy hex
mnemonic = mnemonic_from_entropy("0a84d45bb74a0d80c144f9ad765c3b9edc40a8dbb5c053c0930ef040992036d2")

# create bip39 seed from mnemonic
seed = bip39_seed_from_mnemonic(mnemonic=mnemonic)

# or with optional password
seed = bip39_seed_from_mnemonic(mnemonic=mnemonic, password="secret")
```

##### Script
```python3
from io import BytesIO
from btc_hd_wallet import BaseWallet
from btc_hd_wallet import (
    Script, p2wsh_script, p2wpkh_script, p2sh_script, p2pkh_script
)

# you can parse script hex
script_hex = "1976a9148ca70d5eda840e9fb5d38234ae948dfad1d266d788ac"
script = Script.parse(BytesIO(bytes.fromhex(script_hex)))
str(script)
> OP_DUP OP_HASH160 8ca70d5eda840e9fb5d38234ae948dfad1d266d7 OP_EQUALVERIFY OP_CHECKSIG

# script can be raw serialized
script.raw_serialize()

# or it can be serialized with length prepended
script.serialize()

# or creating script pubkeys from wallet
w = BaseWallet.new_wallet()
# derive some child node to use (I'll go with bip84)
node = w.by_path("m/84'/0'/100'/0/0")
hash160_pub_key = node.public_key.h160()
script = p2wpkh_script(hash160_pub_key)
str(script)
> OP_0 8ca70d5eda840e9fb5d38234ae948dfad1d266d7
```

##### Bip85
```python3
from btc_hd_wallet import BIP85DeterministicEntropy

xprv = "xprv9s21ZrQH143K2n9ryKS5EXxvQaNSbCxrVHSUigxG9ywY6GVQYsrk6n8e9j6m9z9LvBULFnSyjcLFxbG6WtXoeYRF19f1FY23nni39XSLPWm"
# create new deterministic entropy object from extended private key
bip85 = BIP85DeterministicEntropy.from_xprv(xprv=xprv)

# bip39 mnemonic
bip85.bip39_mnemonic(word_count=24, index=0)
> lift boost vague vanish occur stamp eagle twice kite pause sunny execute defy grocery mercy assist volume venture subject analyst fiscal lecture connect bunker
bip85.bip39_mnemonic(word_count=12, index=0)
> good brave hunt license deliver conduct more dutch donkey green skill gauge
bip85.bip39_mnemonic(word_count=15, index=1)
> vessel nerve buzz wife good ski sock walnut crew toward team vast dynamic parade candy

# wallet import format (WIF)
bip85.wif(index=0)
> 'KyxeP1pijLmtKZv8ry7d3tbNsq3XDeGgN99Mqi2Gn2Kx6WwPr2wC'
bip85.wif(index=1)
> 'KxsrnifkxsZTBeP52VxHzZGawyUSULBi1trHrJhU7ndQxkTXguFJ'

# extended private key (XPRV)
bip85.xprv(index=0)
> 'xprv9s21ZrQH143K2SrZ37WGmQ4TcqHbcAxy7tfuoVNZBxnd7huX6XuD2UZBUuXVfrZjjtw5X3B9JgUvoVegVALTeTXWsiUSK9F4FWXFZLfZVzV'
bip85.xprv(index=1)
> 'xprv9s21ZrQH143K4RPx2iS7FecFHCUiC4CA2x4PqY6rtqjgqpxqWNcTxK88oRDyiZf8WiTLA6GWwR7BSoFkjjNSEx4wAgGq7nnxukd2FJP7AKH'

# hex
bip85.hex(index=0)
> '78ebebfc701429f60ab4540168950c8fc9db5d275324545e7512f9e23b1fcd42'
bip85.hex(num_bytes=64, index=0)
> '2205163efb2ae4e78609b4a7410e9a4856f673b04dd0af7ce9851a9f2f7883c854f76a3e1cf639c217adde4956604dcdd853104dfcb93751856e3e13dcb9ab35'

# bip85 is also available in BaseWallet class as its attribute
from btc_hd_wallet.base_wallet import BaseWallet

w = BaseWallet.new_wallet()
type(w.bip85) == BIP85DeterministicEntropy
> True
```

# Documentation
Sphinx documentation is located in the `docs` subdirectory. 
Run `make html` from there to create html documentation from docstrings.
Documentation html is available in `docs/build/html/index.html`

dependency: Sphinx
```shell script
pip install Sphinx
```

## Roadmap:
This project is Work In Progress
1. basic HD paper wallet generator supporting bip32, bip44, bip49, bip84, slip132 (Multi-signature P2WSH in P2SH, Multi-signature P2WSH)
2. storage
3. network calls 
4. (to be decided)
