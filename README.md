# Installation
1. install python3.6 or higher for your OS
2. [install](https://www.linode.com/docs/development/version-control/how-to-install-git-on-linux-mac-and-windows/) git 
```shell script
# clone btc-hd-wallet repository
git clone https://github.com/scgbckbone/btc-hd-wallet.git
# change directory to project root
cd btc-hd-wallet
# install project
python setup.py install
# run unittests (optional)
python setup.py test
```

# Base Wallet
```python3
from btc_hd_wallet import BaseWallet

# many option how to get to BaseWallet object
w = BaseWallet()

# derive external chian node of accoutn 100
external_chain_node = w.by_path(path="m/84'/0'/100'/0")

# create generator
bip84_gen = w.next_address(node=external_chain_node)

# generate addresses
next(bip84_gen)
```

# Paper Wallet
```python3
from btc_hd_wallet import PaperWallet
w = PaperWallet()

# to display in console
w.pretty_print()

# export to csv file
w.export_to_csv(file_path="wallet.csv")
```

## Roadmap:
This project is Work In Progress
1. basic HD paper wallet generator supporting bip32, bip44, bip49, bip84, slip132 (Multi-signature P2WSH in P2SH, Multi-signature P2WSH)
2. storage
3. network calls 
4. (to be decided)
