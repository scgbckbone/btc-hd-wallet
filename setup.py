#!/usr/bin/env python

from setuptools import setup
import os

__version__ = "0.0.1"

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

install_requires = [
    "ecdsa>=0.15"
]

setup(
    name='btc_hd_wallet',
    version=__version__,
    license="MIT",
    author="Andrej Virgovic",
    author_email="virgovica@gmail.com",
    description='Bitcoin HD paper wallet implementation.',
    long_description=README,
    long_description_content_type='text/markdown',
    classifiers=[
      "Development Status :: 4 - Beta",
      "Programming Language :: Python :: 3 :: Only",
      "Programming Language :: Python :: 3.5",
      "Programming Language :: Python :: 3.6",
      "Programming Language :: Python :: 3.7",
      "Programming Language :: Python :: 3.8",
      "Programming Language :: Python :: 3.9",
    ],
    url='https://github.com/scgbckbone/btc-hd-wallet',
    keywords=[
        "bitcoin",
        "btc",
        "hierarchical deterministic wallet",
        "BIP32",
        "BIP85",
        "BIP39",
    ],
    packages=["btc_hd_wallet"],
    zip_safe=False,
    install_requires=install_requires,
    test_suite="tests"
)
