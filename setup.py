#!/usr/bin/env python

from setuptools import setup, find_packages
import os

__version__ = "0.0.1"

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

requires = [
    "requests",
    "ecdsa"
]


setup(name='btc-hd-wallet',
      version=__version__,
      description='Bitcoin HD paper wallet implementation based on BIP32',
      long_description=README,
      long_description_content_type='text/markdown',
      classifiers=[
          "Development Status :: 3 - Alpha"
          "Programming Language :: Python :: 3.6",
      ],
      url='https://github.com/scgbckbone/btc-hd-wallet',
      keywords='bitcoin',
      packages=find_packages(),
      zip_safe=False,
      install_requires=requires,
      test_suite="btc_hd_wallet/tests"
)

