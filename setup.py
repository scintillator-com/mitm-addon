# -*- coding: utf-8 -*-

from os import path
from setuptools import setup, find_packages
#here = path.abspath( path.dirname( __file__ ) )

setup(
    name             = "scintillator",
    description      = "Scintillator addon for mitmproxy",
    long_description = "Scintillator addon for mitmproxy",
    version          = "0.2.0",

    author       = 'Chris Esquibel',
    author_email = 'c.esquibel@scintillator.com',

    url = 'https://www.scintillator.com/',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        'Programming Language :: Python :: 3.7+'
    ],
    packages = find_packages(),
    data_files = [
      'data/rules.json'
    ],
    install_requires = [
        'pymongo == 3.11.2'
    ],
    python_requires = ">=3.7",
    scripts = [],
)
