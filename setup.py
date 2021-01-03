# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from os import path
here = path.abspath( path.dirname( __file__ ) )

setup(
    name             = "Scintillator addon for mitmproxy",
    description      = "Scintillator addon for mitmproxy",
    long_description = "Scintillator addon for mitmproxy",
    version          = "0.1.0",

    author       = 'Chris Esquibel',
    author_email = 'c.esquibel@scintillator.com',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        'Programming Language :: Python :: 3.7+'
    ],

    package = find_packages(),

    data_files= [],

    install_requires = [
        'pymongo == 3.11.2'
    ],

    scripts = [],
)
