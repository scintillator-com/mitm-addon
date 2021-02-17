# -*- coding: utf-8 -*-

import logging, urllib.parse
import pymongo


class Configuration( object ):
    MONGO_DB   = 'scintillator'
    MONGO_HOST = '192.168.1.31'
    MONGO_PORT = 27017
    MONGO_SRV = False
    MONGO_USER = None
    MONGO_PASS = None
    MONGO_OPTIONS = {
        #'retryWrites': 'true',
        #'w': 'majority'
    }

    RULES_FILE = '/home/lc/sites/mitm-addon/data/rules.json'
    WEBSITE = 'http://DESKTOP-QCP8I15.localdomain:3000'

    '''
    SKIP_AUTH = False
    SKIP_REQUEST_EXT = (
      '.css',
      '.doc',
      '.docx',
      '.gif',
      '.gz',
      '.ico',
      '.iso',
      '.jpg',
      '.jpeg',
      '.js',
      '.pdf',
      '.png',
      '.tar',
      '.xls',
      '.xlsx',
      '.zip'
    )
    '''


