# -*- coding: utf-8 -*-

import logging


class Configuration( object ):
    LOG_LEVEL  = logging.INFO
    MONGO_DB   = None
    MONGO_URI  = None
    RULES_FILE = None
    SKIP_AUTH  = None
    RATELIMIT  = None
    WEBSITE    = None
