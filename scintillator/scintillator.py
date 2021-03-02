# -*- coding: utf-8 -*-

import logging

try:
    from addons import ScintillatorAddon

    addons = [
        ScintillatorAddon()
    ]
except Exception as ex:
    logging.exception( ex )


