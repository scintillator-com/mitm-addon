# -*- coding: utf-8 -*-

import logging

try:
    from addons import ScintillatorAddon

    addons = [
        ScintillatorAddon( logging.INFO )
    ]
except Exception as ex:
    logging.exception( ex )


