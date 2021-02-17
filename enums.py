# -*- coding: utf-8 -*-

class ContentType( object ):
    APPLICATION_JSON = 'application/json'
    APPLICATION_JSON_PB = 'application/json+protobuf'
    APPLICATION_XWWWFORMURLENCODED = 'application/x-www-form-urlencoded'
    MULTIPART_FORMDATA = 'multipart/form-data'
    TEXT_PLAIN = 'text/plain'


class FlowAttributes( object ):
    NONE           = None
    AUTHORIZED     = 'AUTHORIZED'
    DENIED         = 'DENIED'
    IGNORED        = 'IGNORED'
    REQUEST_SAVED  = 'REQUEST_SAVED'
    RESPONSE_SAVED = 'RESPONSE_SAVED'


class RuleSetBehavior( object ):
    FIRST = 'first'
    LAST  = 'last'
    ALL   = ( 'first', 'last' )

    @classmethod
    def validate( cls, behavior:str ):
        if not behavior in cls.ALL:
            raise NotImplementedError( behavior )


class RuleTarget( object ):
    #1
    requestheaders = 'requestheaders'
    #2
    request = 'request'
    #3
    responseheaders = 'responseheaders'
    #4
    response = 'response'

    ALL = ( 'requestheaders', 'request', 'responseheaders', 'response' )

    @classmethod
    def validate( cls, target:str ):
        if not target in cls.ALL:
            raise NotImplementedError( target )
