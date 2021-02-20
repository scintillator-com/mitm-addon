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


class FlowTasks( object ):
    LOAD_REQUEST_DETAIL   = 'LOAD_REQUEST_DETAIL'
    LOAD_REQUEST_SUMMARY  = 'LOAD_REQUEST_SUMMARY'
    LOAD_RESPONSE_DETAIL  = 'LOAD_RESPONSE_DETAIL'
    LOAD_RESPONSE_SUMMARY = 'LOAD_RESPONSE_SUMMARY'
    SAVE_REQUEST_DETAIL   = 'SAVE_REQUEST_DETAIL'
    SAVE_REQUEST_SUMMARY  = 'SAVE_REQUEST_SUMMARY'
    SAVE_RESPONSE_DETAIL  = 'SAVE_RESPONSE_DETAIL'
    SAVE_RESPONSE_SUMMARY = 'SAVE_RESPONSE_SUMMARY'


class RuleSetBehavior( object ):
    FIRST = 'first'
    LAST  = 'last'
    ALL   = ( 'first', 'last' )

    @classmethod
    def validate( cls, behavior:str ):
        if not behavior in cls.ALL:
            raise NotImplementedError( behavior )


class RuleTarget( object ):
    requestheaders = 1
    request = 2
    responseheaders = 3
    response = 4
    ALL = ( 1, 2, 3, 4 )

    @classmethod
    def validate( cls, target:str ):
        if not target in cls.ALL:
            raise NotImplementedError( target )
