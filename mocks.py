# -*- coding: utf-8 -*-

from models import Moment, Request, Response


class MitmFlow(object):
    def __init__( self ):
        self.request = MitmRequest()
        
        self.attributes = set()
        self.moment     = Moment()
        self.moment.request = Request()
        self.org        = None
        self.user       = None


class MitmHeaders( list ):
    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

    def add( self, key, value ):
        self.append(( key, value ))

    #def clear( self ):
    #    self.clear()

    def items( self, *args, **kwargs ):
        return self


class MitmRequest( object ):
    def __init__( self ):
        self.headers = MitmHeaders()
        self.is_detail   = False
        self.is_summary  = False
        self.text        = ''
        self.content     = ''
        self.raw_content = ''
