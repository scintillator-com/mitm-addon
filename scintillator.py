# -*- coding: utf-8 -*-

"""Generic event hooks."""
import datetime, json, logging, logging.handlers, os, sys, typing
from urllib.parse import urlencode

import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.log
import mitmproxy.proxy.protocol

from mitmproxy import ctx
from mitmproxy.net import http
from mitmproxy.script import concurrent

import pymongo


class Configuration( object ):
    MONGO_DB   = 'scintillator'
    MONGO_HOST = '192.168.1.31'
    MONGO_PORT = 27017
    MONGO_USER = None
    MONGO_PASS = None

    WEBSITE = 'http://DESKTOP-QCP8I15.localdomain:3000'


class Moment( object ):
    __slots__ = ( 'request', 'response', 'timing', 'org_id', 'user_id', 'visibility' )
    def __init__( self, flow ):
        self.request  = Request( flow.request )
        if flow.user:
            self.org_id     = flow.user['org_id']
            self.user_id    = flow.user['_id']
            self.visibility = 'private'
        else:
            self.visibility = 'public'

        self.response = None #Response( response ) if flow.response else None
        self.timing = {}
        self.org_id = None
        self.user_id = None
        self.visibility = None


    def to_dict( self ):
        data = {
            'request':  None,
            'response': None,
            'timing':   {}
        }

        for slot in self.__slots__:
            value = getattr( self, slot )
            if value:
              if slot == 'request':
                  data[ slot ] = value.to_dict()
              elif slot == 'response':
                  data[ slot ] = value.to_dict()
              else:
                  data[ slot ] = value

        return data


class HTTPData( object ):
    def load_body( self, source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            #TODO: body_type
            self.body = self.load_multidict( source.multipart_form )
            return


        if hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            #TODO: body_type
            self.body = self.load_multidict( source.urlencoded_form )
            return


        if source.text:
            self.body = source.text

        elif source.content:
            self.body = source.content
            
        elif source.raw_content:
            self.body = source.raw_content

        if self.body:
            try:
                #TODO: body_type
                self.body = json.loads( self.body )
            except Exception as ex:
                #TODO: body_type
                logging.warn( ex )


    def load_headers( self, source ):
        if source.headers:
            self.load_multidict( source.headers, self.headers )

            #get_content_length
            for value in source.headers.get_all( 'content-length' ):
                self.content_length = value

            #get_content_type
            for value in source.headers.get_all( 'content-type' ):
                self.content_type = value


    @staticmethod
    def load_multidict( source, target=None ):
        no_target = target is None
        if no_target:
            target = []

        for key in source:
            target.append({
                'k': key,
                'v': source[ key ],
                'i': len( target )
            })

        return target if no_target else None
    
    
    def to_dict( self ):
        return { slot: getattr( self, slot ) for slot in self.__slots__ }


class Request( HTTPData ):
    __slots__ = ( 'created', 'http_version', 'method', 'scheme', 'host', 'port', 'path',
        'query_data', 'query_string', 'content_length', 'content_type', 'headers', 'body' )

    def __init__( self, request = None ):
        self.created = datetime.datetime.now()
        self.http_version = None
        self.method       = None
        self.scheme       = None
        self.host         = None
        self.port         = None
        self.path         = None

        self.query_data   = []
        self.query_string = None
        self.headers      = []
        self.content_length = None
        self.content_type = None
        
        self.body = None

        if request:
            #logging.debug( request )
            #for k in [ 'host', 'host_header', 'pretty_host' ]:
            #    logging.debug({ k: getattr( request, k ) })

            '''
            for k in [ 'text', 'content', 'raw_content', 'urlencoded_form', 'multipart_form' ]:
                val = getattr( request, k )
                b = not not val
                logging.debug({
                  k: val,
                  'bool': b
                })
            '''

            self.http_version = request.http_version
            self.method = request.method
            self.scheme = request.scheme
            self.host   = request.host_header
            self.port   = request.port
            self.path   = request.path

            self.load_headers( request )

            if request.query:
                split_at = self.path.find( '?' )
                self.query_string = self.path[split_at+1:]
                self.path = self.path[:split_at]

                self.load_multidict( request.query, self.query_data )

                #qs = []
                #for kvi in self.query_data:
                #    qs.append(( kvi['k'], kvi['v'] ))
                #self.query_string = urlencode( qs )

            self.load_body( request )


class Response( HTTPData ):
    __slots__ = ( 'created', 'http_version', 'status_code', 'headers', 'content_length', 'content_type', 'body' )

    def __init__( self, response = None ):
        self.created = datetime.datetime.now()
        self.http_version = None
        self.status_code = None

        self.headers      = []
        self.content_length = None
        self.content_type = None

        self.body = None

        if response:
            #for k in [ 'text', 'content', 'raw_content' ]:
            #    val = getattr( response, k )
            #    b = not not val
            #    logging.debug({
            #      k: val,
            #      'bool': b
            #    })

            self.http_version = response.http_version
            self.status_code = response.status_code

            self.load_headers( response )
            self.load_body( response )



################ Scintillator Methods ################
class ScintillatorBase:
    MAX_CONTENT_LENGTH = 20000
    
    MONGO = None

    RECORD_CONTENT_TYPES = (
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data'
    )

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


    @classmethod
    def authorize_request( cls, flow: mitmproxy.http.HTTPFlow ):
        # init
        flow.cancelled = False
        flow.ignored   = False
        flow.org       = None
        flow.user      = None


        if cls.ignore_request( flow ):
            logging.info( "Ignoring request path '{0}'".format( path ) )
            flow.ignored = True
            return

        client_key = cls.get_client_key( flow )
        if not client_key:
            # anonymous is ratelimited by IP
            #TODO: check rate limit, create if missing
            return


        if not cls.authorize_user( flow, client_key ):
            cls.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )
            return


        if not cls.authorize_org( flow, client_key ):
            cls.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )
            return


        if cls.check_ratelimit( flow.org['client_key'], 'proxy_evergreen' ):
            return
        elif cls.check_ratelimit( flow.org['client_key'], 'proxy_adhoc' ):
            return
        else:
            cls.cancel_proxy( flow, "Proxy: Too Many Requests", 429 )


    @classmethod
    def authorize_response( cls, flow: mitmproxy.http.HTTPFlow ):
        for value in flow.response.headers.get_all( 'content-length' ):
            try:
                value = int( value )
            except ValueError:
                logging.warn( "Could not convert Content-Length( {0} ) to int".format( value ) )
                continue

            if value > cls.MAX_CONTENT_LENGTH:
                logging.warn( "Content-Length too long: {0}".format( value ) )
            else:
                logging.debug( "Content-Length ok: {0}".format( value ) )

        for value in flow.response.headers.get_all( 'content-type' ):
            if value in cls.RECORD_CONTENT_TYPES:
                logging.debug( "Content-Type supported: {0}".format( value ) )
            else:
                logging.warn( "Content-Type unsupported: {0}".format( value ) )


    @classmethod
    def authorize_org( cls, flow: mitmproxy.http.HTTPFlow, client_key ):
        logging.debug( 'Auth org' )
        if not flow.org:
            flow.org = cls.get_org({ "client_key": client_key })

        if flow.org:
            if flow.org['enabled']:
                logging.debug( 'Org enabled' )
                return True

            else:
                logging.warn( 'Org disabled' )
                return False

        else:
            logging.warn( 'Org not found' )
            return False


    @classmethod
    def authorize_user( cls, flow: mitmproxy.http.HTTPFlow, client_key ):
        logging.debug( 'Auth user' )
        flow.user = cls.get_user({ "client_key": client_key })
        if flow.user:
            if flow.user['enabled']:
                logging.debug( 'User enabled' )
                flow.org = cls.get_org({ "_id": flow.user['org_id'] })
                return True
        
            else:
                logging.warn( 'User disabled' )
                return False

        else:
            logging.debug( 'User not found...' )
            return True

    

    @staticmethod
    def cancel_proxy( flow: mitmproxy.http.HTTPFlow, content, status_code, headers=None ):
        if not headers:
            headers = {
                "Content-Type": "text/plain"
            }

        flow.cancelled = True
        flow.response = mitmproxy.http.HTTPResponse.make(
            status_code,  # (optional) status code
            content,      # (optional) content
            headers       # (optional) headers
        )


    @classmethod
    def check_ratelimit( cls, org_client_key, key ):
        query = {
            "org_client_key": org_client_key,
            key: { "$gt": 0 }
        }
        update = {
            '$inc': {
                key: -1
            }
        }
        res = cls.get_mongo( Configuration.MONGO_DB, 'rate_limits' ).update_one( query, update )
        return res.modified_count >= 0


    @classmethod
    def configure_logging( cls ):
        __dir__ = os.path.dirname( os.path.realpath( __file__ ) )
        log_name = 'scintillator'
        log_path = os.path.join( __dir__, 'logs', log_name +'.log' )

        formatter = logging.Formatter( '[%(asctime)s] %(name)s %(levelname)-8s %(filename)12.12s:%(lineno)3d %(message)s' )

        con_handler = logging.StreamHandler( sys.stdout )
        con_handler.setFormatter( formatter )
        con_handler.setLevel( logging.DEBUG )

        file_handler = logging.handlers.TimedRotatingFileHandler( log_path, when='midnight', backupCount=7 )
        file_handler.setFormatter( formatter )
        file_handler.setLevel( logging.DEBUG )

        logger = logging.getLogger()
        #for handler in logger.handlers:
        #    print( handler )

        #remove others
        while logger.hasHandlers():
            logger.removeHandler(logger.handlers[0])
        
        logger.addHandler( con_handler )
        logger.addHandler( file_handler )
        logger.setLevel( logging.DEBUG )


    @classmethod
    def connect( cls ):
        cls.MONGO = pymongo.MongoClient( Configuration.MONGO_HOST, Configuration.MONGO_PORT )


    @staticmethod
    def get_client_key( flow ):
        #TODO: check for base64

        client_key = None
        for value in flow.request.headers.get_all( 'x-client-key' ):
            if client_key:
                logging.debug( "Ignoring X-Client-Key: {0}".format( value ) )
            
            else:
                logging.debug( "Found X-Client-Key: {0}".format( value ) )
                client_key = value

        if client_key:
            del flow.request.headers[ 'x-client-key' ]


        for value in flow.request.headers.get_all( 'x-api-key' ):
            if client_key:
                logging.debug( "Ignoring X-Api-Key: {0}".format( value ) )

            else:
                logging.debug( "Found X-Api-Key: {0}".format( value ) )
                client_key = value

        if client_key:
            del flow.request.headers[ 'x-api-key' ]


        return client_key


    @classmethod
    def get_mongo( cls, db_name, collection_name ):
        db = getattr( cls.MONGO, db_name )
        return getattr( db, collection_name )


    @staticmethod
    def get_path( flow: mitmproxy.http.HTTPFlow ):
        if flow.request.query:
            split_at = flow.request.path.find( '?' )
            return flow.request.path[:split_at]
        else:
            return flow.request.path


    @classmethod
    def get_org( cls, query ):
        return cls.get_mongo( Configuration.MONGO_DB, 'orgs' ).find_one( query )


    @classmethod
    def get_user( cls, query ):
        return cls.get_mongo( Configuration.MONGO_DB, 'users' ).find_one( query )


    @classmethod
    def ignore_request( cls, flow: mitmproxy.http.HTTPFlow ):
        path = cls.get_path( flow )
        _, ext = os.path.splitext( flow.request.path )
        return ext in cls.SKIP_REQUEST_EXT


    @classmethod
    def record_request( cls, flow: mitmproxy.http.HTTPFlow ):
        if flow.cancelled:
            return

        if flow.ignored:
            return


        # https://mitmproxy.readthedocs.io/en/v2.0.2/scripting/api.html
        moment = Moment( flow )

        as_dict = moment.to_dict()
        #logging.debug( as_dict )
        res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).insert_one( as_dict )
        flow.id = res.inserted_id
        logging.info({ 'flow.id': flow.id })


    @classmethod
    def record_response( cls, flow: mitmproxy.http.HTTPFlow ):
        if flow.cancelled:
            return

        if flow.ignored:
            return

      


        response = Response( flow.response )
        as_dict = response.to_dict()
        #logging.debug( as_dict )

        res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).update_one(
          { "_id": flow.id },
          { "$set": { "response": as_dict } }
        )

        flow.response.headers["S-Moment-Id"] = str( flow.id )
        flow.response.headers["Link"] = '{0}/moment/{1}'.format( Configuration.WEBSITE, str( flow.id ) )




class ScintillatorAddon( ScintillatorBase ):
    #0
    def __init__( self ):
        self.configure_logging()
        logging.debug( '''
  /////////////////
 // 0: __init__ //
/////////////////
''' )
        
        self.connect()


    ################ Core Events ################
    #1
    def load(self, entry: mitmproxy.addonmanager.Loader):
        """
            Called when an addon is first loaded. This event receives a Loader
            object, which contains methods for adding options and commands. This
            method is where the addon configures itself.
        """
        logging.debug( '1: load' )


    #2
    def running(self):
        """
            Called when the proxy is completely up and running. At this point,
            you can expect the proxy to be bound to a port, and all addons to be
            loaded.
        """
        logging.debug( '2: running' )


    #3
    def configure(self, updated: typing.Set[str]):
        """
            Called when configuration changes. The updated argument is a
            set-like object containing the keys of all changed options. This
            event is called during startup with all options in the updated set.
        """
        logging.debug( '3: configure' )


    ################ Global Events ################
    #4 - global
    def error(self, flow: mitmproxy.http.HTTPFlow):
        """
            An HTTP error has occurred, e.g. invalid server responses, or
            interrupted connections. This is distinct from a valid server HTTP
            error response, which is simply a response with an HTTP error code.
        """
        logging.error( '4: error' )


    #4 - global
    def log(self, entry: mitmproxy.log.LogEntry):
        """
            Called whenever a new log entry is created through the mitmproxy
            context. Be careful not to log from this event, which will cause an
            infinite loop!
        """
        if entry.level == 'debug':
            logging.log( logging.DEBUG, str( entry.msg ) )
        elif entry.level == 'info':
            logging.log( logging.INFO, str( entry.msg ) )
        elif entry.level == 'warn':
            logging.log( logging.WARN, entry.msg )
        elif entry.level == 'error':
            logging.log( logging.ERROR, entry.msg )
        else:
            logging.log( logging.WARN, entry.msg )


    '''
    #4 - global
    def next_layer(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            Network layers are being switched. You may change which layer will
            be used by returning a new layer object from this event.
        """
        logging.debug( '4: next_layer' )
    '''
    '''
    #4 - global
    def update(self, flows: typing.Sequence[mitmproxy.flow.Flow]):
        """
            Update is called when one or more flow objects have been modified,
            usually from a different addon.
        """
        logging.debug( '4: update' )
    '''

    ################ HTTP Events ################
    '''
    #5
    def clientconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has connected to mitmproxy. Note that a connection can
            correspond to multiple HTTP requests.
        """
        logging.debug( '5: clientconnect' )
    '''
    '''
    #6
    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        """
            An HTTP CONNECT request was received. Setting a non 2xx response on
            the flow will return the response to the client abort the
            connection. CONNECT requests and responses do not generate the usual
            HTTP handler events. CONNECT requests are only valid in regular and
            upstream proxy modes.
        """
        logging.debug( '6: http_connect' )
        #TODO: if there are files, return 500
        #TODO: if request size > 1k
        #TODO: if response size > 1k
    '''


    #7
    @concurrent
    def requestheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP request headers were successfully read. At this point, the body
            is empty.
        """
        logging.debug( '7: requestheaders' )
        
        try:
            self.authorize_request( flow )
        except ex:
            logging.exception( ex )
            flow.ignored = True


    #8
    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """
        logging.debug( '8: request' )
        
        try:
            self.record_request( flow )
        except ex:
            logging.exception( ex )
            flow.ignored = True


    ################ Intermediate Core Event ################
    '''
    #9
    def serverconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has connected to a server. Note that a connection can
            correspond to multiple requests.
        """
        logging.debug( '9: serverconnect' )
    '''

    ################ HTTP Events ################
    #10
    @concurrent
    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP response headers were successfully read. At this point, the body
            is empty.
        """

        logging.debug( '10: responseheaders' )
        
        if not flow.ignored:
            try:
                self.authorize_response( flow )
            except ex:
                logging.exception( ex )
                flow.ignored = True


    #11
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """
        logging.debug( '11: response' )
        
        if not flow.ignored:
            try:
                self.record_response( flow )
            except ex:
                logging.exception( ex )
                flow.ignored = True


    ################ Final Core Event ################
    '''
    #12
    def clientdisconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has disconnected from mitmproxy.
        """
        logging.debug( '12: clientdisconnect' )
    '''
    '''
    #13
    def serverdisconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has disconnected from a server.
        """
        logging.debug( '13: serverdisconnect' )
    '''

    #14
    def done(self):
        """
            Called when the addon shuts down, either by being removed from
            the mitmproxy instance, or when mitmproxy itself shuts down. On
            shutdown, this event is called after the event loop is
            terminated, guaranteeing that it will be the final event an addon
            sees. Note that log handlers are shut down at this point, so
            calls to log functions will produce no output.
        """
        logging.debug( '''
  //////////////
 // 14: done //
//////////////
''' )

addons = [
    ScintillatorAddon()
]
