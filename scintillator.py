# -*- coding: utf-8 -*-

"""Generic event hooks."""
import datetime, json, logging, logging.handlers, os, re, sys, typing, urllib.parse
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
    USE_SRV    = False
    MONGO_DB   = 'scintillator'
    MONGO_HOST = '192.168.1.31'
    MONGO_PORT = 27017
    MONGO_USER = None
    MONGO_PASS = None
    MONGO_OPTIONS = {
        #'retryWrites': 'true',
        #'w': 'majority'
    }

    WEBSITE = 'http://DESKTOP-QCP8I15.localdomain:3000'

    @classmethod
    def getMongoDbUri( cls ):
        options = ''
        if cls.MONGO_OPTIONS:
            options = '?'+ urlencode( cls.MONGO_OPTIONS )

        port = ''
        if cls.MONGO_PORT != 27017:
            port = ':{port}'.format( port=cls.MONGO_PORT )

        scheme = 'mongodb'
        if cls.USE_SRV:
            scheme = 'mongodb+srv'

        user_pass = ''
        if cls.MONGO_USER and cls.MONGO_PASS:
            user_pass = '{username}:{password}@'.format(
                username=urllib.parse.quote_plus( cls.MONGO_USER ),
                password=urllib.parse.quote_plus( cls.MONGO_PASS )
            )

        formatted = "{scheme}://{user_pass}{host}{port}/{dbname}{options}".format(
            scheme=scheme,
            user_pass=user_pass,
            host=cls.MONGO_HOST,
            port=port,
            dbname=cls.MONGO_DB,
            options=options
        )

        logging.info( formatted )
        return formatted


class Moment( object ):
    __slots__ = (
        '_id',
        'request',
        'response',
        'timing',
        'org_id',
        'user_id',
        'visibility'
    )

    def __init__( self, flow: mitmproxy.http.HTTPFlow ):
        self._id        = None
        self.request    = None
        self.org_id     = None
        self.user_id    = None
        self.visibility = None

        self.response   = None
        self.timing     = {}

        if flow.user:
            self.org_id     = flow.user['org_id']
            self.user_id    = flow.user['_id']
            self.visibility = 'private'

        elif flow.org:
            self.org_id     = flow.org['_id']
            self.user_id    = None
            self.visibility = 'private'

        else:
            self.org_id     = None
            self.user_id    = None
            self.visibility = 'public'

        self.timing = flow.timing


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
    '''
    Used for flow.request.headers and flow.response.headers
    '''
    @staticmethod
    def get_content_length( source ):
        content_length = 0
        if source.headers:
            for value in source.headers.get_all( 'content-length' ):
                if content_length:
                    logging.warn( "Content-Length already exists: {0}".format( content_length ))

                try:
                    content_length = int( value )
                except ValueError:
                    pass

        return content_length


    '''
    Used for flow.request.headers and flow.response.headers
    '''
    @staticmethod
    def get_content_type( source ):
        content_type = None
        if source.headers:
            for value in source.headers.get_all( 'content-type' ):
                if content_type:
                    logging.warn( "Content-Type already exists: {0}".format( content_type ))

                #TODO: boundary??
                content_type = value.split( ';', 1 )[0]

        return content_type


    def load_body( self, source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            logging.warn( 'MULTIPART_FORM' )
            #TODO: content_type
            self.body = cls.load_multidict( source.multipart_form )

        if hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            logging.warn( 'URLENCODED' )
            #TODO: content_type
            self.body = cls.load_multidict( source.urlencoded_form )

        if source.text:
            self.body = source.text
        elif source.content:
            self.body = source.content
        elif source.raw_content:
            self.body = source.raw_content

        if self.body:
            try:
                self.body = json.loads( self.body )
                if self.content_type != 'application/json':
                    logging.warn( "Old content-type: '{0}'".format( self.content_type ) )
                    self.content_type = 'application/json'

            except Exception as ex:
                logging.warn( ex )


    '''
    Used for flow.request.headers and flow.response.headers
    '''
    @staticmethod
    def load_headers( source ):
        headers = []
        if source.headers:
            for key, value in source.headers.items( True ):
                headers.append({
                    'k': key,
                    'v': value,
                    'i': len( headers )
                })

        return headers


    @staticmethod
    def load_multidict( source ):
        target = []
        for key, value in source.items( True ):
            target.append({
                'k': key,
                'v': value,
                'i': len( target )
            })

        return target


    @staticmethod
    def load_query( source ):
        query_data = []
        if source.query:
            for key, value in source.query.items( True ):
                query_data.append({
                    'k': key,
                    'v': value,
                    'i': len( query_data )
                })

        return query_data


    @staticmethod
    def measure_body( source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            logging.warn( 'MULTIPART_FORM' )
            logging.warn( source.multipart_form )
            #TODO: boundary
            raise NotImplementedError()

            '''
            body_data = {}
            flow.moment.request.body = HTTPData.load_form( source.multipart_form,  )

            if flow.moment.request.content_type:
                logging.warn( 'Received {0}'.format( flow.moment.request.content_type ) )
                logging.warn( 'Actual multipart/form-data' )
            else:
                flow.moment.request.content_type = 'multipart/form-data'
            '''

        elif hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            logging.warn( 'URLENCODED' )
            logging.warn( source.multipart_form )
            #TODO: boundary
            raise NotImplementedError()

            '''
            flow.moment.request.body = HTTPData.load_multidict( source.urlencoded_form )
            #TODO: content_length
            if not flow.moment.request.content_type:
                flow.moment.request.content_type = 'application/x-www-form-urlencoded'
            else:
                logging.warn( flow.moment.request.content_type )
            '''

        elif source.text:
            return len( source.text )
            '''
            if not flow.moment.request.content_length:
                flow.moment.request.content_length = len( flow.moment.request.body )

            if not flow.moment.request.content_type:
                flow.moment.request.content_type = 'text/plain'
            else:
                logging.warn( flow.moment.request.content_type )
            '''

        elif source.content:
            return len( source.content )
            '''
            if not flow.moment.request.content_length:
                flow.moment.request.content_length = len( flow.moment.request.body )

            if not flow.moment.request.content_type:
                flow.moment.request.content_type = 'text/plain'
            else:
                logging.warn( flow.moment.request.content_type )
            '''

        elif source.raw_content:
            return len( source.raw_content )
            '''
            if not flow.moment.request.content_length:
                flow.moment.request.content_length = len( flow.moment.request.body )

            if not flow.moment.request.content_type:
                flow.moment.request.content_type = 'text/plain'
            else:
                logging.warn( flow.moment.request.content_type )
            '''
        else:
            return 0


    '''
    Used for flow.request.headers and flow.response.headers
    '''
    @staticmethod
    def measure_headers( source ):
        length = 0
        if source.headers:
            for key, value in source.headers.items( True ):
                # +2 for colon (:) and newline (\n)
                length += len( key ) + len( value ) + 2

        return length


    def to_dict( self ):
        return { slot: getattr( self, slot ) for slot in self.__slots__ }


class Request( HTTPData ):
    __slots__ = (
        'created',
        'http_version',
        'method',
        'scheme',
        'host',
        'port',
        'path',

        'query_data',
        'query_string',
        'headers',
        'content_length',
        'content_type',

        'body',
        'is_complete',
        'is_summary'
    )

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
        self.is_complete = False
        self.is_summary = False

        if request:
            '''
            logging.debug( request )
            for k in [ 'host', 'host_header', 'pretty_host' ]:
                logging.debug({ k: getattr( request, k ) })
            '''
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

            self.content_length = self.get_content_length( request )
            self.content_type   = self.get_content_type( request )
            if request.query:
                self.path, self.query_string = self.path.split( '?', 1 )



class Response( HTTPData ):
    __slots__ = (
        'created',
        'http_version',
        'status_code',

        'headers',
        'content_length',
        'content_type',

        'body',
        'is_complete',
        'is_summary'
    )

    def __init__( self, response = None ):
        self.created = datetime.datetime.now()
        self.http_version = None
        self.status_code = None

        self.headers      = []
        self.content_length = None
        self.content_type = None

        self.body = None
        self.is_complete = False
        self.is_summary = False

        if response:
            '''
            for k in [ 'text', 'content', 'raw_content' ]:
                val = getattr( response, k )
                b = not not val
                logging.debug({
                  k: val,
                  'bool': b
                })
            '''

            self.http_version = response.http_version
            self.status_code = response.status_code
            self.content_length = self.get_content_length( response )
            self.content_type = self.get_content_type( response )



################ Scintillator Methods ################
class ScintillatorBase:
    BASE_64 = re.compile( '^[0-9A-Za-z+/]+$' )
    HEX = re.compile( '^[0-9A-Fa-f]+$' )

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
    def authorize_org( cls, flow: mitmproxy.http.HTTPFlow, client_key ):
        logging.debug( 'Auth org' )
        if not flow.org:
            flow.org = cls.get_org({ "client_key": client_key })

        if flow.org:
            if flow.org['is_enabled']:
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
            if flow.user['is_enabled']:
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

        flow.is_cancelled = True
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
        cls.MONGO = pymongo.MongoClient( Configuration.getMongoDbUri() )


    @classmethod
    def get_client_key( cls, flow ):
        my_key = None
        keep_fields = []
        check_headers = ( 'x-api-key', 'x-client-key' )
        for key, value in flow.request.headers.items( True ):
            if key.lower() in check_headers:
                if value.startswith( 'sci/' ) and cls.BASE_64.match( value ):
                    if my_key:
                        logging.debug( "Ignoring Scintillator {0}: {1}".format( key, value ) )
                    else:
                        logging.debug( "Found {0}: {1}".format( key, value ) )
                        my_key = value

                else:
                    logging.debug( "Ignoring {0}: {1}".format( key, value ) )
                    keep_fields.append(( key, value ))

            else:
                logging.debug( "Ignoring {0}: {1}".format( key, value ) )
                keep_fields.append(( key, value ))

        #only rebuild if something changed
        if my_key:
            flow.request.headers.clear()
            for key, value in keep_fields:
                flow.request.headers.add( key, value )

        return my_key


    @classmethod
    def get_mongo( cls, db_name, collection_name ):
        db = getattr( cls.MONGO, db_name )
        return getattr( db, collection_name )


    @staticmethod
    def get_path( flow: mitmproxy.http.HTTPFlow ):
        return flow.request.path.split( '?', 1 )[0]


    @classmethod
    def get_org( cls, query ):
        return cls.get_mongo( Configuration.MONGO_DB, 'orgs' ).find_one( query )


    @classmethod
    def get_user( cls, query ):
        return cls.get_mongo( Configuration.MONGO_DB, 'users' ).find_one( query )


    @classmethod
    def ignore_request( cls, flow: mitmproxy.http.HTTPFlow ):
        if not flow.is_ignored:
            path = cls.get_path( flow )
            _, ext = os.path.splitext( flow.request.path )
            flow.is_ignored = ext in cls.SKIP_REQUEST_EXT

        return flow.is_ignored


    @classmethod
    def ignore_response( cls, flow: mitmproxy.http.HTTPFlow ):
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
    def moment_recorded( cls, moment: Moment ):
        if moment.org_id:
            query = {
                "org_id":  moment.org_id,
                "host":    moment.request.host
            }

            update = {
                "$inc": {
                    "moments": 1
                }
            }

            res = cls.get_mongo( Configuration.MONGO_DB, 'projects' ).update_one( query, update )
            if res.modified_count == 0:
                created = datetime.datetime.now()
                project = query
                project["created"]   = created
                project["modified"]  = created
                project["is_locked"] = True
                project["moments"]   = 1
                res = cls.get_mongo( Configuration.MONGO_DB, 'projects' ).insert_one( project )


    @classmethod
    def record_request( cls, flow: mitmproxy.http.HTTPFlow ):
        #TODO: load_request_summary
        # https://mitmproxy.readthedocs.io/en/v2.0.2/scripting/api.html
        flow.moment = Moment( flow )
        flow.moment.request = Request( flow.request )

        headers_length = HTTPData.measure_headers( flow.request )
        query_length   = len( flow.moment.request.query_string )
        if flow.moment.request.content_length:
            body_length = HTTPData.measure_body( flow.request )
            if body_length != flow.moment.request.content_length:
                logging.warn( 'Content-Length (header): {0}'.format( flow.moment.request.content_length ) )
                logging.warn( 'Content-Length (body): {0}'.format( HTTPData.measure_body( flow.request ) ) )
        else:
            flow.moment.request.content_length = HTTPData.measure_body( flow.request )

        total_length = headers_length + query_length + flow.moment.request.content_length
        logging.warn( 'total_length: {0}'.format( total_length ) )


        #TODO: plan limits vs user limits
        flow.moment.request.is_complete = True


        #TODO: 
        if flow.moment.request.is_complete:
            flow.moment.request.query_data = HTTPData.load_query( flow.request )
            flow.moment.request.headers    = HTTPData.load_headers( flow.request )
            flow.moment.request.load_body( flow.request )


        flow.timing['request_parsed'] = datetime.datetime.now()


        as_dict = flow.moment.to_dict()
        #logging.debug( as_dict )
        res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).insert_one( as_dict )
        flow.moment._id = res.inserted_id
        logging.info({ 'flow.id': flow.moment._id })


    @classmethod
    def record_response( cls, flow: mitmproxy.http.HTTPFlow ):
        flow.moment.response = Response( flow.response )

        headers_length = HTTPData.measure_headers( flow.response )
        if flow.moment.response.content_length:
            logging.warn( 'Content-Length (header): {0}'.format( flow.moment.response.content_length ) )
            logging.warn( 'Content-Length (body): {0}'.format( HTTPData.measure_body( flow.response ) ) )
        else:
            flow.moment.response.content_length = HTTPData.measure_body( flow.response )

        total_length = headers_length + flow.moment.response.content_length
        logging.warn( 'total_length: {0}'.format( total_length ) )

        
        #TODO: plan limits vs user limits
        flow.moment.response.is_complete = True


        if flow.moment.response.is_complete:
            flow.moment.response.headers    = HTTPData.load_headers( flow.response )
            flow.moment.response.load_body( flow.response )


        flow.timing['response_parsed'] = datetime.datetime.now()


        as_dict = flow.moment.response.to_dict()
        #logging.debug( as_dict )
        res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).update_one(
          { "_id": flow.moment._id },
          { "$set": {
              "response": as_dict,
              "timing": flow.timing
          }}
        )

        flow.response.headers["S-Moment-Id"] = str( flow.moment._id )
        flow.response.headers["Link"] = '{0}/moment/{1}'.format( Configuration.WEBSITE, str( flow.moment._id ) )
        cls.moment_recorded( flow.moment )




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

        #flow.client_conn
        #flow.request
        #flow.response

        # init
        flow.is_cancelled = False
        flow.is_ignored   = False
        flow.moment    = None
        flow.org       = None
        flow.timing    = {}
        flow.user      = None

        #request_started??
        flow.timing['request_received'] = datetime.datetime.now()

        if self.ignore_request( flow ):
            path = cls.get_path( flow )
            logging.info( "Ignoring request path '{0}'".format( path ) )
            return


        try:
            self.authorize_request( flow )
        except ex:
            logging.exception( ex )
            flow.is_ignored = True


    #8
    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """
        logging.debug( '8: request' )
        if flow.is_cancelled or flow.is_ignored:
            return

        #??
        #flow.timing['request_received'] = datetime.datetime.now()


        try:
            self.record_request( flow )
        except Exception as ex:
            logging.exception( ex )
            flow.is_ignored = True


        #TODO: X-Forwarded
        #TODO: X-Forwarded-For
        if flow.client_conn.address[0].startswith( '::ffff:' ):
            ip_addr = flow.client_conn.address[0][7:]
        else:
            ip_addr = flow.client_conn.address[0]


        logging.info( 'Address: {0}'.format( ip_addr ) )



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
        if flow.is_cancelled or flow.is_ignored:
            return


        #response_started??
        flow.timing['response_received'] = datetime.datetime.now()

        #TODO:
        #if self.ignore_response( flow ):
        #    logging.info( "Ignoring response" )
        #    return



    #11
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """
        logging.debug( '11: response' )
        if flow.is_cancelled or flow.is_ignored:
            return

        #???
        #flow.timing['response_received'] = datetime.datetime.now()

        try:
            self.record_response( flow )
        except ex:
            logging.exception( ex )
            flow.is_ignored = True


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
