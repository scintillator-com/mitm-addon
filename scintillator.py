# -*- coding: utf-8 -*-

"""Generic event hooks."""
import datetime, json, logging, logging.handlers, os, re, sys, typing, urllib.parse
from urllib.parse import urlencode

try:
    from cStringIO import StringIO
except ModuleNotFoundError:
    from io import StringIO



import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.log
import mitmproxy.proxy.protocol

from mitmproxy import ctx
from mitmproxy.net import http
from mitmproxy.script import concurrent

import pymongo


class NoData( Exception ):
    pass


class ContentType( object ):
    APPLICATION_JSON = 'application/json'
    APPLICATION_XWWWFORMURLENCODED = 'application/x-www-form-urlencoded'
    MULTIPART_FORMDATA = 'multipart/form-data'
    TEXT_PLAIN = 'text/plain'


class Configuration( object ):
    MONGO_DB   = 'scintillator'
    MONGO_HOST = '192.168.1.31'
    MONGO_PORT = 27017
    MONGO_USER = None
    MONGO_PASS = None
    MONGO_OPTIONS = {
        #'retryWrites': 'true',
        #'w': 'majority'
    }

    MONGO_SRV = False

    REQUEST_CONTENT_LENGTH = 5000
    REQUEST_CONTENT_TYPES  = (
        ContentType.APPLICATION_JSON,
        ContentType.APPLICATION_XWWWFORMURLENCODED,
        ContentType.MULTIPART_FORMDATA,
        #ContentType.TEXT_PLAIN
    )

    RESPONSE_CONTENT_LENGTH = 20000
    RESPONSE_CONTENT_TYPES  = (
        ContentType.APPLICATION_JSON,
        ContentType.TEXT_PLAIN
    )

    SKIP_AUTH = True
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
        if cls.MONGO_SRV:
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


class FlowStatus( object ):
    NONE     = None
    CANCEL   = 'CANCEL'
    COMPLETE = 'COMPLETE'
    IGNORE   = 'IGNORE'
    SUMMARY  = 'SUMMARY'


class Moment( object ):
    __slots__ = (
        '_id',
        'generator',
        'org_id',
        'user_id',
        'visibility',
        'request',
        'response',
        'timing'
    )

    def __init__( self, flow: mitmproxy.http.HTTPFlow ):
        self._id        = None
        self.generator  = 'python'
        self.org_id     = None
        self.user_id    = None
        self.visibility = None

        self.request    = None
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
    def count_files( self, data ):
        count = 0
        with StringIO( data ) as reader:
          for line in reader:
              if self.body_boundary in line:
                  in_header = True

              elif in_header:
                  if line.strip():
                      logging.debug( 'line: {0}'.format( line.rstrip() ) )
                      key, value = line.split( ':', 1 )
                      value, attributes = HTTPData.parse_header_value( value )
                      if key.lower() == 'content-disposition' and value.lower() == 'form-data':
                          if 'filename' in attributes:
                              count += 1

                  else:
                      in_header = False
              
              else:
                  # ignore body data
                  pass

        return count


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
    @classmethod
    def get_content_type( cls, source ):
        headers = []
        if source.headers:
            headers = source.headers.get_all( 'content-type' )

        if len( headers ) > 1:
            logging.warn( "Multiple Content-Type headers received: {0}".format( headers ))

        boundary = None
        content_type = None
        for header in headers:
            tmp, attributes = cls.parse_header_value( header ) #value.split( ';', 1 )
            if content_type and content_type != tmp:
                logging.warn( "Conflicting Content-Types: {0} != {1}".format( content_type, tmp ))
            else:
                content_type = tmp

            if content_type == ContentType.MULTIPART_FORMDATA and 'boundary' in attributes:
                if boundary and boundary != attributes['boundary']:
                    logging.warn( "Conflicting Content-Types BOUNDARY: {0} != {1}".format( boundary, attributes['boundary'] ))
                else:
                    boundary = attributes['boundary']

            if 'charset' in attributes and attributes['charset']:
                logging.info( 'Charset: {0}'.format( attributes['charset'] ) )

        return content_type, boundary


    def load_body( self, source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            if self.content_type != ContentType.MULTIPART_FORMDATA:
                logging.warn( 'Multipart/Form-Data has unexpected content-type: {0}'.format( self.content_type ) )

            if self.body_boundary:
                logging.debug( "boundary: '{0}'".format( self.body_boundary ) )
                attachments = self.parse_multipart( source )
                self.body = [ att.to_dict() for att in attachments ]
                self.is_complete = True
                self.is_summary = False

            else:
                logging.warn( "Multipart/Form-Data doesn't have a boundary" )
                self.body = self.load_multidict( source.multipart_form )
                self.is_complete = True
                self.is_summary = False

        elif hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            if self.content_type != ContentType.APPLICATION_XWWWFORMURLENCODED:
                logging.warn( 'X-WWW-UrlEncoded has unexpected content-type: {0}'.format( self.content_type ) )

            self.body = self.load_multidict( source.urlencoded_form )
            self.is_complete = True
            self.is_summary = False

        else:
            if source.text:
                self.body = source.text
            elif source.content:
                self.body = source.content
            elif source.raw_content:
                self.body = source.raw_content

            if self.body:
                self.is_complete = True
                self.is_summary = False

                try:
                    self.body = json.loads( self.body )
                    if self.content_type != ContentType.APPLICATION_JSON:
                        logging.warn( "Old content-type: '{0}'".format( self.content_type ) )
                        self.content_type = ContentType.APPLICATION_JSON

                except json.decoder.JSONDecodeError as ex:
                    pass

                except Exception as ex:
                    logging.exception( ex )


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
            logging.info( key )
            logging.info( value )
            target.append({
                'k': str( key ),
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


    def measure_body( self, source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            if self.body_boundary:
                logging.debug( "boundary: '{0}'".format( self.body_boundary ) )
                if source.text:
                    return len( source.text ), self.count_files( source.text ) > 0
                elif source.content:
                    return len( source.content ), self.count_files( source.content ) > 0
                elif source.raw_content:
                    return len( source.raw_content ), self.count_files( source.raw_content ) > 0

            else:
                logging.warn( "Multipart/Form-Data doesn't have a boundary" )
                #TODO: measure multidict

            logging.warn( 'MULTIPART' )
            logging.warn( source.multipart_form )
            raise NotImplementedError()

        elif hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            #MultiDictView
            if source.text:
                return len( source.text ), False
            elif source.content:
                return len( source.content ), False
            elif source.raw_content:
                return len( source.raw_content ), False

            logging.warn( 'URLENCODED' )
            logging.warn( source.urlencoded_form )
            raise NotImplementedError()

        elif source.text:
            return len( source.text ), False

        elif source.content:
            return len( source.content ), False

        elif source.raw_content:
            return len( source.raw_content ), False

        else:
            return 0, False


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


    @staticmethod
    def parse_header_value( header ):
        values = header.split( ',' )
        if len( values ) > 1:
            raise NotImplementedError()

        else:
            pieces = values[0].strip().split( ';' )
            
            attributes = {}
            value = pieces.pop(0).strip()
            for piece in pieces:
                k, v = piece.strip().split( '=', 1 )
                attributes[ k ] = v

            return value, attributes


    def parse_multipart( self, source ):
        if source.text:
            logging.info( "parse_multipart( 'source.text' )" )
            reader = StringIO( source.text )
        elif source.content:
            logging.info( "parse_multipart( 'source.content' )" )
            reader = StringIO( source.content )
        elif source.raw_content:
            logging.info( "parse_multipart( 'source.raw_content' )" )
            reader = StringIO( source.raw_content )
        else:
            return []


        attachments = []
        with reader:
            for line in reader:
                if self.body_boundary in line:
                    try:
                        attachment = Attachment.from_stream( reader, self.body_boundary )
                        attachments.append( attachment )
                    except NoData:
                        pass

        return attachments


    def to_dict( self ):
        return { slot: getattr( self, slot ) for slot in self.__slots__ }


    @staticmethod
    def unquote( value ):
        if value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        else:
            return value


class Attachment( object ):
    __slots__ = (
        'headers',
        'content_length',
        'content_type',

        'body',
        'name',
        
        'filename'
    )

    def __init__( self ):
        self.headers = []
        self.content_length = 0
        self.content_type = None
        
        self.body = ''
        self.name = None

        self.filename = None


    @classmethod
    def from_stream( cls, stream, boundary ):
        content_start = prev_pos = start = stream.tell()
        
        in_header = True
        attachment = cls()
        for line in stream:
            if boundary in line:
                #found new boundary, back up so outer loop can find it too
                stream.seek( prev_pos )
                break

            elif in_header:
                if line.strip():
                    logging.debug( 'line: {0}'.format( line.rstrip() ) )
                    key, value = line.split( ':', 1 )
                    value, attributes = HTTPData.parse_header_value( value )

                    header = {
                        'k': key,
                        'v': value,
                        'i': len( attachment.headers )
                        #attributes
                    }
                    attachment.headers.append( header )

                    if key.lower() == 'content-disposition' and value.lower() == 'form-data':
                        if attachment.name:
                            logging.warn( 'received multiple content names' )
                        else:
                            attachment.name = HTTPData.unquote( attributes['name'] )

                        if 'filename' in attributes:
                            attachment.filename = HTTPData.unquote( attributes['filename'] )


                    elif key.lower() == 'content-type':
                        if attachment.content_type:
                            logging.warn( 'received multiple content types' )
                        else:
                            attachment.content_type = value

                else:
                    in_header = False
                    content_start = prev_pos
            
            else:
                attachment.body += line

            prev_pos = stream.tell()

        if attachment.name:
            #finalize data
            attachment.body = attachment.body.rstrip()
            attachment.content_length = len( attachment.body )
            return attachment

        else:
            raise NoData()


    def to_dict( self ):
        return {
            'k': self.name,
            'v': self.body,
            #'headers': self.headers,
            'l': self.content_length,
            't': self.content_type,
            'fn': self.filename
        }


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
        'body_boundary',

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
        self.body_boundary = None
        
        self.body = None
        self.is_complete = False
        self.is_summary = False

        if request:
            '''
            logging.info( request )
            for k in [ 'host', 'host_header', 'pretty_host' ]:
                logging.info({ k: getattr( request, k ) })
            '''
            '''
            for k in [ 'text', 'content', 'raw_content', 'urlencoded_form', 'multipart_form' ]:
                val = getattr( request, k )
                b = not not val
                logging.info({
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

            if request.query:
                self.path, self.query_string = self.path.split( '?', 1 )

            self.query_data = HTTPData.load_query( request )
            self.headers    = HTTPData.load_headers( request )
            self.content_length = self.get_content_length( request )
            self.content_type, self.body_boundary = self.get_content_type( request )

            self.is_summary = True


class Response( HTTPData ):
    __slots__ = (
        'created',
        'http_version',
        'status_code',

        'headers',
        'content_length',
        'content_type',
        'body_boundary',

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
        self.body_boundary = None

        self.body = None
        self.is_complete = False
        self.is_summary = False

        if response:
            '''
            for k in [ 'text', 'content', 'raw_content' ]:
                val = getattr( response, k )
                b = not not val
                logging.info({
                  k: val,
                  'bool': b
                })
            '''

            self.http_version = response.http_version
            self.status_code = response.status_code
            
            self.headers = HTTPData.load_headers( response )
            self.content_length = self.get_content_length( response )
            self.content_type, self.body_boundary = self.get_content_type( response )

            self.is_summary = True


################ Scintillator Methods ################
class ScintillatorBase:
    BASE_64 = re.compile( '^[0-9A-Za-z+/]+$' )
    HEX = re.compile( '^[0-9A-Fa-f]+$' )

    MAX_CONTENT_LENGTH = 20000
    
    MONGO = None



    @classmethod
    def authorize_org( cls, flow: mitmproxy.http.HTTPFlow, client_key ):
        logging.info( 'Auth org' )
        if not flow.org:
            flow.org = cls.get_org({ "client_key": client_key })


        if flow.org:
            if flow.org['is_enabled']:
                logging.info( 'Org enabled' )
                return True

            else:
                logging.warn( 'Org disabled' )
                return False

        else:
            logging.warn( 'Org not found...' )
            return None


    @classmethod
    def authorize_user( cls, flow: mitmproxy.http.HTTPFlow, client_key ):
        logging.info( 'Auth user' )
        flow.user = cls.get_user({ "client_key": client_key })
        if flow.user:
            if flow.user['is_enabled']:
                logging.info( 'User enabled' )
                flow.org = cls.get_org({ "_id": flow.user['org_id'] })
                return True
        
            else:
                logging.warn( 'User disabled' )
                return False

        else:
            logging.info( 'User not found...' )
            return None


    @staticmethod
    def cancel_proxy( flow: mitmproxy.http.HTTPFlow, content, status_code, headers=None ):
        if not headers:
            headers = {
                "Content-Type": ContentType.TEXT_PLAIN
            }

        flow.status = FlowStatus.CANCEL
        flow.response = mitmproxy.http.HTTPResponse.make(
            status_code,  # (optional) status code
            content,      # (optional) content
            headers       # (optional) headers
        )


    @classmethod
    def check_ratelimit( cls, flow ):
        if Configuration.SKIP_AUTH:
            return True

        elif cls._check_ratelimit( flow.org['client_key'], 'proxy_evergreen' ):
            return True

        elif cls._check_ratelimit( flow.org['client_key'], 'proxy_adhoc' ):
            return True

        else:
            return False


    @classmethod
    def _check_ratelimit( cls, org_client_key, key ):
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
    def configure_logging( cls, level=logging.DEBUG ):
        __dir__ = os.path.dirname( os.path.realpath( __file__ ) )
        log_name = 'scintillator'
        log_path = os.path.join( __dir__, 'logs', log_name +'.log' )

        formatter = logging.Formatter( '[%(asctime)s] %(name)s %(levelname)-8s %(filename)12.12s:%(lineno)3d %(message)s' )

        con_handler = logging.StreamHandler( sys.stdout )
        con_handler.setFormatter( formatter )
        con_handler.setLevel( level )

        file_handler = logging.handlers.TimedRotatingFileHandler( log_path, when='midnight', backupCount=7 )
        file_handler.setFormatter( formatter )
        file_handler.setLevel( level )

        default_logger = logging.getLogger()
        #for handler in default_logger.handlers:
        #    print( handler )

        #remove others
        while default_logger.hasHandlers():
            default_logger.removeHandler(default_logger.handlers[0])
        
        default_logger.addHandler( con_handler )
        default_logger.addHandler( file_handler )
        default_logger.setLevel( level )

        #TODO: set hpack.hpack to INFO

        hpack_logger = logging.getLogger( 'hpack.hpack' )
        hpack_logger.setLevel( logging.INFO )


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
                if value.endswith( '/tor' ) and cls.BASE_64.match( value ):
                    if my_key:
                        logging.info( "Ignoring Scintillator {0}: {1}".format( key, value ) )
                    else:
                        logging.info( "Found {0}: {1}".format( key, value ) )
                        my_key = value

                else:
                    logging.log( 0, "Ignoring {0}: {1}".format( key, value ) )
                    keep_fields.append(( key, value ))

            else:
                logging.log( 0, "Ignoring {0}: {1}".format( key, value ) )
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
    def is_authorized( cls, flow: mitmproxy.http.HTTPFlow ):
        if Configuration.SKIP_AUTH:
            return True


        client_key = cls.get_client_key( flow )
        if not client_key:
            return False

        user_auth = cls.authorize_user( flow, client_key )
        if user_auth is True:
            return True
        elif user_auth is None:
            pass
        else:
            return False

        org_auth = cls.authorize_org( flow, client_key )
        if org_auth is True:
            return True
        else:
            return False

        return False


    @classmethod
    def load_request( cls, flow: mitmproxy.http.HTTPFlow, get_body=False ):
        flow.moment = Moment( flow )
        flow.moment.request = Request( flow.request )

        headers_length = HTTPData.measure_headers( flow.request )

        query_length = 0
        if flow.moment.request.query_string:
            query_length = len( flow.moment.request.query_string )

        total_length = headers_length + query_length + flow.moment.request.content_length
        return total_length


    @classmethod
    def load_response( cls, flow: mitmproxy.http.HTTPFlow, get_body=False ):
        flow.moment.response = Response( flow.response )
        headers_length = HTTPData.measure_headers( flow.response )
        total_length = headers_length + flow.moment.response.content_length
        return total_length


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

        #TODO: 
        if flow.moment.request.is_complete:

            flow.moment.request.load_body( flow.request )


        flow.timing['request_parsed'] = datetime.datetime.now()


        as_dict = flow.moment.to_dict()
        #logging.info( as_dict )
        res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).insert_one( as_dict )
        flow.moment._id = res.inserted_id
        logging.info({ 'flow.id': flow.moment._id })


    @classmethod
    def record_response( cls, flow: mitmproxy.http.HTTPFlow ):
        as_dict = flow.moment.response.to_dict()
        #logging.info( as_dict )
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
        self.configure_logging( logging.INFO )
        logging.info( '''
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
        logging.info( '1: load' )


    #2
    def running(self):
        """
            Called when the proxy is completely up and running. At this point,
            you can expect the proxy to be bound to a port, and all addons to be
            loaded.
        """
        logging.info( '2: running' )


    #3
    def configure(self, updated: typing.Set[str]):
        """
            Called when configuration changes. The updated argument is a
            set-like object containing the keys of all changed options. This
            event is called during startup with all options in the updated set.
        """
        logging.info( '3: configure' )


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
        logging.info( '4: next_layer' )
    '''
    '''
    #4 - global
    def update(self, flows: typing.Sequence[mitmproxy.flow.Flow]):
        """
            Update is called when one or more flow objects have been modified,
            usually from a different addon.
        """
        logging.info( '4: update' )
    '''

    ################ HTTP Events ################
    '''
    #5
    def clientconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has connected to mitmproxy. Note that a connection can
            correspond to multiple HTTP requests.
        """
        logging.info( '5: clientconnect' )
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
        logging.info( '6: http_connect' )
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
        logging.info( '7: requestheaders' )

        # init
        flow.status = FlowStatus.NONE
        flow.moment = None
        flow.org    = None
        flow.timing = {}
        flow.user   = None

        #request_started??
        flow.timing['request_received'] = datetime.datetime.now()


        #apply forward header(s)
        #TODO: is there another XFF header?
        if flow.client_conn.address[0].startswith( '::ffff:' ):
            ip_addr = flow.client_conn.address[0][7:]
        else:
            ip_addr = flow.client_conn.address[0]
        flow.request.headers.add( 'X-Forwarded-For', ip_addr )
        #TODO: X-Forwarded


        #populate flow.moment.request
        total_length = self.load_request( flow )
        logging.debug( 'content_length: {0}'.format( flow.moment.request.content_length ) )
        logging.debug( 'total_length:   {0}'.format( total_length ) )


        #TODO: flow.moment.request.path
        if flow.moment.request.content_type and flow.moment.request.content_type in Configuration.REQUEST_CONTENT_TYPES:
            if self.is_authorized( flow ):
                if flow.moment.request.content_type == ContentType.MULTIPART_FORMDATA:
                    #undecided, get the body
                    flow.status = FlowStatus.NONE
                elif flow.moment.request.content_length:
                    if flow.moment.request.content_length <= Configuration.REQUEST_CONTENT_LENGTH:
                        flow.status = FlowStatus.COMPLETE
                    else:
                        logging.warn( 'Request body {0} > {1}'.format( flow.moment.request.content_length, Configuration.REQUEST_CONTENT_LENGTH ) )
                        flow.status = FlowStatus.SUMMARY
                        flow.request.stream = True
                else:
                    #undecided, get the body
                    flow.status = FlowStatus.NONE

            else:
                return self.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )

        else:
            #wrong type
            flow.status = FlowStatus.SUMMARY
            flow.request.stream = True


    #8
    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """
        logging.info( '8: request' )
        if flow.status == FlowStatus.CANCEL:
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )
            return

        if flow.status == FlowStatus.IGNORE:
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )
            return

        if not self.check_ratelimit( flow ):
            cls.cancel_proxy( flow, "Proxy: Too Many Requests", 429 )
            return


        #TODO: flow.timing['request_received'] = datetime.datetime.now()

        if flow.status == FlowStatus.NONE:
            body_length, has_files = flow.moment.request.measure_body( flow.request )
            if flow.moment.request.content_length:
                if body_length != flow.moment.request.content_length:
                    logging.warn( 'Content-Length (header): {0}'.format( flow.moment.request.content_length ) )
                    logging.warn( 'Content-Length (body): {0}'.format( body_length ) )
                    flow.moment.request.content_length = body_length
            else:
                flow.moment.request.content_length = body_length

            if body_length <= Configuration.REQUEST_CONTENT_LENGTH:
                flow.status = FlowStatus.COMPLETE
            else:
                flow.status = FlowStatus.SUMMARY


        if flow.status == FlowStatus.COMPLETE:
            try:
                flow.moment.request.load_body( flow.request )
                flow.timing['request_parsed'] = datetime.datetime.now()
            except Exception as ex:
                flow.moment.request.error = str( ex )
                flow.status = FlowStatus.SUMMARY
                flow.timing['request_parsed'] = datetime.datetime.now()
                logging.exception( ex )
        elif flow.status == FlowStatus.SUMMARY:
            flow.timing['request_parsed'] = None
        else:
            logging.warn( "REQUEST flow.status = '{0}'".format( flow.status ) )
            flow.status = FlowStatus.IGNORE
            flow.timing['request_parsed'] = None


        if flow.status in ( FlowStatus.COMPLETE, FlowStatus.SUMMARY ):
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )
            try:
                self.record_request( flow )
            except Exception as ex:
                logging.exception( ex )
                flow.status = FlowStatus.IGNORE
        else:
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )




    ################ Intermediate Core Event ################
    '''
    #9
    def serverconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has connected to a server. Note that a connection can
            correspond to multiple requests.
        """
        logging.info( '9: serverconnect' )
    '''

    ################ HTTP Events ################
    #10
    @concurrent
    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP response headers were successfully read. At this point, the body
            is empty.
        """
        logging.info( '10: responseheaders' )
        if flow.status == FlowStatus.CANCEL:
            logging.info( "RESPONSE flow.status = '{0}'".format( flow.status ) )
            return
        
        if flow.status == FlowStatus.IGNORE:
            logging.info( "RESPONSE flow.status = '{0}'".format( flow.status ) )
            return


        #response_started??
        flow.timing['response_received'] = datetime.datetime.now()

        #populate flow.moment.response
        total_length = self.load_response( flow )
        logging.debug( 'content_length: {0}'.format( flow.moment.response.content_length ) )
        logging.debug( 'total_length:   {0}'.format( total_length ) )

        if flow.moment.response.content_type and flow.moment.response.content_type in Configuration.RESPONSE_CONTENT_TYPES:
            if flow.moment.response.content_length:
                if flow.moment.response.content_length <= Configuration.RESPONSE_CONTENT_LENGTH:
                    flow.status = FlowStatus.COMPLETE
                else:
                    logging.warn( 'Response body {0} > {1}'.format( flow.moment.response.content_length, Configuration.RESPONSE_CONTENT_LENGTH ) )
                    flow.response.stream = True
                    flow.status = FlowStatus.SUMMARY
            else:
                #undecided, get the body
                flow.status = FlowStatus.NONE
        elif flow.status in ( FlowStatus.COMPLETE, FlowStatus.SUMMARY ):
            logging.warn( "Content-Type: '{0}'".format( flow.moment.response.content_type ) )
            flow.response.stream = True
            flow.status = FlowStatus.SUMMARY
        else:
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )
            flow.response.stream = True
            flow.status = FlowStatus.IGNORE


    #11
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """
        logging.info( '11: response' )
        if flow.status == FlowStatus.CANCEL:
            logging.info( "RESPONSE flow.status = '{0}'".format( flow.status ) )
            return

        if flow.status == FlowStatus.IGNORE:
            logging.info( "RESPONSE flow.status = '{0}'".format( flow.status ) )
            return


        #TODO: flow.timing['response_received'] = datetime.datetime.now()
        if flow.status == FlowStatus.NONE:
            body_length, has_files = flow.moment.response.measure_body( flow.response )
            if flow.moment.response.content_length:
                if body_length != flow.moment.response.content_length:
                    logging.warn( 'Content-Length (header): {0}'.format( flow.moment.response.content_length ) )
                    logging.warn( 'Content-Length (body): {0}'.format( body_response ) )
                    flow.moment.response.content_length = body_length
            else:
                flow.moment.response.content_length = body_length

            if body_length <= Configuration.RESPONSE_CONTENT_LENGTH:
                flow.status = FlowStatus.COMPLETE
            else:
                flow.status = FlowStatus.SUMMARY


        if flow.status == FlowStatus.COMPLETE:
            try:
                flow.moment.response.load_body( flow.response )
                flow.timing['response_parsed'] = datetime.datetime.now()
            except Exception as ex:
                flow.moment.response.error = str( ex )
                flow.status = FlowStatus.SUMMARY
                flow.timing['response_parsed'] = None
                logging.exception( ex )
        elif flow.status == FlowStatus.SUMMARY:
            flow.timing['request_parsed'] = None
        else:
            flow.status = FlowStatus.IGNORE
            flow.timing['response_parsed'] = None


        if flow.status in ( FlowStatus.COMPLETE, FlowStatus.SUMMARY ):
            logging.info( "RESPONSE flow.status = '{0}'".format( flow.status ) )
            try:
                self.record_response( flow )
            except ex:
                logging.exception( ex )
        else:
            logging.info( "REQUEST flow.status = '{0}'".format( flow.status ) )


    ################ Final Core Event ################
    '''
    #12
    def clientdisconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has disconnected from mitmproxy.
        """
        logging.info( '12: clientdisconnect' )
    '''
    '''
    #13
    def serverdisconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has disconnected from a server.
        """
        logging.info( '13: serverdisconnect' )
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
        logging.info( '''
  //////////////
 // 14: done //
//////////////
''' )

addons = [
    ScintillatorAddon()
]
