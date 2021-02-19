# -*- coding: utf-8 -*-

import datetime, json, logging

try:
    from cStringIO import StringIO
except ModuleNotFoundError:
    from io import StringIO

from enums  import ContentType, RuleSetBehavior, RuleTarget
from errors import NoData


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
                            logging.warning( 'received multiple content names' )
                        else:
                            attachment.name = HTTPData.unquote( attributes['name'] )

                        if 'filename' in attributes:
                            attachment.filename = HTTPData.unquote( attributes['filename'] )


                    elif key.lower() == 'content-type':
                        if attachment.content_type:
                            logging.warning( 'received multiple content types' )
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



class HTTPData( object ):
    @staticmethod
    def count_files( data, body_boundary ):
        count = 0
        with StringIO( data ) as reader:
          for line in reader:
              if body_boundary in line:
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
                    logging.warning( "Content-Length already exists: {0}".format( content_length ))

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
            logging.warning( "Multiple Content-Type headers received: {0}".format( headers ))

        boundary = None
        content_type = None
        for header in headers:
            tmp, attributes = cls.parse_header_value( header ) #value.split( ';', 1 )
            if content_type and content_type != tmp:
                logging.warning( "Conflicting Content-Types: {0} != {1}".format( content_type, tmp ))
            else:
                content_type = tmp

            if content_type == ContentType.MULTIPART_FORMDATA and 'boundary' in attributes:
                if boundary and boundary != attributes['boundary']:
                    logging.warning( "Conflicting Content-Types BOUNDARY: {0} != {1}".format( boundary, attributes['boundary'] ))
                else:
                    boundary = attributes['boundary']

            if 'charset' in attributes and attributes['charset']:
                logging.info( 'Charset: {0}'.format( attributes['charset'] ) )

        return content_type, boundary


    def load_body( self, source ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            if self.content_type != ContentType.MULTIPART_FORMDATA:
                logging.warning( 'Multipart/Form-Data has unexpected content-type: {0}'.format( self.content_type ) )

            if self.body_boundary:
                logging.debug( "boundary: '{0}'".format( self.body_boundary ) )
                attachments = self.parse_multipart( source, self.body_boundary )
                self.body = [ att.to_dict() for att in attachments ]
                self.is_detail = True
                self.is_summary = False

            else:
                logging.warning( "Multipart/Form-Data doesn't have a boundary" )
                self.body = self.load_multidict( source.multipart_form )
                self.is_detail = True
                self.is_summary = False

        elif hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            if self.content_type != ContentType.APPLICATION_XWWWFORMURLENCODED:
                logging.warning( 'X-WWW-UrlEncoded has unexpected content-type: {0}'.format( self.content_type ) )

            self.body = self.load_multidict( source.urlencoded_form )
            self.is_detail = True
            self.is_summary = False

        else:
            if source.text:
                self.body = source.text
            elif source.content:
                self.body = source.content
            elif source.raw_content:
                self.body = source.raw_content

            if self.body:
                self.is_detail = True
                self.is_summary = False

                try:
                    self.body = json.loads( self.body )
                    if self.content_type != ContentType.APPLICATION_JSON:
                        logging.warning( "Old content-type: '{0}'".format( self.content_type ) )
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


    @classmethod
    def measure_body( cls, source, body_boundary ):
        if hasattr( source, 'multipart_form' ) and source.multipart_form:
            if body_boundary:
                logging.debug( "boundary: '{0}'".format( body_boundary ) )
                if source.text:
                    return len( source.text ), cls.count_files( source.text, body_boundary ) > 0
                elif source.content:
                    return len( source.content ), cls.count_files( source.content, body_boundary ) > 0
                elif source.raw_content:
                    return len( source.raw_content ), cls.count_files( source.raw_content, body_boundary ) > 0

            else:
                logging.warning( "Multipart/Form-Data doesn't have a boundary" )
                #TODO: measure multidict

            logging.warning( 'MULTIPART' )
            logging.warning( source.multipart_form )
            raise NotImplementedError()

        elif hasattr( source, 'urlencoded_form' ) and source.urlencoded_form:
            #MultiDictView
            if source.text:
                return len( source.text ), False
            elif source.content:
                return len( source.content ), False
            elif source.raw_content:
                return len( source.raw_content ), False

            logging.warning( 'URLENCODED' )
            logging.warning( source.urlencoded_form )
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


    @classmethod
    def parse_multipart( cls, source, boundary ):
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
                if body_boundary in line:
                    try:
                        attachment = Attachment.from_stream( reader, body_boundary )
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

    def __init__( self ):
        self._id        = None
        self.generator  = 'python'
        self.org_id     = None
        self.user_id    = None
        self.visibility = 'private'

        self.request    = None
        self.response   = None
        self.timing     = {}


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
        'is_detail',
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
        self.is_detail = False
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


            # NOTE: port and scheme are not available yet!
            self.http_version = request.http_version
            self.method = request.method
            self.scheme = request.scheme or None
            self.host   = request.host_header
            self.port   = request.port or None
            self.path   = request.path

            if request.query:
                self.path, self.query_string = self.path.split( '?', 1 )

            self.query_data = HTTPData.load_query( request )
            self.headers    = HTTPData.load_headers( request )
            self.content_length = self.get_content_length( request )
            self.content_type, self.body_boundary = self.get_content_type( request )

            self.is_summary = True


    def measure( self ):
        headers_length = 0
        for header in self.headers:
            headers_length += len( header['k'] ) + len( header['v'] ) + 2

        query_length = 0
        if self.query_string:
            query_length = len( self.query_string )

        total_length = headers_length + query_length + self.content_length
        return total_length


    def measure_body( self, flow ):
        body_length = HTTPData.measure_body( flow.request, self.body_boundary )
        if self.content_length:
            if body_length != self.content_length:
                logging.warning( 'Content-Length (header): {0}'.format( self.content_length ) )
                logging.warning( 'Content-Length   (body): {0}'.format( body_length ) )
                self.content_length = body_length
        else:
            self.content_length = body_length



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
        'is_detail',
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
        self.is_detail = False
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


    def measure( self ):
        headers_length = 0
        for header in self.headers:
            headers_length += len( header['k'] ) + len( header['v'] ) + 2

        total_length = headers_length + self.content_length
        return total_length


    def measure_body( self, flow ):
        body_length, has_files = HTTPData.measure_body( flow.response, self.body_boundary )
        if self.content_length:
            if body_length != self.content_length:
                logging.warning( 'Content-Length (header): {0}'.format( self.content_length ) )
                logging.warning( 'Content-Length   (body): {0}'.format( body_length ) )
                self.content_length = body_length
        else:
            self.content_length = body_length



class RuleFilters( object ):
    __slots__ = (
        #'client',
        'host',
        'method',
        #'path',
        'port',
        'scheme',
        #'accept',

        'content_length',
        'content_type',

        'status'
    )

    def __init__( self, **kwargs ):
        #self.client = None
        self.host   = kwargs[ 'host'   ] if 'host'   in kwargs else None
        self.method = kwargs[ 'method' ] if 'method' in kwargs else None
        #self.path   = None
        self.port   = kwargs[ 'port'   ] if 'port'   in kwargs else None
        self.scheme = kwargs[ 'scheme' ] if 'scheme' in kwargs else None
        #self.accept = None

        self.content_length = kwargs[ 'content_length' ] if 'content_length' in kwargs else None
        self.content_type   = kwargs[ 'content_type'   ] if 'content_type' in kwargs else None

        self.status  = kwargs['status'] if 'status' in kwargs else None


    def is_match( self, moment:Moment, target:str ):
        if target == RuleTarget.requestheaders:
            return self.is_match_requestheaders( moment.request )

        elif target == RuleTarget.request:
            return self.is_match_request( moment.request )

        elif target == RuleTarget.responseheaders:
            return self.is_match_reponseheaders( moment.response )

        elif target == RuleTarget.response:
            return self.is_match_response( moment.response )

        else:
            raise NotImplementedError( target )


    def is_match_requestheaders( self, req:Request ):
        #if self.client:
        #    #TODO: CIDR
        #    if req.client not in self.client:
        #        return False

        if self.host:
            #TODO: wildcard
            if req.host not in self.host:
                return False

        if self.method:
            if req.method not in self.method:
                return False

        #if self.path:
        #    #TODO: wildcard
        #    if req.path not in self.path:
        #        return False

        if self.port:
            if req.port not in self.port:
                return False

        if self.scheme:
            if req.scheme not in self.scheme:
                return False

        #if self.accept:
        #    #TODO: wildcard
        #    if req.accept not in self.accept:
        #        return False

        if self.content_length:
            if req.content_length < self.content_length[0]:
                return False
            elif req.content_length > self.content_length[1]:
                return False

        if self.content_type:
            #TODO: wildcard
            if req.content_type not in self.content_type:
                return False

        return True


    def is_match_request( self, req:Request ):
        #if self.client:
        #    #TODO: CIDR
        #    if req.client not in self.client:
        #        return False

        if self.host:
            #TODO: wildcard
            if req.host not in self.host:
                return False

        if self.method:
            if req.method not in self.method:
                return False

        #if self.path:
        #    #TODO: wildcard
        #    if req.path not in self.path:
        #        return False

        if self.port:
            if req.port not in self.port:
                return False

        if self.scheme:
            if req.scheme not in self.scheme:
                return False

        #if self.accept:
        #    #TODO: wildcard
        #    if req.accept not in self.accept:
        #        return False

        if self.content_length:
            if req.content_length < self.content_length[0]:
                return False
            elif req.content_length > self.content_length[1]:
                return False

        if self.content_type:
            #TODO: wildcard
            if req.content_type not in self.content_type:
                return False

        return True


    def is_match_reponseheaders( self, res:Response ):
        if self.content_length:
            if self.content_length[0] <= res.content_length and res.content_length <= self.content_length[1]:
                pass
            else:
                return False

        if self.content_type:
            #TODO: wildcard
            if res.content_type not in self.content_type:
                return False

        if self.status:
            if res.status < self.status[0]:
                return False
            elif res.status > self.status[1]:
                return False

        return True


    def is_match_reponse( self, res: Response ):
        if self.content_length:
            if res.content_length < self.content_length[0]:
                return False
            elif res.content_length > self.content_length[1]:
                return False

        if self.content_type:
            #TODO: wildcard
            if res.content_type not in self.content_type:
                return False

        if self.status:
            if res.status < self.status[0]:
                return False
            elif res.status > self.status[1]:
                return False

        return True




    @classmethod
    def load( cls, filter_data ):
        instance = RuleFilters()

        try:
            instance.host = filter_data['host']
        except KeyError: pass

        try:
            instance.method = filter_data['method']
        except KeyError: pass

        try:
            instance.port = filter_data['port']
        except KeyError: pass

        try:
            instance.scheme = filter_data['scheme']
        except KeyError: pass

        try:
            instance.content_length = filter_data['content_length']
        except KeyError: pass

        try:
            instance.content_type = filter_data['content_type']
        except KeyError: pass

        try:
            instance.status = filter_data['status']
        except KeyError: pass

        return instance


    def validate( self, target:str ):
        if target == RuleTarget.requestheaders:
            return True

        #elif target == RuleTarget.request:
        #    raise NotImplementedError()

        elif target == RuleTarget.responseheaders:
            return True

        #elif target == RuleTarget.response:
        #    raise NotImplementedError()

        else:
            raise NotImplementedError( target )



class Rule( object ):
    __slots__ = (
        'agents',
        'filters',
        'index',
        'target'
    )

    def __init__( self, agents=[], filters:RuleFilters=None, index:int=-1, target=None ):
        self.agents  = agents  or []
        self.filters = filters or RuleFilters()
        self.index   = index   or -1
        self.target  = target  or None


    def is_match( self, moment:Moment, target:str ):
        if target == self.target:
            return self.filters.is_match( moment, self.target )
        else:
            return False


    @classmethod
    def load( cls, rule_data ):
        from agents import AgentBase

        logging.debug( rule_data )
        instance = Rule()
        for agent in rule_data['agents']:
            instance.agents.append( AgentBase.create( agent ) )

        instance.filters = RuleFilters.load( rule_data['filters'] )
        instance.index  = rule_data['index']
        instance.target = getattr( RuleTarget, rule_data['target'] )
        return instance


    def process( self, flow, target:str ):
        logging.info( "Processing rule {0}".format( self.index ) )
        for agent in self.agents:
            logging.info( "Processing agent {0}".format( type( agent ) ) )
            #try:
            agent.process( flow, target )
            #except Exception as ex :
            #    logging.warn( ex )


    def validate( self ):
        if not self.agents:
            raise

        if self.index < 0:
            raise

        if not self.target:
            raise
        elif self.target not in RuleTarget.ALL:
            raise

        if not self.filters.validate( self.target ):
            raise



class RuleSet( object ):
    __slots__ = (
        'behavior',
        'rules'
        #'strategy'
    )

    def __init__( self, behavior, rules=[] ):
        self.behavior = behavior
        self.rules    = rules or []


    def append( self, rule: Rule ):
        self.rules.append( rule )


    def filter( self, moment:Moment, target:str ):
        if self.behavior == RuleSetBehavior.FIRST:
            return self.first( target, moment )
        elif self.behavior == RuleSetBehavior.LAST:
            return self.last( target, moment )
        else:
            raise


    def first( self, moment:Moment, target:str ):
        for rule in self.rules:
            if rule.is_match( target, moment ):
                return rule

        return None


    def last( self, moment:Moment, target:str ):
        match = None
        for rule in self.rules:
            if rule.is_match( target, moment ):
                match = rule

        return match


    @classmethod
    def load( cls, data ):
        RuleSetBehavior.validate( data['behavior'] )
        instance = RuleSet( data['behavior'] )
        for rule in data['rules']:
            instance.append( Rule.load( rule ) )

        return instance


    @classmethod
    def load_file( cls, path ):
        logging.info( "Loading RuleSet from '{0}'".format( path ) )
        with open( path ) as fd:
            return cls.load( json.load( fd ) )


    def process( self, flow, target:str ):
        rule = self.filter( flow.moment, target )
        if rule:
            rule.process( flow, target )
        else:
            logging.warning( "No matching rules for phase '{0}'...".format( target ) )


    def validate( self ):
        if not self.behavior:
            raise

        if not self.default_agent:
            raise


    class Behavior( object ):
        FIRST = 'first'
        LAST  = 'last'

        @classmethod
        def validate( cls, behavior:str ):
            if not behavior in ( cls.FIRST, cls.LAST ):
                raise NotImplementedError()

