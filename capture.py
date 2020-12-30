"""Generic event hooks."""
import datetime, json, typing
from urllib.parse import urlencode

import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.log
import mitmproxy.proxy.protocol
from mitmproxy.net import http

import pymongo


class Configuration( object ):
    MONGO_HOST = '192.168.1.31'
    MONGO_PORT = 27017
    MONGO_USER = None
    MONGO_PASS = None

    WEBSITE = 'http://DESKTOP-QCP8I15.localdomain:3000'



class Moment( object ):
    __slots__ = ( 'request', 'response', 'timing', 'org_id', 'user_id', 'visibility' )
    def __init__( self, request = None, response = None ):
        self.request  = Request( request )
        self.response = Response( response ) if response else None
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
                print( ex )


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
            #print( request )
            #for k in [ 'host', 'host_header', 'pretty_host' ]:
            #    print({ k: getattr( request, k ) })

            '''
            for k in [ 'text', 'content', 'raw_content', 'urlencoded_form', 'multipart_form' ]:
                val = getattr( request, k )
                b = not not val
                print({
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
            #    print({
            #      k: val,
            #      'bool': b
            #    })

            self.http_version = response.http_version
            self.status_code = response.status_code

            self.load_headers( response )
            self.load_body( response )



class Scintillator:
    #0
    def __init__( self ):
        print( '0: __init__' )
        self.connect()


    def connect( self ):
        self.mongo = pymongo.MongoClient( Configuration.MONGO_HOST, Configuration.MONGO_PORT )


    ################ Core Events ################
    #1
    def load(self, entry: mitmproxy.addonmanager.Loader):
        """
            Called when an addon is first loaded. This event receives a Loader
            object, which contains methods for adding options and commands. This
            method is where the addon configures itself.
        """
        print( '1: load' )


    #2
    def running(self):
        """
            Called when the proxy is completely up and running. At this point,
            you can expect the proxy to be bound to a port, and all addons to be
            loaded.
        """
        print( '2: running' )


    #3
    def configure(self, updated: typing.Set[str]):
        """
            Called when configuration changes. The updated argument is a
            set-like object containing the keys of all changed options. This
            event is called during startup with all options in the updated set.
        """
        print( '3: configure' )


    ################ Global Events ################
    #4 - global
    def error(self, flow: mitmproxy.http.HTTPFlow):
        """
            An HTTP error has occurred, e.g. invalid server responses, or
            interrupted connections. This is distinct from a valid server HTTP
            error response, which is simply a response with an HTTP error code.
        """
        print( '4: error' )


    #4 - global
    def log(self, entry: mitmproxy.log.LogEntry):
        """
            Called whenever a new log entry is created through the mitmproxy
            context. Be careful not to log from this event, which will cause an
            infinite loop!
        """
        print( '4: log' )

    '''
    #4 - global
    def next_layer(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            Network layers are being switched. You may change which layer will
            be used by returning a new layer object from this event.
        """
        print( '4: next_layer' )
    '''
    '''
    #4 - global
    def update(self, flows: typing.Sequence[mitmproxy.flow.Flow]):
        """
            Update is called when one or more flow objects have been modified,
            usually from a different addon.
        """
        print( '4: update' )
    '''

    ################ HTTP Events ################
    '''
    #5
    def clientconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has connected to mitmproxy. Note that a connection can
            correspond to multiple HTTP requests.
        """
        print( '5: clientconnect' )
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
        print( '6: http_connect' )
        #TODO: if there are files, return 500
        #TODO: if request size > 1k
        #TODO: if response size > 1k
    '''

    def authorize_request( self, flow: mitmproxy.http.HTTPFlow ):
        # init
        flow.cancelled = False
        flow.org       = None
        flow.user      = None

        #TODO: check content-type
        #TODO: check content-length


        #for key in flow.request.headers['x-client-key']:


        #TODO: check for base64
        client_key = None
        for value in flow.request.headers.get_all( 'x-client-key' ):
            if client_key:
                print( "Ignoring X-Client-Key: {0}".format( value ) )
                #TODO: strip this
            
            else:
                print( "Found X-Client-Key: {0}".format( value ) )
                client_key = value
                #TODO: strip this

        
        for value in flow.request.headers.get_all( 'x-api-key' ):
            if client_key:
                print( "Ignoring X-Api-Key: {0}".format( value ) )
                #TODO: strip this
            
            else:
                print( "Found X-Api-Key: {0}".format( value ) )
                client_key = value
                #TODO: strip this


        # anonymous is ratelimited by IP
        if not client_key:
            #TODO: check rate limit
            flow.cancelled = False
            flow.user = None
            return


        print( 'Auth user' )
        # user with bad client_key is blocked
        flow.user = self.mongo.scintillator.users.find_one({ "client_key": client_key })
        if flow.user:
            if flow.user['enabled']:
                flow.org = self.mongo.scintillator.orgs.find_one({ "_id": flow.user['org_id'] })

            else:
                print( 'User disabled' )
                self.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )
                return
        else:
            print( 'User not found, checking org...' )
            flow.org = self.mongo.scintillator.orgs.find_one({ "client_key": client_key })


        print( 'Auth org' )
        if flow.org:
            if flow.org['enabled']:
                pass

            else:
                print( 'Org disabled' )
                self.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )
                return

        else:
            print( 'Org not found' )
            self.cancel_proxy( flow, "Proxy: Authentication Failed", 407 )
            return


        #TODO: check rate limit
        query = {
            "org_client_key": flow.org['client_key'],
            "proxy_evergreen": { "$gt": 0 }
        }
        update = {
            '$inc': {
                "proxy_evergreen": -1
            }
        }
        res = self.mongo.scintillator.rate_limits.update_one( query, update )
        if res.modified_count:
            return


        query = {
            "org_client_key": flow.org['client_key'],
            "proxy_adhoc": { "$gt": 0 }
        }
        update = {
            '$inc': {
                "proxy_adhoc": -1
            }
        }
        res = self.mongo.scintillator.rate_limits.update_one( query, update )
        if res.modified_count:
            return


        self.cancel_proxy( flow, "Proxy: Too Many Requests", 429 )


    def cancel_proxy( self, flow, content, status_code, headers=None ):
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


    #7
    def requestheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP request headers were successfully read. At this point, the body
            is empty.
        """
        print( '7: requestheaders' )
        flow.cancelled = False
        flow.org = None
        flow.user = None
        self.authorize_request( flow )


    #
    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """
        print( '8: request' )
        if not flow.cancelled:
            # https://mitmproxy.readthedocs.io/en/v2.0.2/scripting/api.html
            moment = Moment( flow.request )
            
            if flow.user:
                moment.org_id = flow.user['org_id']
                moment.user_id = flow.user['_id']
                moment.visibility = 'private'
            else:
                moment.visibility = 'public'

            as_dict = moment.to_dict()
            #print( as_dict )
            res = self.mongo.scintillator.moments.insert_one( as_dict )

            flow.id = res.inserted_id
            print({ 'flow.id': flow.id })


    ################ Intermediate Core Event ################
    '''
    #9
    def serverconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has connected to a server. Note that a connection can
            correspond to multiple requests.
        """
        print( '9: serverconnect' )
    '''

    ################ HTTP Events ################
    def authorize_response( self, flow: mitmproxy.http.HTTPFlow ):
        #TODO: check content-type
        #TODO: check content-length
        #flow.cancelled = True
        #flow.response = mitmproxy.http.HTTPResponse.make(
        #    407,  # (optional) status code
        #    "Proxy Authentication Failed",  # (optional) content
        #    {"Content-Type": "text/plain"}  # (optional) headers
        #)
        pass


    #10
    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP response headers were successfully read. At this point, the body
            is empty.
        """

        print( '10: responseheaders' )
        self.authorize_response( flow )


    #11
    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """
        print( '11: response' )
        if not flow.cancelled:
            response = Response( flow.response )
            as_dict = response.to_dict()
            #print( as_dict )

            res = self.mongo.scintillator.moments.update_one(
              { "_id": flow.id },
              { "$set": { "response": as_dict } }
            )

            flow.response.headers["S-Moment-Id"] = str( flow.id )
            flow.response.headers["Link"] = '{0}/moment/{1}'.format( Configuration.WEBSITE, str( flow.id ) )


    ################ Final Core Event ################
    '''
    #12
    def clientdisconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has disconnected from mitmproxy.
        """
        print( '12: clientdisconnect' )
    '''
    '''
    #13
    def serverdisconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has disconnected from a server.
        """
        print( '13: serverdisconnect' )
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
        print( '14: done' )


addons = [
    Scintillator()
]
