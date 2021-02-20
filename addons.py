# -*- coding: utf-8 -*-

"""Generic event hooks."""
import datetime, logging, logging.handlers, os, sys, typing

import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.log
import mitmproxy.proxy.protocol

#from mitmproxy import ctx
#from mitmproxy.net import http
from mitmproxy.script import concurrent

from agents import RecordAgentBase
from config import Configuration
from enums  import FlowAttributes, FlowTasks, RuleTarget
from models import HTTPData, Moment, Request, Response, Rule, RuleSet


class AddonBase( object ):
    RULES_MANAGER = None

    @classmethod
    def add_xff_headers( cls, flow ):
        #apply forward header(s)
        #TODO: is there another XFF header?
        if flow.client_conn.address[0].startswith( '::ffff:' ):
            ip_addr = flow.client_conn.address[0][7:]
        else:
            ip_addr = flow.client_conn.address[0]
        flow.request.headers.add( 'X-Forwarded-For', ip_addr )
        #TODO: X-Forwarded


    @classmethod
    def configure_logging( cls, level ):
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

        hpack_logger = logging.getLogger( 'hpack.hpack' )
        hpack_logger.setLevel( logging.INFO )


    @staticmethod
    def is_flow_denied( flow ):
        return FlowAttributes.DENIED in flow.attributes


    @staticmethod
    def is_flow_ignored( flow ):
        return FlowAttributes.IGNORED in flow.attributes


    @classmethod
    def process_rules( cls, flow:mitmproxy.http.HTTPFlow, target:str ):
        if cls.is_flow_denied( flow ):
            logging.debug( "SKIP: process_rules( '{0}' ) because flow is DENIED".format( target ) )
            return

        if cls.is_flow_ignored( flow ):
            logging.debug( "SKIP: process_rules( '{0}' ) because flow is IGNORED".format( target ) )
            return

        if not cls.RULES_MANAGER:
            cls.RULES_MANAGER = RuleSet.load_file( Configuration.RULES_FILE )

        cls.RULES_MANAGER.process( flow, target )


    @classmethod
    def process_tasks( cls, flow, abilities ):
        remaining = []
        for task in flow.pending:
            if task in abilities:
                cls.process_task( flow, task )
            else:
                remaining.append( task )
        flow.pending = remaining


    @classmethod
    def process_task( cls, flow, task ):
        if task == FlowTasks.LOAD_REQUEST_DETAIL:
            cls.load_request_detail( flow )
            flow.completed.append( task )
            return

        if task == FlowTasks.LOAD_REQUEST_SUMMARY:
            cls.load_request_summary( flow )
            flow.completed.append( task )
            return

        if task == FlowTasks.LOAD_RESPONSE_DETAIL:
            cls.load_response_detail( flow )
            flow.completed.append( task )
            return

        if task == FlowTasks.LOAD_RESPONSE_SUMMARY:
            cls.load_response_summary( flow )
            flow.completed.append( task )
            return

        if task == FlowTasks.SAVE_REQUEST_DETAIL:
            cls.save_request_detail( flow )
            flow.completed.append( task )
            return

        if task == FlowTasks.SAVE_RESPONSE_DETAIL:
            cls.save_response_detail( flow )
            flow.completed.append( task )
            return

        raise NotImplementedError( task )


    @staticmethod
    def load_request_detail( flow ):
        if flow.request.stream:
            # data is in flow.client_conn.rfile
            flow.moment.timing['request_parsed'] = None
        else:
            flow.moment.request.load_body( flow.request )
            flow.moment.timing['request_parsed'] = datetime.datetime.now()
            flow.moment.request.measure_body( flow )


    @staticmethod
    def load_request_summary( flow ):
        flow.moment.request = Request( flow.request )

        if flow.server_conn:
            flow.moment.request.port = flow.server_conn.address[1]
            if flow.moment.request.port == 80:
                flow.moment.request.scheme = 'http'
            elif flow.moment.request.port == 443:
                flow.moment.request.scheme = 'https'
            else:
                logging.warning( "Can't default scheme for port({0})".format( flow.moment.request.port ))
        else:
            logging.warning( "Empty flow.server_conn".format( flow.moment.request.port ))

        total_length = flow.moment.request.measure()
        logging.debug( 'content_length: {0}'.format( flow.moment.request.content_length ) )
        logging.debug( 'total_length:   {0}'.format( total_length ) )

        if flow.moment.request.content_length:
            #logging.warning( "Request has Content-Length( {0} )".format(
            #    flow.moment.request.content_length
            #))
            pass

        elif flow.moment.request.content_type:
            logging.warning( 'Request has Content-Type without Content-Length' )
            #raise 411


    @staticmethod
    def load_response_detail( flow ):
        if flow.response.stream:
            # data is in flow.server_conn.rfile
            flow.moment.timing['response_parsed'] = None
        else:
            flow.moment.response.load_body( flow.response )
            flow.moment.timing['response_parsed'] = datetime.datetime.now()
            flow.moment.response.measure_body( flow )


    @staticmethod
    def load_response_summary( flow ):
        flow.moment.response = Response( flow.response )
        total_length = flow.moment.response.measure()
        logging.debug( 'content_length: {0}'.format( flow.moment.response.content_length ) )
        logging.debug( 'total_length:   {0}'.format( total_length ) )

        if flow.moment.response.content_length:
            #logging.warning( "Response has Content-Length( {0} )".format(
            #    flow.moment.response.content_length
            #))
            pass

        elif flow.moment.response.content_type:
            logging.warning( 'Response has Content-Type without Content-Length' )
            #raise 411


    @staticmethod
    def save_request_detail( flow ):
        RecordAgentBase.record_moment( flow.moment )


    @staticmethod
    def save_response_detail( flow ):
        RecordAgentBase.record_moment( flow.moment )



class ScintillatorAddon( AddonBase ):
    #0
    def __init__( self, level=logging.DEBUG ):
        self.configure_logging( level )
        logging.info( '''
  /////////////////
 // 0: __init__ //
/////////////////
''' )


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
    '''


    #7
    def requestheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP request headers were successfully read. At this point, the body
            is empty.
        """
        logging.info( '7: requestheaders' )
        
        try:
            abilities = {
                FlowTasks.LOAD_REQUEST_SUMMARY,
                FlowTasks.SAVE_REQUEST_SUMMARY
            }

            #request_started??
            request_received = datetime.datetime.now()

            # init
            flow.attributes = set()
            flow.completed  = []
            flow.moment     = Moment()
            flow.moment.timing = { 'request_received': request_received }
            flow.pending    = [ FlowTasks.LOAD_REQUEST_SUMMARY ]
            flow.org        = None
            flow.status     = FlowAttributes.NONE
            flow.user       = None

            #pre - load request summary
            self.process_tasks( flow, abilities )
            self.add_xff_headers( flow )
            self.process_rules( flow, RuleTarget.requestheaders )
            self.process_tasks( flow, abilities )
        except Exception as ex:
            logging.exception( ex )


    #8
    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """
        logging.info( '8: request' )

        try:
            abilities = {
                FlowTasks.LOAD_REQUEST_DETAIL,
                FlowTasks.SAVE_REQUEST_DETAIL,
                FlowTasks.SAVE_REQUEST_SUMMARY
            }

            if flow.request.scheme:
                flow.moment.request.scheme = flow.request.scheme

            if flow.request.port:
                flow.moment.request.port = flow.request.port

            if self.is_flow_denied( flow ):
                logging.debug( "SKIP: request( flow ) because flow is DENIED" )
                return

            if self.is_flow_ignored( flow ):
                logging.debug( "SKIP: request( flow ) because flow is IGNORED" )
                return


            self.process_tasks( flow, abilities )
            self.process_rules( flow, RuleTarget.request )
            self.process_tasks( flow, abilities )
        except Exception as ex:
            logging.exception( ex )


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
        
        try:
            #response_started??
            response_received = datetime.datetime.now()
            abilities = {
                FlowTasks.LOAD_RESPONSE_SUMMARY,
                FlowTasks.SAVE_REQUEST_DETAIL,
                FlowTasks.SAVE_REQUEST_SUMMARY,
                FlowTasks.SAVE_RESPONSE_SUMMARY
            }

            if self.is_flow_denied( flow ):
                logging.debug( "SKIP: responseheaders( flow ) because flow is DENIED" )
                return

            if self.is_flow_ignored( flow ):
                logging.debug( "SKIP: responseheaders( flow ) because flow is IGNORED" )
                return


            flow.moment.timing[ 'response_received' ] = response_received
            flow.pending.append( FlowTasks.LOAD_RESPONSE_SUMMARY )
            self.process_tasks( flow, abilities )
            self.process_rules( flow, RuleTarget.responseheaders )
            self.process_tasks( flow, abilities )
        except Exception as ex:
            logging.exception( ex )


    #11
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """
        logging.info( '11: response' )

        try:
            abilities = {
                FlowTasks.LOAD_RESPONSE_DETAIL,
                FlowTasks.SAVE_REQUEST_DETAIL,
                FlowTasks.SAVE_REQUEST_SUMMARY,
                FlowTasks.SAVE_RESPONSE_DETAIL,
                FlowTasks.SAVE_RESPONSE_SUMMARY
            }

            if self.is_flow_denied( flow ):
                logging.debug( "SKIP: response( flow ) because flow is DENIED" )
                return

            if self.is_flow_ignored( flow ):
                logging.debug( "SKIP: response( flow ) because flow is IGNORED" )
                return


            flow.pending.append( FlowTasks.LOAD_RESPONSE_DETAIL )
            self.process_tasks( flow, abilities )
            self.process_rules( flow, RuleTarget.response )
            self.process_tasks( flow, abilities )
        except Exception as ex:
            logging.exception( ex )


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
