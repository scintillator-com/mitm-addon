# -*- coding: utf-8 -*-

import datetime, logging, re
import pymongo

from config import Configuration
from enums  import FlowAttributes, FlowTasks, RuleTarget
from models import HTTPData, Moment


class AgentBase( object ):
    def __init__( self, **kwargs ):
        logging.info( "Creating '{0}'".format( type( self ) ) )
        
        if kwargs:
            logging.warning( "KW Args ignored: {0}".format( kwargs ) )


    @staticmethod
    def create( agent ):
        if agent['type'] == 'AlertAgent':
            return AlertAgent( **agent['kwargs'] )

        if agent['type'] == 'AuthorizedAgent':
            return AuthorizedAgent( **agent['kwargs'] )

        if agent['type'] == 'DenyAgent':
            return DenyAgent( **agent['kwargs'] )

        if agent['type'] == 'IgnoreAgent':
            return IgnoreAgent( **agent['kwargs'] )

        if agent['type'] == 'LastAgent':
            return LastAgent( **agent['kwargs'] )

        if agent['type'] == 'RequestDetailAgent':
            return RequestDetailAgent( **agent['kwargs'] )

        if agent['type'] == 'RequestSummaryAgent':
            return RequestSummaryAgent( **agent['kwargs'] )

        if agent['type'] == 'ResponseDetailAgent':
            return ResponseDetailAgent( **agent['kwargs'] )

        if agent['type'] == 'ResponseSummaryAgent':
            return ResponseSummaryAgent( **agent['kwargs'] )

        raise NotImplementedError( agent['type'] )


    def process( self, flow, target:str ):
        raise NotImplementedError()


    def validate( self, flow, target:str ):
        if not flow:
            raise TypeError( "Expected type 'mitmproxy.Flow', got None instead" )

        RuleTarget.validate( target )



class MongoAgent( AgentBase ):
    MONGO = None

    @classmethod
    def connect( cls ):
        cls.get_mongo()


    @classmethod
    def get_mongo( cls ):
        if not cls.MONGO:
            cls.MONGO = pymongo.MongoClient( cls.get_mongo_uri() )
        return cls.MONGO


    @classmethod
    def get_mongo_db( cls ):
        return cls.get_mongo()[ Configuration.MONGO_DB ]


    @classmethod
    def get_mongo_collection( cls, collection_name ):
        return cls.get_mongo_db()[ collection_name ]


    @staticmethod
    def get_mongo_uri():
        options = ''
        if Configuration.MONGO_OPTIONS:
            options = '?'+ urlencode( Configuration.MONGO_OPTIONS )

        port = ''
        if Configuration.MONGO_PORT != 27017:
            port = ':{port}'.format( port=Configuration.MONGO_PORT )

        scheme = 'mongodb'
        if Configuration.MONGO_SRV:
            scheme = 'mongodb+srv'

        user_pass = ''
        if Configuration.MONGO_USER and Configuration.MONGO_PASS:
            user_pass = '{username}:{password}@'.format(
                username=urllib.parse.quote_plus( Configuration.MONGO_USER ),
                password=urllib.parse.quote_plus( Configuration.MONGO_PASS )
            )

        formatted = "{scheme}://{user_pass}{host}{port}/{dbname}{options}".format(
            scheme=scheme,
            user_pass=user_pass,
            host=Configuration.MONGO_HOST,
            port=port,
            dbname=Configuration.MONGO_DB,
            options=options
        )

        logging.debug( formatted )
        return formatted



class AlertAgent( AgentBase ):
    def process( self, flow, target:str ):
        self.validate( flow, target )
        raise NotImplementedError( 'AlertAgent' )



# 1) do not process any other rules
# 2) cancel the current request/response
class DenyAgent( AgentBase ):
    __slots__ = ( 'status_code', 'content', 'headers' )

    def __init__( self, status_code=403, content='Blocked', headers={}, **kwargs ):
        super().__init__( **kwargs )

        self.status_code = status_code or 403
        self.content     = content or 'Blocked'
        self.headers     = headers or {
            'Content-Type': 'text/plain'
        }


    def process( self, flow, target:str ):
        if flow:
            flow.attributes.add( FlowAttributes.DENIED )
            self.cancel_response( flow )

        else:
            raise TypeError( "Expected type 'mitmproxy.Flow', got None instead" )


    def cancel_response( self, flow ):
        try:
            import mitmproxy
            flow.response = mitmproxy.http.HTTPResponse.make( self.status_code, self.content, self.headers )
        except Exception as ex:
            logging.warning( ex )



# authorize the capture
class AuthorizedAgent( MongoAgent, DenyAgent ):
    BASE_64 = re.compile( '^[0-9A-Za-z+/]+$' )

    def __init__( self, permission_error=None, **kwargs ):
        #TODO: how to call separate super constructors?

        kwargs[ 'content' ] = 'Unauthorized'
        kwargs[ 'headers' ] = {
            'Content-Type': 'text/plain'
        }
        kwargs[ 'status_code' ] = 401
        if permission_error:
            logging.info( permission_error )
            for key in ( 'content', 'headers', 'status_code' ):
                if key in permission_error:
                    kwargs[ key ] = permission_error[ key ]

        super().__init__( **kwargs )


    def process( self, flow, target:str ):
        self.validate( flow, target )

        if Configuration.SKIP_AUTH:
            logging.debug( 'SKIP_AUTH' )
            return

        if FlowAttributes.AUTHORIZED in flow.attributes:
            logging.debug( 'flow is already authorized' )
            return


        try:
            api_key = self.get_api_key( flow )
            logging.debug( api_key )
        except Exception as ex:
            logging.warning( "AuthorizedAgent.get_api_key() failed: {0}".format( ex ) )
            self.cancel_response( flow )
            return



        if api_key:
            auth = self.authorize_user( api_key )
            if auth:
                flow.org, flow.user = auth
            else:
                flow.org = self.authorize_org( api_key )
                logging.debug( flow.org )


            if flow.org and self.check_ratelimit( flow.org['client_key'] ):
                self.set_auth_attributes( flow )
                flow.attributes.add( FlowAttributes.AUTHORIZED )
                return


        self.cancel_response( flow )
        return


    @classmethod
    def authorize_org( cls, client_key ):
        org = cls.get_org({ "client_key": client_key })
        if org:
            if org['is_enabled']:
                logging.debug( 'Org enabled' )
                return org

            else:
                logging.info( 'Org disabled' )
                return False

        else:
            logging.info( 'Org not found' )
            return None


    @classmethod
    def authorize_user( cls, api_key ):
        user = cls.get_user({ "client_key": api_key })
        if user:
            if user['is_enabled']:
                logging.debug( 'User enabled' )
                org = cls.get_org({ "_id": user['org_id'] })
                return ( org, user )
        
            else:
                logging.info( 'User disabled' )
                return False

        else:
            logging.info( 'User not found...' )
            return None


    @classmethod
    def check_ratelimit( cls, org_api_key ):
        # TODO
        #if Configuration.SKIP_AUTH:
        #    logging.info( 'SKIP_AUTH' )
        #    return True

        if cls._check_ratelimit( org_api_key, 'proxy_evergreen' ):
            logging.debug( 'Used evergreen ratelimit' )
            return True

        elif cls._check_ratelimit( org_api_key, 'proxy_adhoc' ):
            logging.debug( 'Used adhoc ratelimit' )
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
        res = cls.get_mongo_collection( 'rate_limits' ).update_one( query, update )
        return res.modified_count >= 0


    @classmethod
    def get_api_key( cls, flow ):
        my_key = None
        keep_fields = []
        # check_headers = ( 'x-api-key', 'x-client-key' )
        for key, value in flow.request.headers.items( True ):
            #if key.lower() in check_headers:
            if key.lower() == 'x-api-key':
                if cls.is_base64( value ) and cls.is_scintillator_key( value ):
                    if my_key:
                        logging.info( "Ignoring Scintillator '{0}': '{1}'".format( key, value ) )
                    else:
                        logging.info( "Found Scintillator '{0}': '{1}'".format( key, value ) )
                        my_key = value

                else:
                    logging.debug( "Ignoring '{0}': '{1}'".format( key, value ) )
                    keep_fields.append(( key, value ))

            else:
                logging.debug( "Ignoring '{0}': '{1}'".format( key, value ) )
                keep_fields.append(( key, value ))

        # rebuild if something changed
        if my_key:
            flow.request.headers.clear()
            for key, value in keep_fields:
                flow.request.headers.add( key, value )

        return my_key


    @classmethod
    def get_org( cls, query ):
        return cls.get_mongo_collection( 'orgs' ).find_one( query )


    @classmethod
    def get_user( cls, query ):
        return cls.get_mongo_collection( 'users' ).find_one( query )


    @classmethod
    def is_base64( cls, value ):
        return cls.BASE_64.match( value )


    @classmethod
    def is_scintillator_key( cls, value ):
        return value.endswith( '/tor' )


    @classmethod
    def set_auth_attributes( cls, flow ):
        if flow.user:
            flow.moment.org_id     = flow.user['org_id']
            flow.moment.user_id    = flow.user['_id']
            flow.moment.visibility = 'private'

        elif flow.org:
            flow.moment.org_id     = flow.org['_id']
            flow.moment.user_id    = None
            flow.moment.visibility = 'private'

        else:
            flow.moment.org_id     = None
            flow.moment.user_id    = None
            flow.moment.visibility = 'public'



# 1) do not process any other rules
# 2) cancel any pending captures
# good for files/images
#class IgnoreAgent( LastAgent ):
#    def process( self, flow, target:str ):
#        pass



class RecordAgentBase( AuthorizedAgent ):
    @classmethod
    def moment_recorded( cls, moment:Moment ):
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

            res = cls.get_mongo_collection( 'projects' ).update_one( query, update )
            if res.modified_count == 0:
                created = datetime.datetime.now()
                project = query
                project["created"]   = created
                project["modified"]  = created
                project["is_locked"] = True
                project["moments"]   = 1
                res = cls.get_mongo_collection( 'projects' ).insert_one( project )


    @classmethod
    def record_moment( cls, moment:Moment ):
        request_dict  = None
        if moment.request:
            request_dict = moment.request.to_dict()
            #logging.info( request_dict )

        response_dict = None
        if moment.response:
            response_dict = moment.response.to_dict()
            #logging.info( response_dict )

        if moment._id:
            res = cls.get_mongo_collection( 'moments' ).update_one(
                { "_id": moment._id },
                { "$set": {
                    "request":  request_dict,
                    "response": response_dict,
                    "timing":   moment.timing
                }}
            )
            logging.debug( 'Moment updated' )

        else:
            res = cls.get_mongo_collection( 'moments' ).insert_one({
                "request":  request_dict,
                "response": response_dict,
                "timing":   moment.timing
            })

            moment._id = res.inserted_id
            logging.info({ 'moment._id': moment._id })
            cls.moment_recorded( moment )
            logging.debug( 'Moment inserted' )



class RequestDetailAgent( RecordAgentBase ):
    def process( self, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super().process( flow, target )

        if FlowTasks.SAVE_REQUEST_DETAIL in flow.completed:
            #this has already been recorded
            return


        if target < RuleTarget.request:
            flow.request.stream = False
            flow.pending.append( FlowTasks.LOAD_REQUEST_DETAIL )
            flow.pending.append( FlowTasks.SAVE_REQUEST_DETAIL )
            return


        if flow.moment.request.is_detail:
            # perfect
            self.record_moment( flow.moment )

        elif flow.moment.request.is_summary:
            # take what we have
            self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "RequestDetailAgent.process( '{0}' )".format( target ) )



class RequestSummaryAgent( RecordAgentBase ):
    def process( self, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super().process( flow, target )

        if 'SAVE_REQUEST_SUMMARY' in flow.completed:
            #this has already been recorded
            return


        if target == RuleTarget.requestheaders:
            flow.request.stream = True


        if flow.moment.request.is_detail:
            # reduce
            flow.moment.request.body = None
            flow.moment.request.is_detail = False
            flow.moment.request.is_summary = True
            self.record_moment( flow.moment )

        elif flow.moment.request.is_summary:
            self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "RequestSummaryAgent.process( '{0}' )".format( target ) )



class ResponseDetailAgent( RecordAgentBase ):
    def process( self, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super().process( flow, target )

        if FlowTasks.SAVE_RESPONSE_DETAIL in flow.completed:
            #this has already been recorded
            return


        if target < RuleTarget.response:
            if flow.response:
                flow.response.stream = False

            flow.pending.append( FlowTasks.LOAD_RESPONSE_DETAIL )
            flow.pending.append( FlowTasks.SAVE_RESPONSE_DETAIL )
            return


        if flow.moment.response.is_detail:
            # perfect
            self.record_moment( flow.moment )

        elif flow.moment.response.is_summary:
            # take what we have
            self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "ResponseDetailAgent.process( '{0}' )".format( target ) )



class ResponseSummaryAgent( RecordAgentBase ):
    @classmethod
    def process( cls, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super().process( flow, target )

        if 'SAVE_RESPONSE_SUMMARY' in flow.completed:
            #this has already been recorded
            return


        if target < RuleTarget.responseheaders:
            flow.pending.append( 'SAVE_RESPONSE_SUMMARY' )
            return


        if target == RuleTarget.responseheaders:
            flow.response.stream = False


        if flow.moment.response.is_detail:
            # reduce
            flow.moment.response.body = None
            flow.moment.response.is_detail = False
            flow.moment.response.is_summary = True
            self.record_moment( flow.moment )

        elif flow.moment.response.is_summary:
            self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "ResponseSummaryAgent.process( '{0}' )".format( target ) )

