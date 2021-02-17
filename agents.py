# -*- coding: utf-8 -*-

import datetime, logging, re
import pymongo

from config import Configuration
from enums  import FlowAttributes, RuleTarget
from models import HTTPData, Moment


class AgentBase( object ):
    def __init__( self, *args, **kwargs ):
        logging.info( "Creating '{0}'".format( type( self ) ) )
        
        if args:
            logging.warning( "Args ignored: {0}".format( args ) )

        if kwargs:
            logging.warning( "KW Args ignored: {0}".format( kwargs ) )


    @staticmethod
    def create( agent ):
        if agent['type'] == 'AlertAgent':
            return AlertAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'AuthorizedAgent':
            return AuthorizedAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'DenyAgent':
            return DenyAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'IgnoreAgent':
            return IgnoreAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'LastAgent':
            return LastAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'RequestDetailAgent':
            return RequestDetailAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'RequestSummaryAgent':
            return RequestSummaryAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'ResponseDetailAgent':
            return ResponseDetailAgent( *agent['args'], **agent['kwargs'] )

        if agent['type'] == 'ResponseSummaryAgent':
            return ResponseSummaryAgent( *agent['args'], **agent['kwargs'] )

        raise NotImplementedError( agent['type'] )


    def process( self, flow, target:str ):
        raise NotImplementedError()


    def validate( self, flow, target:str ):
        if not flow:
            raise TypeError( "Expected type 'mitmproxy.Flow', got None instead" )

        RuleTarget.validate( target )


class MongoAgent( AgentBase ):
    MONGO = None

    def __init__( self, *args, **kwargs ):
        pass


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

    def __init__( self, status_code=403, content='Blocked', headers={}, *args, **kwargs ):
        super( DenyAgent, self ).__init__( *args, **kwargs )

        self.status_code = status_code or 403
        self.content     = content or 'Blocked'
        self.headers     = headers or {
            'Content-Type': 'text/plain'
        }


    def process( self, flow, target:str ):
        if flow:
            flow.attributes.add( FlowAttributes.DENIED )
            self.cancel_response( flow )
            #TODO: cancel the flow
            
        else:
            raise TypeError( "Expected type 'mitmproxy.Flow', got None instead" )


    def cancel_response( self, flow ):
        try:
            import mitmproxy
            flow.response = mitmproxy.http.HTTPResponse.make( self.status_code, self.content, self.headers )
        except Exception as ex:
            logging.warning( ex )



# authorize the capture
class AuthorizedAgent( MongoAgent ):
    BASE_64 = re.compile( '^[0-9A-Za-z+/]+$' )

    def process( self, flow, target:str ):
        self.validate( flow, target )


        if FlowAttributes.AUTHORIZED in flow.attributes:
            logging.debug( 'flow is already authorized' )
            return

        #TODO: skip auth

        try:
            api_key = self.get_api_key( flow )
            logging.debug( api_key )
        except Exception as ex:
            logging.warning( "AuthorizedAgent.get_api_key() failed: {0}".format( ex ) )
            
            #TODO: DenyAgent.process()
            raise PermissionError()


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

        #TODO: DenyAgent.process()
        raise PermissionError()


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



class RequestBaseAgent( AuthorizedAgent ):
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
    def record_moment( cls, moment:Moment ):
        if moment._id:
            as_dict = flow.moment.response.to_dict()
            #logging.info( as_dict )
            res = cls.get_mongo( Configuration.MONGO_DB, 'moments' ).update_one(
                { "_id": flow.moment._id },
                { "$set": {
                    "response": as_dict,
                    "timing": flow.timing
                }}
            )
        
        
        else:
            as_dict = moment.to_dict()
            #logging.info( as_dict )
            res = cls.get_mongo_collection( 'moments' ).insert_one( as_dict )
            moment._id = res.inserted_id
            logging.info({ 'moment._id': moment._id })



class RequestDetailAgent( RequestBaseAgent ):
    def __init__( self, *args, **kwargs ):
        super( RequestDetailAgent, self ).__init__( *args, **kwargs )


    def process( self, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super( RequestDetailAgent, self ).process( flow, target )

        if flow.moment._id:
            #this has already been recorded
            return


        if flow.moment.request.is_detail:
            self.record_moment( flow.moment )

        elif flow.moment.request.is_summary:
            if target == RuleTarget.requestheaders:
                # wait for next phase
                flow.request.stream = False
            else:
                # take what we have
                self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "RequestDetailAgent.process( '{0}' )".format( target ) )



class RequestSummaryAgent( RequestBaseAgent ):
    def __init__( self, *args, **kwargs ):
        super( RequestSummaryAgent, self ).__init__( *args, **kwargs )


    def process( self, flow, target:str ):
        self.validate( flow, target )

        #AuthorizedAgent.process()
        super( RequestSummaryAgent, self ).process( flow, target )

        if flow.moment._id:
            #this has already been recorded
            return


        if flow.moment.request.content_length:
            logging.warning( "{0} has content_length( {1} )".format(
                flow.moment.request.method.upper(),
                flow.moment.request.content_length
            ))


        if flow.moment.request.is_detail:
            flow.moment.request.body = None
            flow.moment.request.is_detail = False
            flow.moment.request.is_summary = True
            self.record_moment( flow.moment )

        elif flow.moment.request.is_summary:
            if target == RuleTarget.requestheaders:
                # optimize
                flow.request.stream = True

            self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "RequestSummaryAgent.process( '{0}' )".format( target ) )



class ResponseDetailAgent( AuthorizedAgent ):
    def __init__( self, *args, **kwargs ):
        super( ResponseDetailAgent, self ).__init__( *args, **kwargs )


    def process( self, flow, target:str ):
        self.validate( flow, target )

        if target == RuleTarget.requestheaders \
            or target == RuleTarget.request:
            return

        #AuthorizedAgent.process()
        super( ResponseDetailAgent, self ).process( flow, target )

        if flow.moment.response.is_detail:
            self.record_moment( flow.moment )

        elif flow.moment.response.is_summary:
            if target == RuleTarget.responseheaders:
                # wait for next phase
                flow.response.stream = False
            else:
                # take what we have
                self.record_moment( flow.moment )

        else:
            raise NotImplementedError( "ResponseDetailAgent.process( '{0}' )".format( target ) )



class ResponseSummaryAgent( AuthorizedAgent ):
    def __init__( self, *args, **kwargs ):
        super( ResponseSummaryAgent, self ).__init__( *args, **kwargs )


    @classmethod
    def process( cls, flow, target:str ):
        self.validate( flow, target )

        if target == RuleTarget.requestheaders \
            or target == RuleTarget.request:
            return

        #AuthorizedAgent.process()
        super( ResponseSummaryAgent, self ).process( flow, target )

        if flow.moment.response.content_length:
            logging.warning( "Response has content_length( {0} )".format(
                flow.moment.response.content_length
            ))


        if flow.moment.response.is_detail:
            flow.moment.response.body = None
            flow.moment.response.is_detail = False
            flow.moment.response.is_summary = True
            self.record_moment( flow.moment )

        elif flow.moment.response.is_summary:
            if target == RuleTarget.responseheaders:
                # optimize
                flow.response.stream = True

            self.record_request( flow )

        else:
            raise NotImplementedError( "ResponseSummaryAgent.process( '{0}' )".format( target ) )

