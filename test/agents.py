# -*- coding: utf-8 -*-

import logging, sys, unittest

from agents import AgentBase, AlertAgent, AuthorizedAgent, DenyAgent, RequestDetailAgent, RequestSummaryAgent#, ResponseDetailAgent, ResponseSummaryAgent
from errors import RequestDeniedError
from mocks import MitmFlow, MitmHeaders, MitmRequest
#from ..config import Configuration
#from ..models import Moment, Request, Response, Rule, RuleFilters, RulesManager


class BaseTestCase( unittest.TestCase ):
    #result = None

    def assertEqual( self, *args, **kwargs ):
        #BaseTestCase.result.assertions += 1
        return super( BaseTestCase, self ).assertEqual( *args, **kwargs )
    
    def assertFalse( self, *args, **kwargs ):
        #BaseTestCase.result.assertions += 1
        return super( BaseTestCase, self ).assertFalse( *args, **kwargs )
    
    def assertRaises( self, *args, **kwargs ):
        #BaseTestCase.result.assertions += 1
        return super( BaseTestCase, self ).assertRaises( *args, **kwargs )

    def assertTrue( self, *args, **kwargs ):
        #BaseTestCase.result.assertions += 1
        return super( BaseTestCase, self ).assertTrue( *args, **kwargs )

    '''
    # override
    def defaultTestResult( self ):
        pass

    # override
    def _makeResult( self ):
        if BaseTestCase.result:
            pass
        else:
            print( 'created' )
            BaseTestCase.result = TextTestResult()
            BaseTestCase.result.assertions = 0

        return BaseTestCase.result
    '''


class TestAgents( BaseTestCase ):
    def __init__( self, *args, **kwargs ):
        super( TestAgents, self ).__init__( *args, **kwargs )


    @classmethod
    def setupClass( self ):
        pass


    def setUp( self ):
        pass

        
    def tearDown( self ):
        pass


    @classmethod
    def tearDownClass(cls):
        pass


    def test_agent_base( self ):
        with self.assertRaises( NotImplementedError ):
            AgentBase.process( None )


    @unittest.skip( "NotImplementedError( 'AlertAgent' )" )
    def test_alert_agent( self ):
        with self.assertRaises( NotImplementedError ):
            AlertAgent.process( None )


    def test_auth_agent( self ):
        with self.assertRaises( TypeError ):
            AuthorizedAgent.process( None )

        flow = MitmFlow()
        flow.request = None
        with self.assertRaises( PermissionError ):
            AuthorizedAgent.process( flow )


        # test org.client_key
        flow = MitmFlow()
        flow.request.headers.add( 'Something', 'DA03mnsa3i9rd$*@#n2328udhjetor' )
        flow.request.headers.add( 'X-Api-Key', 'ec8tJq78WX63Pj6l0Qdi3KlgOclQNd60/tor' )
        flow.request.headers.add( 'elsE', '61546sdaol3ei-902392me5@#$%#$' )
        AuthorizedAgent.process( flow )
        self.assertTrue( flow.org )
        self.assertEqual( flow.org['client_key'], 'ec8tJq78WX63Pj6l0Qdi3KlgOclQNd60/tor' )
        self.assertFalse( flow.user )


        # test user.client_key
        flow = MitmFlow()
        flow.request.headers.add( 'Something', 'DA03mnsa3i9rd$*@#n2328udhjetor' )
        flow.request.headers.add( 'X-Api-Key', 'DiTYsSaS/j7pZNvLk32Isop+eSaISHhS/tor' )
        flow.request.headers.add( 'elsE', '61546sdaol3ei-902392me5@#$%#$' )
        AuthorizedAgent.process( flow )
        self.assertTrue(  flow.org )
        self.assertEqual( flow.org['client_key'], 'ec8tJq78WX63Pj6l0Qdi3KlgOclQNd60/tor' )
        self.assertTrue(  flow.user )
        self.assertEqual( flow.user['client_key'], 'DiTYsSaS/j7pZNvLk32Isop+eSaISHhS/tor' )


    def test_deny_agent( self ):
        with self.assertRaises( TypeError ):
            DenyAgent.process( None )

        DenyAgent.process( MitmFlow() )

    def test_request_detail_agent( self ):
        with self.assertRaises( TypeError ):
            RequestDetailAgent.process( None )

        flow = MitmFlow()
        flow.request.headers.add( 'X-Api-Key', 'DiTYsSaS/j7pZNvLk32Isop+eSaISHhS/tor' )
        
        with self.assertRaises( NotImplementedError ):
            RequestDetailAgent.process( flow )

        flow.request.is_detail = True
        RequestDetailAgent.process( flow )

        flow.request.is_detail  = False
        flow.request.is_summary = True
        RequestDetailAgent.process( flow )


    def test_request_summary_agent( self ):
        with self.assertRaises( TypeError ):
            RequestSummaryAgent.process( None )

        flow = MitmFlow()
        flow.request.headers.add( 'X-Api-Key', 'DiTYsSaS/j7pZNvLk32Isop+eSaISHhS/tor' )
        
        with self.assertRaises( NotImplementedError ):
            RequestDetailAgent.process( flow )

        flow.request.is_detail = True
        RequestDetailAgent.process( flow )

        flow.request.is_detail  = False
        flow.request.is_summary = True
        RequestDetailAgent.process( flow )



if __name__ == '__main__':
    try:
        level = logging.DEBUG

        #__dir__ = os.path.dirname( os.path.realpath( __file__ ) )
        #log_name = 'scintillator'
        #log_path = os.path.join( __dir__, 'logs', log_name +'.log' )

        formatter = logging.Formatter( '[%(asctime)s] %(name)s %(levelname)-8s %(filename)12.12s:%(lineno)3d %(message)s' )

        con_handler = logging.StreamHandler( sys.stdout )
        con_handler.setFormatter( formatter )
        con_handler.setLevel( level )

        #file_handler = logging.handlers.TimedRotatingFileHandler( log_path, when='midnight', backupCount=7 )
        #file_handler.setFormatter( formatter )
        #file_handler.setLevel( level )

        default_logger = logging.getLogger()
        #for handler in default_logger.handlers:
        #    print( handler )

        #remove others
        #while default_logger.hasHandlers():
        #    default_logger.removeHandler(default_logger.handlers[0])

        default_logger.addHandler( con_handler )
        #default_logger.addHandler( file_handler )
        default_logger.setLevel( level )

        unittest.main()
    except Exception as ex:
        print( ex )
