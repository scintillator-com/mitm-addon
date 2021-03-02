

class TestBehaviorFirst( unittest.TestCase ):
    def __init__( self, *args, **kwargs ):
        unittest.TestCase.__init__( self, *args, **kwargs )

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


    @classmethod
    def create_manager(cls):
        manager = RulesManager( RulesManager.Behavior.FIRST, DenyAgent )
        
        #1 - match body requests
        filters = RuleFilters(
            method=( 'PATCH', 'POST', 'PUT' ),
            content_length=( 0, 5000 ),
            content_type=(
                'application/json',
                'application/json+protobuf',
                'application/x-www-form-urlencoded',
                'multipart/form-data'
            )
        )
        rule = Rule( agents=( RequestDetailAgent, ), index=1, target=Rule.Target.requestheaders, filters=filters )
        rule.validate()
        manager.append( rule )

        #2 - match requests without body
        filters = RuleFilters(
            method=( 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'TRACE' ),
        )
        rule = Rule( agents=( RequestSummaryAgent, ), index=2, target=Rule.Target.requestheaders, filters=filters )
        rule.validate()
        manager.append( rule )


        #3 - match any other request
        filters = RuleFilters()
        rule = Rule( agents=( DenyAgent, ), index=3, target=Rule.Target.requestheaders, filters=filters )
        rule.validate()
        manager.append( rule )


        #4
        filters = RuleFilters(
            content_length=( 0, 20000 ),
            content_type=(
                'application/json',
                'application/json+protobuf'
            )
        )
        rule = Rule( agents=( ResponseDetailAgent, ), index=4, target=Rule.Target.responseheaders, filters=filters )
        rule.validate()
        manager.append( rule )


        #5
        filters = RuleFilters(
            status=( 500, 599 )
        )
        rule = Rule( agents=( ResponseDetailAgent, ), index=5, target=Rule.Target.responseheaders, filters=filters )
        rule.validate()
        manager.append( rule )


        #6
        filters = RuleFilters(
            status=( 400, 499 )
        )
        rule = Rule( agents=( ResponseDetailAgent, ), index=6, target=Rule.Target.responseheaders, filters=filters )
        rule.validate()
        manager.append( rule )
        return manager


    def test_good_first( self ):
        moment = Moment()
        moment.
        moment.request = Request()
        moment.request.method         = 'PATCH'
        moment.request.content_length = 3000
        moment.request.content_type   = ContentType.APPLICATION_JSON

        rule = self.create_manager().filter( Rule.Target.requestheaders, moment )
        self.assertTrue( rule )
        self.assertEqual( rule.index, 1 )

        #RequestDetailAgent
        for agent in rule.agents:
            agent.process( None, moment )


    def test_bad_method( self ):
        moment = Moment()
        moment.request = Request()
        moment.request.method         = 'COW'
        moment.request.content_length = 3000
        moment.request.content_type   = ContentType.APPLICATION_JSON

        rule = self.create_manager().filter( Rule.Target.requestheaders, moment )
        print( rule )
        self.assertTrue( rule )
        self.assertEqual( rule.index, 3 )

        print( rule.agents )
        for agent in rule.agents:
            agent.process( moment )



class TestBehaviorLast( unittest.TestCase ):
    def __init__( self, *args, **kwargs ):
        unittest.TestCase.__init__( self, *args, **kwargs )

    @classmethod
    def setupClass( self ):
        pass

    def setUp( self ):
        self.manager = RulesManager( RulesManager.Behavior.FIRST, DenyAgent )

    def tearDown( self ):
        pass



class TestFilters( unittest.TestCase ):
    def __init__( self, *args, **kwargs ):
        unittest.TestCase.__init__( self, *args, **kwargs )

    @classmethod
    def setupClass( self ):
        pass

    def setUp( self ):
        self.manager = RulesManager( RulesManager.Behavior.FIRST, DenyAgent )

    def tearDown( self ):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_host( self ):
        pass

    def test_method( self ):
        pass

    def test_port( self ):
        pass

    def test_scheme( self ):
        pass
    
    def test_content_length( self ):
        pass

    def test_content_length( self ):
        pass

    def test_status( self ):
        pass

#fail1
req = Request()
req.method         = 'PATCH'
req.content_length = -10
req.content_type   = ContentType.APPLICATION_JSON

#fail2
req = Request()
req.method         = 'PATCH'
req.content_length = 1000
req.content_type   = ContentType.TEXT_PLAIN


#fail3
req = Request()
req.method         = 'PATCH'
req.content_length = 1000
req.content_type   = ContentType.TEXT_PLAIN
