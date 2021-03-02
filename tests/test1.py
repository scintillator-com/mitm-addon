# -*- coding: utf-8 -*-

from ..agents import DenyAgent
from ..config import Configuration
from ..enums  import ContentType
from ..models import Request, Rule


rule = Rule()
rule.index = 7
rule.target = 'requestheaders'
rule.filters.method = [ 'PATCH', 'POST', 'PUT' ]
rule.filters.content_length = [ 0, 5000 ]
rule.filters.content_type = [
    'application/json',
    'application/json+protobuf',
    'application/x-www-form-urlencoded',
    'multipart/form-data'
]


manager = RuleManager( RuleManager.Behavior.FIRST, DenyAgent )
manager.append( rule )
manager.validate()
#manager.extend( rules )


# succeed
req = Request()
req.method         = 'PATCH'
req.content_length = 3000
req.content_type   = ContentType.APPLICATION_JSON
match = manager.filter( req )
print( match )
exit()


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



