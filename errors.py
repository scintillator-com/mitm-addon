# -*- coding: utf-8 -*-

class NoData( Exception ):
    pass


class RequestDeniedError( InterruptedError ):
    __slots__ = ( 'status', 'content', 'headers' )
    def __init__( self, status=None, content=None, headers={} ):
        self.status  = status or 403
        self.content = content or "Request blocked by rule"
        
        if headers:
            self.headers = headers
        else:
            # TODO: agent attributes
            self.headers = {
                "Content-Type": ContentType.TEXT_PLAIN
            }

'''
flow.status = FlowAttributes.CANCEL
flow.response = mitmproxy.http.HTTPResponse.make(
    status_code,  # (optional) status code
    content,      # (optional) content
    headers       # (optional) headers
)
'''
