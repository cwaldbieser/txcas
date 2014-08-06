

# Standard library
import cgi
import base64
from StringIO import StringIO
from urllib import urlencode
import urlparse

# External modules
from treq import content, text_content, json_content

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.web.client import Agent, BrowserLikeRedirectAgent, \
                            FileBodyProducer, readBody
from twisted.python import log
from twisted.web.http_headers import Headers

class WebClientContextFactory(ClientContextFactory):
    """
    Context factory does *not* verify SSL cert.
    """
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

def request(method, url, headers=None, params=None, data=None, auth=None, timeout=None):
    p = urlparse.urlparse(url)
    agent_args = [reactor]
    contextFactory = WebClientContextFactory()
    agent_args.append(contextFactory)
        
    body = None
    if data is not None:
        body = FileBodyProducer(StringIO(data))
    if params is not None:
        if p.params == '':
            param_str = urlencode(params)
        else:
            param_str = p.params + '&' + urlencode(params)
        p = urlparse.ParseResult(*tuple(p[:4] + (param_str,) + p[5:]))
        url = urlparse.urlunparse(p)

    if auth is not None:
        auth = "%s:%s" % auth
        b64auth = base64.b64encode(auth)
        auth = 'Basic %s' % b64auth
        if headers is None:
            headers = Headers({'Authorization': [auth]})
        else:
            if not headers.hasHeader('Authorization'):
                headers.addRawHeader('Authorization', auth)

    agent = BrowserLikeRedirectAgent(Agent(*agent_args))
    d = agent.request(
        method, 
        url,
        headers=headers,
        bodyProducer=body)

    if timeout is not None:
        timeoutCall = reactor.callLater(timeout, d.cancel)
        def completed(passthrough, timeoutCall):
            if timeoutCall.active():
                timeoutCall.cancel()
            return passthrough
        d.addBoth(completed, timeoutCall)
        
    return d

def post(*args, **kwds):
    return request('POST', *args, **kwds)

def get(*args, **kwds):
    return request('GET', *args, **kwds)

def put(*args, **kwds):
    return request('PUT', *args, **kwds)

def delete(*args, **kwds):
    return request('DELETE', *args, **kwds)
