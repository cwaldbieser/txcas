
# Standard library
from __future__ import print_function
# External modules
from treq.client import HTTPClient
from twisted.internet.ssl import ClientContextFactory
from twisted.web.client import (
    Agent, BrowserLikePolicyForHTTPS)


class NonVerifyingContextFactory(ClientContextFactory):
    """
    Context factory does *not* verify SSL cert.
    """
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

def normalizeDict_(d):
    if d is None:
        d = {}
    else:
        d = dict(d)
    return d

def createNonVerifyingHTTPClient(reactor, agent_kwds=None, **kwds):
    agent_kwds = normalizeDict_(agent_kwds)
    agent_kwds['contextFactory'] = NonVerifyingContextFactory()
    return HttpClient(Agent(reactor, **agent_kwds), **kwds)

def createVerifyingHTTPClient(reactor, agent_kwds=None, **kwds):
    agent_kwds = normalizeDict_(agent_kwds)
    agent_kwds['contextFactory'] = BrowserLikePolicyForHTTPS()
    return HttpClient(Agent(reactor, **agent_kwds), **kwds)
