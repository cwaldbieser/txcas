from twisted.internet import reactor
from twisted.application.service import Service
from twisted.internet.endpoints import serverFromString
from twisted.web.server import Site

from txcas.checker import FunctionChecker
from txcas.server import ServerApp, UserRealm, InMemoryTicketStore




class CASService(Service):
    """
    Service for CAS server
    """


    def __init__(self, endpoint_s, authorize, ticket_timeout,
                 auth_timeout, valid_service, requireSSL=True):
        self.port_s = endpoint_s

        ticket_store = InMemoryTicketStore(valid_service=valid_service)
        ticket_store.lifespan = ticket_timeout
        ticket_store.cookie_lifespan = auth_timeout

        checker = FunctionChecker(authorize)
        
        app = ServerApp(ticket_store, UserRealm(), [checker],
                        lambda x:True, requireSSL=requireSSL)
        root = app.app.resource()

        self.site = Site(root)


    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)