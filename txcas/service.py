
# Application modules
from txcas.checker import FunctionChecker
from txcas.interface import ITicketStore
from txcas.server import ServerApp, UserRealm

# External modules
from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.plugin import getPlugins
from twisted.web.server import Site


class CASService(Service):
    """
    Service for CAS server
    """

    def __init__(self, endpoint_s, authorize, ticket_timeout,
                auth_timeout, valid_service, requireSSL=True,
                page_views=None, validate_pgturl=True):
        self.port_s = endpoint_s

        #Load first ticket store plugin.
        ticket_store = None
        for ticket_store in getPlugins(ITicketStore):
            break
        ticket_store.lifespan = ticket_timeout
        ticket_store.cookie_lifespan = auth_timeout

        checker = FunctionChecker(authorize)
        
        app = ServerApp(ticket_store, UserRealm(), [checker],
                        lambda x:True, requireSSL=requireSSL,
                        page_views=page_views, 
                        validate_pgturl=validate_pgturl)
        root = app.app.resource()

        self.site = Site(root)


    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)
