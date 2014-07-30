
# Application modules
from txcas.interface import ITicketStore
from txcas.server import ServerApp

# External modules
from twisted.application.service import Service
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.portal import IRealm
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.plugin import getPlugins
from twisted.web.server import Site


class CASService(Service):
    """
    Service for CAS server
    """

    def __init__(self, endpoint_s, ticket_timeout,
                auth_timeout, valid_service, requireSSL=True,
                page_views=None, validate_pgturl=True):
        self.port_s = endpoint_s

        # Choose the first plugin that implements IRealm.
        realm = None
        for realm in getPlugins(IRealm):
            break

        #Load first ticket store plugin.
        ticket_store = None
        for ticket_store in getPlugins(ITicketStore):
            break
        ticket_store.lifespan = ticket_timeout
        ticket_store.cookie_lifespan = auth_timeout

        # Choose the first plugin that implements ICredentialsChecker.
        checker = None
        for checker in getPlugins(ICredentialsChecker):
            break
        
        app = ServerApp(ticket_store, realm, [checker],
                        lambda x:True, requireSSL=requireSSL,
                        page_views=page_views, 
                        validate_pgturl=validate_pgturl)
        root = app.app.resource()

        self.site = Site(root)


    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)
