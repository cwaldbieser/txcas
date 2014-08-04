
# Application modules
from txcas.interface import ITicketStore
from txcas.server import ServerApp
import txcas.settings

# External modules
from twisted.application.service import Service
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import IRealm
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.python import log
from twisted.web.server import Site


class CASService(Service):
    """
    Service for CAS server
    """

    def __init__(self, 
                endpoint_s, 
                lt_timeout,
                st_timeout,
                pt_timeout,
                pgt_timeout,
                tgt_timeout,
                valid_service, 
                requireSSL=True,
                page_views=None, 
                validate_pgturl=True):

        self.port_s = endpoint_s

        # Load the config.
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas', defaults={
                'PLUGINS': {
                    'cred_checker': 'DemoChecker',
                    'realm': 'DemoRealm',
                    'ticket_store': 'InMemoryTicketStore'}})

        # Choose plugin that implements ITicketStore.
        ticket_store = txcas.settings.get_plugin(
                scp.get('PLUGINS', 'ticket_store'), ITicketStore)
        assert ticket_store is not None, "Ticket Store has not been configured!"
        print("[CONFIG] Ticket Store: %s" % ticket_store.__class__.__name__)
        ticket_store.lt_lifespan = lt_timeout
        ticket_store.st_lifespan = st_timeout
        ticket_store.pt_lifespan = pt_timeout
        ticket_store.pgt_lifespan = pgt_timeout
        ticket_store.tgt_lifespan = tgt_timeout

            
        # Choose the plugin that implements ICredentialsChecker.
        checker = txcas.settings.get_plugin(
                scp.get('PLUGINS', 'cred_checker'), ICredentialsChecker)
        if checker is None:
            checker = InMemoryUsernamePasswordDatabaseDontUse(foo='password')
        print("[CONFIG] Credential Checker: %s" % checker.__class__.__name__)

        # Choose the plugin that implements IRealm.
        realm = txcas.settings.get_plugin(
                scp.get('PLUGINS', 'realm'), IRealm)
        assert realm is not None, "User Realm has not been configured!"
        print("[CONFIG] User Realm: %s" % realm.__class__.__name__)
       
        # Create the application. 
        app = ServerApp(
                    ticket_store, 
                    realm, 
                    [checker],
                    valid_service, 
                    requireSSL=requireSSL,
                    page_views=page_views, 
                    validate_pgturl=validate_pgturl)
        root = app.app.resource()

        self.site = Site(root)

    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)

