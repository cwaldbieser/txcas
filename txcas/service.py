
# Standard library.
import sys

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


def _valid_service(url):
    """
    Authorize anything
    """
    return True

def get_int_opt(scp, section, option):
    try:
        return scp.getint(section, option)
    except ValueError:
        print("Configuration [%s] %s must be an integer.")
        sys.exit(1)
        
def get_bool_opt(scp, section, option):
    try:
        return scp.getboolean(section, option)
    except ValueError:
        print("Configuration [%s] %s must be a boolean value (e.g. 1, 0).")
        sys.exit(1)

class CASService(Service):
    """
    Service for CAS server
    """

    def __init__(self, endpoint_s):
        """
        """
        self.port_s = endpoint_s

        # Load the config.
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas', defaults={
                'CAS': {
                    'lt_lifespan': 300,
                    'st_lifespan': 10,
                    'pt_lifespan': 10,
                    'pgt_lifespan': 600,
                    'tgt_lifespan': 86400,
                    'validate_pgturl': 1,
                },
                'PLUGINS': {
                    'cred_checker': 'DemoChecker',
                    'realm': 'DemoRealm',
                    'ticket_store': 'InMemoryTicketStore'}})

        # Choose plugin that implements ITicketStore.
        ticket_store = txcas.settings.get_plugin(
                scp.get('PLUGINS', 'ticket_store'), ITicketStore)
        assert ticket_store is not None, "Ticket Store has not been configured!"
        print("[CONFIG] Ticket Store: %s" % ticket_store.__class__.__name__)
        lt_lifespan = get_int_opt(scp, 'CAS', 'lt_lifespan')
        st_lifespan = get_int_opt(scp, 'CAS', 'st_lifespan')
        pt_lifespan = get_int_opt(scp, 'CAS', 'pt_lifespan')
        pgt_lifespan = get_int_opt(scp, 'CAS', 'pgt_lifespan')
        tgt_lifespan = get_int_opt(scp, 'CAS', 'tgt_lifespan')
        
        ticket_store.lt_lifespan = lt_lifespan
        ticket_store.st_lifespan = st_lifespan
        ticket_store.pt_lifespan = pt_lifespan
        ticket_store.pgt_lifespan = pgt_lifespan
        ticket_store.tgt_lifespan = tgt_lifespan

            
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
       
        # Page views
        page_views = None
        
        # Validate PGT URL?
        validate_pgturl = get_bool_opt(scp, 'CAS', 'validate_pgturl')
        
        # TGC uses "secure"?
        if endpoint_s.startswith("ssl:"):
            requireSSL = True
        else:
            requireSSL = False
       
        # Create the application. 
        app = ServerApp(
                    ticket_store, 
                    realm, 
                    [checker],
                    validService=_valid_service, 
                    requireSSL=requireSSL,
                    page_views=page_views, 
                    validate_pgturl=validate_pgturl)
        root = app.app.resource()

        self.site = Site(root)

    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)

