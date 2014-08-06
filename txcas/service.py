
# Standard library.
import sys

# Application modules
from txcas.interface import IRealmFactory, ITicketStoreFactory
from txcas.server import ServerApp
import txcas.settings

# External modules
from twisted.application.service import Service
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.strcred import ICheckerFactory
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
        sys.stderr.write("Configuration [%s] %s must be an integer.\n")
        sys.exit(1)
        
def get_bool_opt(scp, section, option):
    try:
        return scp.getboolean(section, option)
    except ValueError:
        sys.stderr.write("Configuration [%s] %s must be a boolean value (e.g. 1, 0).\n")
        sys.exit(1)

class CASService(Service):
    """
    Service for CAS server
    """

    def __init__(self, endpoint_s, checkers=None, realm=None, ticket_store=None):
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
                    'ticket_size': 256,
                },
                'PLUGINS': {
                    'cred_checker': 'demo_checker',
                    'realm': 'demo_realm',
                    'ticket_store': 'InMemoryTicketStore'}})

        # Choose plugin that implements ITicketStore.

        if ticket_store is None:
            tag_args = scp.get('PLUGINS', 'ticket_store')
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factory = txcas.settings.get_plugin_factory(tag, ITicketStoreFactory)
            if factory is None:
                sys.stderr.write("[ERROR] Ticket store type '%s' is not available.\n" % tag)
                sys.exit(1)
            ticket_store = factory.generateTicketStore(args)

        assert ticket_store is not None, "Ticket store has not been configured!"
        sys.stderr.write("[CONFIG] Ticket store: %s\n" % ticket_store.__class__.__name__)
        sys.stderr.write("[CONFIG] Login Ticket Lifespan: %d seconds\n" % ticket_store.lt_lifespan)
        sys.stderr.write("[CONFIG] Service Ticket Lifespan: %d seconds\n" % ticket_store.st_lifespan)
        sys.stderr.write("[CONFIG] Proxy Ticket Lifespan: %d seconds\n" % ticket_store.pt_lifespan)
        sys.stderr.write("[CONFIG] Proxy Granting Ticket Lifespan: %d seconds\n" % ticket_store.pgt_lifespan)
        sys.stderr.write("[CONFIG] Ticket Granting Ticket Lifespan: %d seconds\n" % ticket_store.tgt_lifespan)
        sys.stderr.write("[CONFIG] Ticket Identifier Size: %d characters\n" % ticket_store.ticket_size)

   
        # Choose plugin(s) that implement ICredentialChecker 
        if checkers is None:        
            try:
                tag_args =  scp.get('PLUGINS', 'cred_checker')
            except Exception:
                sys.stderr.write("[ERROR] No valid credential checker was configured.\n")
                sys.exit(1)
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factories = txcas.settings.get_plugins_by_predicate(
                            ICheckerFactory, 
                            lambda x: x.authType == tag)
            if len(factories) == 0:
                checkers= [InMemoryUsernamePasswordDatabaseDontUse(foo='password')]
            else:
                checkers=[f.generateChecker(args) for f in factories]

        for checker in checkers:
            sys.stderr.write("[CONFIG] Credential Checker: %s\n" % checker.__class__.__name__)

        # Choose the plugin that implements IRealm.
        if realm is None:
            tag_args = scp.get('PLUGINS', 'realm')
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factory = txcas.settings.get_plugin_factory(tag, IRealmFactory)
            if factory is None:
                sys.stderr.write("[ERROR] Realm type '%s' is not available.\n" % tag)
                sys.exit(1)
            realm = factory.generateRealm(args)

        assert realm is not None, "User Realm has not been configured!"
        sys.stderr.write("[CONFIG] User Realm: %s\n" % realm.__class__.__name__)
       
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
                    checkers,
                    validService=_valid_service, 
                    requireSSL=requireSSL,
                    page_views=page_views, 
                    validate_pgturl=validate_pgturl)
        root = app.app.resource()

        self.site = Site(root)

    def startService(self):
        endpoint = serverFromString(reactor, self.port_s)
        endpoint.listen(self.site)

