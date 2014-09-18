
# Standard library.
import sys

# Application modules
from txcas.constants import VIEW_LOGIN, VIEW_LOGIN_SUCCESS, VIEW_LOGOUT, \
                        VIEW_INVALID_SERVICE, VIEW_ERROR_5XX, VIEW_NOT_FOUND
from txcas.interface import IRealmFactory, IServiceManagerFactory, \
                        ITicketStoreFactory, IViewProviderFactory, \
                        IServiceManagerAcceptor
from txcas.server import ServerApp
import txcas.settings

# External modules
from OpenSSL import SSL, crypto

from twisted.application.service import Service
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.strcred import ICheckerFactory
from twisted.cred.portal import IRealm
from twisted.internet import reactor, ssl
from twisted.internet.endpoints import serverFromString
from twisted.python import log
from twisted.web.server import Site


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

    def __init__(
                self,   
                endpoint_s=None, 
                endpoint_options=None,
                checkers=None, 
                realm=None, 
                ticket_store=None,
                service_manager=None,
                view_provider=None,
                static_dir=None,
                validate_pgturl=None):
        """
        """
        assert not ((endpoint_s is None) and (endpoint_options is None)), "Must specify either `endpoint_s` or `endpoint_options`."

        # Provide reasonable defaults for `endpoint_options`.
        if endpoint_options is not None:
            ep_defaults = {
                'ssl': False,
                'ssl_method': SSL.SSLv23_METHOD,
                'verify_client_cert': False,
                'port': 9800,
                'certKey': None,
                'privateKey': None,
                'authorities': [],
            }
            ep_defaults.update(endpoint_options)
            endpoint_options = ep_defaults
            del ep_defaults

        self.port_s = endpoint_s
        self.endpoint_options = endpoint_options

        # Load the config.
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas', defaults={
                'CAS': {
                    'lt_lifespan': 300,
                    'st_lifespan': 10,
                    'pt_lifespan': 10,
                    'pgt_lifespan': 600,
                    'tgt_lifespan': 86400,
                    'validate_pgturl': 1,
                    'ticket_size': 128,
                },
                'PLUGINS': {
                    'cred_checker': 'file:./cas_users.passwd',
                    'realm': 'basic_realm',
                    'ticket_store': 'memory_ticket_store'}})

        # Choose plugin that implements IServiceManager.
        if service_manager is None and scp.has_option('PLUGINS', 'service_manager'):
            tag_args = scp.get('PLUGINS', 'service_manager')
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factory = txcas.settings.get_plugin_factory(tag, IServiceManagerFactory)
            if factory is None:
                sys.stderr.write("[ERROR] Service manager type '%s' is not available.\n" % tag)
                sys.exit(1)
            service_manager = factory.generateServiceManager(args)

        if service_manager is not None:
            sys.stderr.write("[CONFIG] Service manager: %s\n" % service_manager.__class__.__name__)

        # Choose plugin that implements IViewProvider.
        if view_provider is None and scp.has_option('PLUGINS', 'view_provider'):
            tag_args = scp.get('PLUGINS', 'view_provider')
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factory = txcas.settings.get_plugin_factory(tag, IViewProviderFactory)
            if factory is None:
                sys.stderr.write("[ERROR] View provider type '%s' is not available.\n" % tag)
                sys.exit(1)
            view_provider = factory.generateViewProvider(args)
        
        if view_provider is not None:
            sys.stderr.write("[CONFIG] View provider: %s\n" % view_provider.__class__.__name__)
        
        # Connect service manager, if available.
        if IServiceManagerAcceptor.providedBy(view_provider):
            view_provider.service_manager = service_manager
            sys.stderr.write("[CONFIG] View provider received a reference to the service manager.\n")

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

        # Connect service manager, if available.
        if IServiceManagerAcceptor.providedBy(ticket_store):
            ticket_store.service_manager = service_manager
            sys.stderr.write("[CONFIG] Ticket store received a reference to the service manager.\n")
   
        # Choose plugin(s) that implement ICredentialChecker 
        if checkers is None or len(checkers) == 0:        
            try:
                tag_args =  scp.get('PLUGINS', 'cred_checker')
            except Exception:
                sys.stderr.write("[ERROR] No valid credential checker was configured.\n")
                sys.exit(1)
            factories = []
            for tag_arg in tag_args.split(','):
                parts = tag_arg.split(':')
                tag = parts[0]
                args = ':'.join(parts[1:])
                factories.extend(txcas.settings.get_plugins_by_predicate(
                                ICheckerFactory, 
                                lambda x: x.authType == tag))
            if len(factories) == 0:
                checkers= [InMemoryUsernamePasswordDatabaseDontUse(foo='password')]
            else:
                checkers=[f.generateChecker(args) for f in factories]

        for checker in checkers:
            sys.stderr.write("[CONFIG] Credential Checker: %s\n" % checker.__class__.__name__)
            # Connect service manager, if available.
            if IServiceManagerAcceptor.providedBy(checker):
                checker.service_manager = service_manager
                sys.stderr.write("[CONFIG] Credential checker received a reference to the service manager.\n")

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
        
        # Connect service manager, if available.
        if IServiceManagerAcceptor.providedBy(realm):
            realm.service_manager = service_manager
            sys.stderr.write("[CONFIG] User realm received a reference to the service manager.\n")
       
        # Page views
        page_views = None
        if view_provider is not None:
            page_views = {}
            symbol_table = [
                VIEW_LOGIN,
                VIEW_LOGIN_SUCCESS,
                VIEW_LOGOUT,
                VIEW_INVALID_SERVICE,
                VIEW_ERROR_5XX,
                VIEW_NOT_FOUND,
                ]
            for symbol in symbol_table:
                func = view_provider.provideView(symbol)
                if func is not None:
                    page_views[symbol] = func
        
        # Validate PGT URL?
        if validate_pgturl is None:
            validate_pgturl = get_bool_opt(scp, 'CAS', 'validate_pgturl')
        if validate_pgturl:
            sys.stderr.write("[CONFIG] pgtUrls will be validated.\n")
        else:
            sys.stderr.write("[CONFIG] pgtUrls will *NOT* be validated.\n")
        
        # TGC uses "secure"?
        if endpoint_s is not None:
            if endpoint_s.startswith("ssl:"):
                requireSSL = True
            else:
                requireSSL = False
        else:
            requireSSL = endpoint_options['ssl']
      
        # Service validation func.
        if service_manager is None:
            validService = lambda x:True
        else:
            validService = service_manager.isValidService
 
        # Serve static resources?
        if static_dir is None and scp.has_option('CAS', 'static_dir'):
            static_dir = scp.get('CAS', 'static_dir')
        if static_dir is not None:
            sys.stderr.write("[CONFIG] Static content served from %s\n" % static_dir)
 
        # Create the application. 
        app = ServerApp(
                    ticket_store, 
                    realm, 
                    checkers,
                    validService=validService, 
                    requireSSL=requireSSL,
                    page_views=page_views, 
                    validate_pgturl=validate_pgturl,
                    static=static_dir)
        root = app.app.resource()

        self.site = Site(root)

    def startService(self):
        if self.port_s is not None:
            #----------------------------------------------------------------------
            # Create endpoint from string.
            #----------------------------------------------------------------------
            sys.stderr.write("[CONFIG] Endpoint string: %s\n" % self.port_s)
            endpoint = serverFromString(reactor, self.port_s)
            endpoint.listen(self.site)
        else:
            endpoint_options = self.endpoint_options
            use_ssl = endpoint_options['ssl']
            certKey = endpoint_options['certKey']
            privateKey = endpoint_options['privateKey']
            port = endpoint_options['port']
            auth_files = endpoint_options['authorities']
            ssl_method = getattr(SSL, endpoint_options['ssl_method'])
            sys.stderr.write("[CONFIG] SSL Method: %s == %d\n" % (endpoint_options['ssl_method'], ssl_method))
            verify_client = endpoint_options['verify_client_cert']
            
            ep_keys = endpoint_options.keys()
            ep_keys.sort()
            lines = []
            for key in ep_keys:
                lines.append("- %s: %s" % (key, str(endpoint_options[key])))
            del ep_keys
            sys.stderr.write("[CONFIG] Endpoint\n%s\n" % ('\n'.join(lines)))
            del lines
            
            if use_ssl:
                #----------------------------------------------------------------------
                # Another way to create the context factory (from separate key and cert
                # files in PEM format) such that it is configured to verify the peer. 
                #
                # The `caCerts` option is used to set the public CA cert that
                # signed the client certs that will be verified.
                #
                # The ssl_context verify_mode is set to VERIFY_PEER, but it is *not*
                # set to fail if there is no peer cert.
                #
                # The veification callback checks if there was an SSL error.  This
                # prevents a connection if a bad client cert that was not signed by the 
                # trusted authority is presented.
                #----------------------------------------------------------------------
                with open(privateKey, "r") as f:
                    buffer = f.read()
                privateKey = crypto.load_privatekey(crypto.FILETYPE_PEM, buffer)
                with open(certKey, "r") as f:
                    buffer = f.read()
                certificate = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
                authorities = []
                for auth_file in auth_files:
                    with open(auth_file, "r") as f:
                        buffer = f.read()
                    authority = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
                    authorities.append(authority)
                
                try: 
                    ctx = ssl.CertificateOptions(
                        privateKey, 
                        certificate, 
                        method=ssl_method, 
                        caCerts=authorities,
                        verify=verify_client)
                except ValueError as ex:
                    if str(ex) == "No such protocol":
                        sys.stderr.write(
                            "[ERROR] SSL protocol %s is not supported by the installed OpenSSL library.\n" % (
                                endpoint_options['ssl_method']))
                        sys.exit(1)
                    else:
                        raise

                if verify_client:
                    # If the client must be verified, set up a special callback
                    # for the ssl context that does peer verification so the client
                    # cert will be available later on from the Request.
                    ssl_context = ctx.getContext()
                    verify_mode = ssl_context.get_verify_mode()
                    #print "verify_mode", verify_mode
                    #print "OpenSSL.SSL.VERIFY_NONE", SSL.VERIFY_NONE
                    #print "OpenSSL.SSL.VERIFY_PEER", SSL.VERIFY_PEER
                    #print "OpenSSL.SSL.VERIFY_CLIENT_ONCE", SSL.VERIFY_CLIENT_ONCE
                    #print "OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT", SSL.VERIFY_FAIL_IF_NO_PEER_CERT
                    def ssl_callback(conn, x509, errno, errdepth, ok):
                        #print "errno", errno
                        #print "errdepth", errdepth
                        #print "ok", ok
                        return ok 
                    ssl_context.set_verify(SSL.VERIFY_PEER, ssl_callback)

                reactor.listenSSL(port, self.site, ctx)
            else: # Not SSL
                reactor.listenTCP(port, self.site)

#class MyContextFactory(ssl.ContextFactory):
#    def __init__(self, wrapped):
#        self.wrapped = wrapped
#
#    def getContext(self):
#        ctx = self.wrapped.getContext()
#        ctx.set_verify(SSL.VERIFY_PEER, lambda *args: True)
#        return ctx

