
# Standard library
import sys

# Application modules
from txcas.interface import IRealmFactory, ITicketStoreFactory
from txcas.service import CASService
import txcas.settings
import txcas.utils

# External modules
from twisted.application import internet
from twisted.application.service import IServiceMaker
from twisted.cred import credentials, strcred
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implements


class Options(usage.Options, strcred.AuthOptionMixin):
    # This part is optional; it tells AuthOptionMixin what
    # kinds of credential interfaces the user can give us.
    supportedInterfaces = (credentials.IUsernamePassword,)

    optFlags = [
            ["ssl", "s", "Use SSL"],
            ["help-realms", None, "List user realm plugins available."],
            ["help-ticket-stores", None, "List user ticket store plugins available."],
        ]

    optParameters = [
                        ["port", "p", 9800, "The port number to listen on.", int],
                        ["cert-key", "c", None, "An x509 certificate file (PEM format)."],
                        ["private-key", "k", None, "An x509 private key (PEM format)."],
                        ["realm", "r", None, "User realm plugin to use."],
                        ["help-realm", None, None, "Help for a specific realm plugin."],
                        ["ticket-store", "t", None, "Ticket store plugin to use."],
                        ["help-ticket-store", None, None, "Help for a specific ticket store plugin."],
                    ]


class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "cas"
    description = "Central Authentication Service (CAS)."
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """
        # Endpoint
        parts = []
        if options["ssl"]:
            parts.append("ssl")
        else:
            parts.append("tcp")
        parts.append(str(options["port"]))
        certKey = options['cert-key']
        if certKey is not None:
            parts.append('certKey=%s' % certKey)
        privateKey = options['private-key']
        if privateKey is not None:
            parts.append('privateKey=%s' % privateKey)
        endpoint = ':'.join(parts)
        checkers = options.get("credCheckers", None)

        # Realm
        if 'help-realms' in options and options['help-realms']:    
            sys.stdout.write("Available Realm Plugins\n") 
            factories = list(getPlugins(IRealmFactory))
            txcas.utils.format_plugin_help_list(factories, sys.stdout)
            sys.exit(0) 

        if 'help-realm' in options and options['help-realm'] is not None:
            realm_tag = options['help-realm']
            factory = txcas.settings.get_plugin_factory(realm_tag, IRealmFactory)
            if factory is None:
                sys.stderr.write("Unknown realm plugin '%s'.\n" % realm_tag)
                sys.exit(1)
            sys.stderr.write(factory.opt_help)
            sys.stderr.write('\n')
            sys.exit(0)

        realm = None
        realm_arg = options.get('realm', None)
        if realm_arg is not None:
            realm_parts = realm_arg.split(':')
            assert len(parts) !=0, "--realm option is malformed."
            realm_tag = realm_parts[0]
            realm_argstr = ':'.join(realm_parts[1:])
            if realm_tag is not None:
                factory = txcas.settings.get_plugin_factory(realm_tag, IRealmFactory)
                if factory is None:
                    sys.stderr.write("Realm type '%s' is not available.\n" % realm_tag)
                    sys.exit(1)
                realm = factory.generateRealm(realm_argstr)

        # Ticket Store
        if 'help-ticket-stores' in options and options['help-ticket-stores']:    
            sys.stdout.write("Available Ticket Store Plugins\n") 
            factories = list(getPlugins(ITicketStoreFactory))
            txcas.utils.format_plugin_help_list(factories, sys.stdout)
            sys.exit(0) 

        if 'help-ticket-store' in options and options['help-ticket-store'] is not None:
            ts_tag = options['help-ticket-store']
            factory = txcas.settings.get_plugin_factory(ts_tag, ITicketStoreFactory)
            if factory is None:
                sys.stderr.write("Unknown ticket store plugin '%s'.\n" % ts_tag)
                sys.exit(1)
            sys.stderr.write(factory.opt_help)
            sys.stderr.write('\n')
            sys.exit(0)

        ticket_store = None
        ts_arg = options.get('ticket-store', None)
        if ts_arg is not None:
            ts_parts = ts_arg.split(':')
            assert len(parts) !=0, "--ticket-store option is malformed."
            ts_tag = ts_parts[0]
            ts_argstr = ':'.join(ts_parts[1:])
            if ts_tag is not None:
                factory = txcas.settings.get_plugin_factory(ts_tag, ITicketStoreFactory)
                if factory is None:
                    sys.stderr.write("Ticket store type '%s' is not available.\n" % ts_tag)
                    sys.exit(1)
                ticket_store = factory.generateTicketStore(ts_argstr)

        # Create the service.
        return CASService(endpoint, checkers=checkers, realm=realm, ticket_store=ticket_store)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
