
# External modules
from twisted.cred.portal import IRealm
from zope.interface import Interface, Attribute


class ICASUser(Interface):

    username = Attribute('String username')
    attribs = Attribute('List of (attribute, value) tuples.')

class IRealmFactory(Interface):

    tag = Attribute('String used to identify the plugin factory.')
    opt_help = Attribute('String description of the plugin.')
    opt_usage = Attribute('String describes how to provide arguments for factory.')

    def generateRealm(argstring=""):
        """
        Create an object that implements IRealm.
        """

class IServiceManagerFactory(Interface):

    tag = Attribute('String used to identify the plugin factory.')
    opt_help = Attribute('String description of the plugin.')
    opt_usage = Attribute('String describes how to provide arguments for factory.')

    def generateServiceManager(argstring=""):
        """
        Create an object that implements txcas.IServiceManager
        """

class IServiceManager(Interface):

    def isValidService(service):
        """
        Returns True if the service is valid; False otherwise.
        """

    def isSSOService(service):
        """
        Returns True if the service participates in SSO.
        Returns False if the service will only accept primary credentials.
        """

class IViewProviderFactory(Interface):

    tag = Attribute('String used to identify the plugin factory.')
    opt_help = Attribute('String description of the plugin.')
    opt_usage = Attribute('String describes how to provide arguments for factory.')

    def generateViewProvider(argstring=""):
        """
        Create an object that provides one or more views.
        """

class IViewProvider(Interface):

    def provideView(view_type):
        """
        Provide a function that will render the named view.
        Return None if the view is not provided.
        """

class ITicketStoreFactory(Interface):

    tag = Attribute('String used to identify the plugin factory.')
    opt_help = Attribute('String description of the plugin.')
    opt_usage = Attribute('String describes how to provide arguments for factory.')

    def generateTicketStore(argstring=""):
        """
        Create an object that implements ITicketStore.
        """

class ITicketStore(Interface):
    
    lt_lifespan = Attribute('LT lifespan in seconds.')
    st_lifespan = Attribute('ST lifespan in seconds.')
    pt_lifespan = Attribute('PT lifespan in seconds.')
    tgt_lifespan = Attribute('TGC lifespan in seconds.')
    pgt_lifespan = Attribute('PGT lifespan in seconds.')
    ticket_size = Attribute('Size of ticket ID in characters.')
    
    isSSOService = Attribute(
                            'Function that accepts a service and returns True if' \
                            'the service may participate in SSO.')
    
    def mkLoginTicket(service):
        """
        Make a login ticket.
        
        @type service: C{string}
        @param service: The service URL.
        
        @rtpe: C{string}
        @return: ticket ID
        """
        
    def useLoginTicket(ticket, service):
        """
        Consume a login ticket.
        Returns a dict with key `service`.
        """
        
    def mkServiceTicket(service, tgt, primaryCredentials):
        """
        """
        
    def useServiceTicket(ticket, service, requirePrimaryCredentials=False):
        """
        """
        
    def mkProxyTicket(service, pgt):
        """
        """
        
    def useServiceOrProxyTicket(ticket, service, requirePrimaryCredentials=False):
        """
        """
        
    def mkProxyGrantingTicket(service, ticket, tgt, pgturl, proxy_chain=None):
        """
        """
        
    def mkTicketGrantingCookie(avatar_id):
        """
        """
        
    def useTicketGrantingCookie(tgt, service):
        """
        """
        
    def expireTGT(tgt):
        """
        """
        
    def register_ticket_expiration_callback(callback):
        """
        Register a function to be called when a ticket is expired.
        The function should take 3 arguments, (ticket, data, explicit).
        `ticket` is the ticket ID, `data` is a dict of the ticket data,
        and `explicit` is a boolean that indicates whether the ticket
        was explicitly expired (e.g. /logout, ST/PT validation) or
        implicitly expired (e.g. timeout or parent ticket expired).
        """

