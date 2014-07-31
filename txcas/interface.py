from zope.interface import Interface, Attribute


class ICASUser(Interface):

    username = Attribute('String username')
    attribs = Attribute('List of (attribute, value) tuples.')


class ITicketStore(Interface):
    
    lifespan = Attribute('ST/PT lifespan in seconds.')
    lt_lifespan = Attribute('LT lifespan in seconds.')
    cookie_lifespan = Attribute('TGC lifespan in seconds.')
    pgt_lifespan = Attribute('PGT lifespan in seconds.')
    
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
    
