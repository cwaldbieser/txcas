from zope.interface import Interface, Attribute


class ICASUser(Interface):

    username = Attribute('String username')
    attribs = Attribute('List of (attribute, value) tuples.')


class ITicketStore(Interface):
    
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
        
    
    
