
# Standard library
import datetime
import random
import string
import sys
from textwrap import dedent
import uuid
from xml.sax.saxutils import escape as xml_escape

# Application modules
from txcas.exceptions import CASError, InvalidTicket, InvalidService, \
                        NotSSOService, InvalidTicketSpec
import txcas.http
from txcas.interface import ITicketStore, ITicketStoreFactory
import txcas.settings

# External modules
import treq
from twisted.internet import defer, reactor
from twisted.plugin import IPlugin
from twisted.python import log
from zope.interface import implements


class InMemoryTicketStoreFactory(object):
    implements(IPlugin, ITicketStoreFactory)

    tag = "memory_ticket_store"

    opt_help = dedent('''\
            A ticket store that manages all CAS tickets in local
            memory.  It is easy to configure and quick to retreive
            and modify tickets.  It is constained to a single process,
            however, so no high availability.  Also, any tickets in
            the store when the CAS process is stopped are lost.
            Valid options include:
            
            - lt_lifespan
            - st_lifespan
            - pt_lifespan
            - tgt_lifespan
            - pgt_lifespan
            - ticket_size
            ''')

    opt_usage = '''A colon-separated key=value list.'''

    def generateTicketStore(self, argstring=""):
        """
        """
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        ts_settings = settings.get('CAS', {})    
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            ts_settings.update(argdict)
        missing = txcas.utils.get_missing_args(
                    InMemoryTicketStore.__init__, ts_settings, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][InMemoryTicketStore] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n') 
            sys.exit(1)
    
        props = (
                'lt_lifespan', 'st_lifespan', 'pt_lifespan',
                'tgt_lifespan', 'pgt_lifespan', 'ticket_size')
        ts_props = dict((prop, int(ts_settings[prop])) for prop in props if prop in ts_settings)
        txcas.utils.filter_args(InMemoryTicketStore.__init__, ts_settings, ['self'])
        obj = InMemoryTicketStore(**ts_settings)
        for prop, value in ts_props.iteritems():
            setattr(obj, prop, value)
        buf = ["[CONFIG][InMemoryTicketStore] Settings:"]
        d = dict(ts_settings)
        d.update(ts_props)
        for k in sorted(d.keys()):
            v = d[k]
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf)) 
        sys.stderr.write('\n') 
        return obj


class InMemoryTicketStore(object):
    """
    A ticket store that exists entirely in system memory.
    """
    implements(IPlugin, ITicketStore)

    lt_lifespan = 60 * 5
    st_lifespan = 10
    pt_lifespan = 10
    tgt_lifespan = 60 * 60 * 24 * 2
    pgt_lifespan = 60 * 60 * 2
    ticket_size = 256
    charset = string.ascii_letters + string.digits + '-'
    
    service_manager = None

    def __init__(self, reactor=reactor, verify_cert=True, _debug=False):
        self.reactor = reactor
        self._tickets = {}
        self._delays = {}
        self._debug = _debug
        self._expire_callback = (lambda ticket, data, explicit: None)
        if verify_cert:
            self.reqlib = treq
        else:
            self.reqlib = txcas.http

    def _getServiceValidator(self):
        service_mgr = self.service_manager
        if service_mgr is None:
            return (lambda x: True)
        else:
            return service_mgr.isValidService

    def _getServiceSSOPredicate(self):
        service_mgr = self.service_manager
        if service_mgr is None:
            return (lambda x: True)
        else:
            return service_mgr.isSSOService
        
    def debug(self, msg):
        if self._debug:
            log.msg(msg)

    def _validService(self, service):
        def cb(result):
            if not result:
                raise InvalidService(service)
            return service
        
        return defer.maybeDeferred(self._getServiceValidator(), service).addCallback(cb)

    def _isSSOService(self, service):
        def cb(result):
            if not result:
                raise NotSSOService(service)
        return defer.maybeDeferred(self._getServiceSSOPredicate(), service).addCallback(cb)

    def _generate(self, prefix):
        r = list(prefix)
        size = self.ticket_size
        while len(r) < size:
            r.append(random.choice(self.charset))
        return ''.join(r)


    def _mkTicket(self, prefix, data, timeout):
        """
        Create a ticket prefixed with C{prefix}

        The ticket will expire after my class' C{lifespan} seconds.

        @param prefix: String prefix for the token.
        @param data: Data associated with this ticket (which will be returned
            when L{_useTicket} is called).
        @param timeout: The time in seconds the ticket lasts.
        """
        ticket = self._generate(prefix)
        self._tickets[ticket] = data
        self.debug("Added ticket '%s' with data: %s" % (ticket, str(data)))
        if prefix == 'TGC-':
            dc = self.reactor.callLater(timeout, self.expireTGT, ticket)
        else:
            dc = self.reactor.callLater(timeout, self.expireTicket, ticket)
        self._delays[ticket] = (dc, timeout)
        return defer.succeed(ticket)


    def expireTicket(self, val):
        """
        This function should only be called when a ticket is expired via
        a timeout or indirectly (e.g. TGT expires so derived PGTs are expired).
        """
        try:
            data = self._tickets[val]
            del self._tickets[val]
            del self._delays[val]
            self._expire_callback(val, data, False)
        except KeyError:
            pass
        self.debug("Expired ticket '%s'." % val)


    def _useTicket(self, ticket, _consume=True):
        """
        Consume a ticket, producing the data that was associated with the ticket
        when it was created.

        @raise InvalidTicket: If the ticket doesn't exist or is no longer valid.
        """
        try:
            val = self._tickets[ticket]
            if _consume:
                del self._tickets[ticket]
                self._expire_callback(ticket, val, True)
                self.debug("Consumed ticket '%s'." % ticket)
            else:
                dc, timeout = self._delays[ticket]
                dc.reset(timeout)
            return defer.succeed(val)
        except KeyError:
            return defer.fail(InvalidTicket())
        except Exception as ex:
            log.err(ex)
            return defer.fail(InvalidTicket())

    def _informTGTOfService(self, st, service, tgt):
        """
        Record in the TGT that a service has requested an ST.
        """
        try:
            data = self._tickets[tgt]
        except KeyError:
            return defer.fail(InvalidTicket())
        services = data.setdefault('services', {})
        services[service] = st
        self.debug("Added service '%s' to TGT '%s' with ST '%s'." % (service, tgt, st))
        return st
        
    def _informTGTOfPGT(self, pgt, tgt):
        """
        Record in the TGT that a service has requested an ST.
        """
        if not pgt.startswith("PGT-"):
            raise InvalidTicket("PGT '%s' is not valid." % pgt)
        if not tgt.startswith("TGC-"):
            raise InvalidTicket("TGT '%s' is not valid." % tgt)
            
        try:
            data = self._tickets[tgt]
        except KeyError:
            return defer.fail(InvalidTicket())
        pgts = data.setdefault('pgts', set([]))
        pgts.add(pgt)
        self.debug("Added PGT '%s' to TGT '%s'." % (pgt, tgt))
        return pgt

    def mkLoginTicket(self, service):
        """
        Create a login ticket.
        """
        d = self._validService(service)
        def cb(_):
            return self._mkTicket('LT-', {
                'service': service,
            }, timeout=self.lt_lifespan)
        return d.addCallback(cb)


    def useLoginTicket(self, ticket, service):
        """
        Use a login ticket.
        """
        if not ticket.startswith("LT-"):
            raise InvalidTicket()
        def doit(_):
            d = self._useTicket(ticket)
            def cb(data):
                if data['service'] != service:
                    raise InvalidTicket()
            return d.addCallback(cb)
        return self._validService(service).addCallback(doit)


    def mkServiceTicket(self, service, tgt_id, primaryCredentials):
        """
        Create a service ticket
        """
        if not tgt_id.startswith("TGC-"):
            raise InvalidTicket()
        try:
            tgt = self._tickets[tgt_id]
        except KeyError:
            raise InvalidTicket("Invalid TGT '%s'." % tgt_id)
            
        def doit(_):
            return self._mkTicket('ST-', {
                'avatar_id': tgt['avatar_id'],
                'service': service,
                'primary_credentials': primaryCredentials,
                'tgt': tgt_id,
            }, timeout=self.st_lifespan)
        d = self._validService(service)
        d.addCallback(doit)
        d.addCallback(self._informTGTOfService, service, tgt_id)
        
        return d


    def useServiceTicket(self, ticket, service, requirePrimaryCredentials=False):
        """
        Get the data associated with a service ticket.
        """
        if not ticket.startswith("ST-"):
            return defer.fail(InvalidTicketSpec())

        return self._useServiceOrProxyTicket(ticket, service, requirePrimaryCredentials)

    def mkProxyTicket(self, service, pgt):
        """
        Create a proxy ticket
        """
        if not pgt.startswith("PGT-"):
            return defer.fail(InvalidTicket())

        try:
            pgt_info = self._tickets[pgt]
        except KeyError:
            return defer.fail(InvalidTicket("PGT '%s' is invalid." % pgt))
        pgturl = pgt_info['pgturl']

        try:
            tgt = pgt_info['tgt']
        except KeyError:
            return defer.fail(InvalidTicket("PGT '%s' is invalid." % pgt))
            
        def doit(_):
            return self._mkTicket('PT-', {
                'avatar_id': pgt_info['avatar_id'],
                'service': service,
                'primary_credentials': False,
                'pgturl': pgturl,
                'pgt': pgt,
                'tgt': tgt,
                'proxy_chain': pgt_info['proxy_chain'],
            }, timeout=self.pt_lifespan)
        d = self._validService(service)
        d.addCallback(doit)
        d.addCallback(self._informTGTOfService, service, tgt)
        
        return d

    def useServiceOrProxyTicket(self, ticket, service, requirePrimaryCredentials=False):
        """
        Get the data associated with a service ticket.
        """
        return self._useServiceOrProxyTicket(ticket, service, requirePrimaryCredentials, True)

    def _useServiceOrProxyTicket(self, ticket, service, requirePrimaryCredentials=False, _allow_pt=False):
        """
        Get the data associated with a service or proxy ticket.
        """
        if not ticket.startswith("ST-"):
            if not ticket.startswith("PT-") and _allow_pt:
                raise InvalidTicket()
                
        def doit(_):
            d = self._useTicket(ticket)
            def cb(data):
                if data['service'] != service:
                    raise InvalidTicket()
                if requirePrimaryCredentials and data['primary_credentials'] == False:
                    raise InvalidTicket("This ticket was not issued in response to primary credentials.")
                return data
            return d.addCallback(cb)
        return self._validService(service).addCallback(doit)

    def mkProxyGrantingTicket(self, service, ticket, tgt, pgturl, proxy_chain=None):
        """
        Create Proxy Granting Ticket
        """
        if not (ticket.startswith("ST-") or ticket.startswith("PT-")):
            raise InvalidTicket()
        
        try:
            tgt_info = self._tickets[tgt]
        except KeyError:
            raise InvalidTicket("TGT '%s' is invalid." % tgt)
        
        def doit(_):
            charset = self.charset
            size = self.ticket_size
            iou = self._generate('PGTIOU-')
            data = {
                'avatar_id': tgt_info['avatar_id'],
                'service': service,
                'st_or_pt': ticket,
                'iou': iou,
                'tgt': tgt,
                'pgturl': pgturl,
            }
            if proxy_chain is not None:
                new_proxy_chain = list(proxy_chain)
                new_proxy_chain.append(pgturl)
            else:
                new_proxy_chain = [pgturl]
            data['proxy_chain'] = new_proxy_chain 
        
            return self._mkTicket('PGT-', data, timeout=self.pgt_lifespan).addCallback(
                self._informTGTOfPGT, tgt).addCallback(
                lambda pgt : {'iou': iou, 'pgt': pgt})
        
        d = self._validService(service)
        d.addCallback(doit)
        return d

    def mkTicketGrantingCookie(self, avatar_id):
        """
        Create a ticket to be used in a cookie.
        """
        return self._mkTicket('TGC-', {'avatar_id': avatar_id}, timeout=self.tgt_lifespan)


    def useTicketGrantingCookie(self, ticket, service):
        """
        Get the user associated with this ticket.
        """
        def use_ticket_cb(_): 
            return self._useTicket(ticket, _consume=False)
            
        if service != "":
            return self._isSSOService(service).addCallback(use_ticket_cb)
        else:
            return use_ticket_cb(None)

    def expireTGT(self, ticket):
        """
        Expire the TGT identified by 'ticket'.
        """
        if not ticket.startswith("TGC-"):
            raise InvalidTicket()
        
        d = self._useTicket(ticket)
        def cb(data):
            """
            Expire associated PGTs.
            Perform SLO.
            """
            self.debug("Expired TGT '%s'." % ticket)
            #SLO
            services = data.get('services', {})
            self.reactor.callLater(0.0, self._notifyServicesSLO, services)
            #PGTs
            pgts = data.get('pgts', {})
            for pgt in pgts:
                self.expireTicket(pgt)
            return None
            
        def eb(failure):
            failure.trap(InvalidTicket)

        return d.addCallback(cb).addErrback(eb)
        
    _samlLogoutTemplate = dedent("""\
        <samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="%(identifier)s"
            Version="2.0"
            IssueInstant="%(issue_instant)s">
            <saml:NameID>@NOT_USED@</saml:NameID>
            <samlp:SessionIndex>%(service_ticket)s</samlp:SessionIndex>
        </samlp:LogoutRequest>
        """)
    def _notifyServicesSLO(self, services):
        """
        """
        template = self._samlLogoutTemplate
        dlist = []
        for service, st in services.iteritems():
            self.debug("Notifing service '%s' of SLO with ST '%s' ..." % (service, st))
            dt = datetime.datetime.today()
            issue_instant = dt.strftime("%Y-%m-%dT%H:%M:%S")
            identifier = str(uuid.uuid4())
            
            data = template % {
                'identifier': xml_escape(identifier),
                'issue_instant': xml_escape(issue_instant),
                'service_ticket': xml_escape(st)
            }
            reqlib = self.reqlib
            d = reqlib.post(service, data=data, timeout=30).addCallback(reqlib.content)
            dlist.append(d)
        return defer.DeferredList(dlist, consumeErrors=True)

    def register_ticket_expiration_callback(self, callback):
        """
        Register a function to be called when a ticket is expired.
        The function should take 3 arguments, (ticket, data, explicit).
        `ticket` is the ticket ID, `data` is a dict of the ticket data,
        and `explicit` is a boolean that indicates whether the ticket
        was explicitly expired (e.g. /logout, ST/PT validation) or
        implicitly expired (e.g. timeout or parent ticket expired).
        """
        self._expire_callback = callback
        
