
# Standard library
import datetime
import json
import random
import string
from textwrap import dedent
import uuid
from xml.sax.saxutils import escape as xml_escape

# Application modules
from txcas.exceptions import CASError, InvalidTicket, InvalidService, \
                        NotSSOService
from txcas.interface import ITicketStore
from txcas.utils import http_status_filter

# External modules
from dateutil.parser import parse as parse_date
import treq
from twisted.internet import defer, reactor
from twisted.plugin import IPlugin
from twisted.python import log
from twisted.web.http_headers import Headers
from zope.interface import implements


class CouchDBError(Exception):
    pass


class CouchDBTicketStore(object):
    """
    A ticket store that uses an external CouchDB.
    """
    implements(IPlugin, ITicketStore)

    lifespan = 10
    cookie_lifespan = 60 * 60 * 24 * 2
    pgt_lifespan = 60 * 60 * 2
    lt_lifespan = 60*5
    charset = string.ascii_letters + string.digits + '-'
    poll_expired = 60 * 5


    def __init__(self, couch_host, couch_port, couch_db,
                couch_user, couch_passwd, use_https=True,
                reactor=reactor, valid_service=None, 
                is_sso_service=None, _debug=False):
        self.reactor = reactor
        self.valid_service = valid_service or (lambda x:True)
        self.is_sso_service = is_sso_service or (lambda x: True)
        self._debug = _debug
        self._debug = True
        self._expire_callback = (lambda ticket, data, explicit: None)
        self._couch_host = couch_host
        self._couch_port = couch_port
        self._couch_db = couch_db
        self._couch_user = couch_user
        self._couch_passwd = couch_passwd
        if use_https:
            self._scheme = 'https://'
        else:
            self._scheme = 'http://'
        
    def debug(self, msg):
        if self._debug:
            log.msg(msg)

    def _validService(self, service):
        def cb(result):
            if not result:
                raise InvalidService(service)
            return service
        return defer.maybeDeferred(self.valid_service, service).addCallback(cb)

    def _isSSOService(self, service):
        def cb(result):
            if not result:
                raise NotSSOService(service)
        return defer.maybeDeferred(self.is_sso_service, service).addCallback(cb)

    def _generate(self, prefix):
        r = prefix
        while len(r) < 256:
            r += random.choice(self.charset)
        return r


    def _mkTicket(self, prefix, data, _timeout=None):
        """
        Create a ticket prefixed with C{prefix}

        The ticket will expire after my class' C{lifespan} seconds.

        @param prefix: String prefix for the token.
        @param data: Data associated with this ticket (which will be returned
            when L{_useTicket} is called).
        """
        timeout = _timeout or self.lifespan
        ticket = self._generate(prefix)
        data['ticket_id'] = ticket
        expires = datetime.datetime.today() + datetime.timedelta(seconds=timeout)
        data[u'expires'] = expires.strftime('%Y-%m-%dT%H:%M:%S')
        if 'pgts' in data:
            data[u'pgts'] = list(data['pgts'])
        
        url = '''%(scheme)s%(host)s:%(port)s/%(db)s''' % {
            'scheme': self._scheme,
            'host': self._couch_host,
            'port': self._couch_port,
            'db': self._couch_db}
        url = url.encode('utf-8')
        doc = json.dumps(data)

        self.debug("[DEBUG][CouchDB] _mkTicket(): url: %s" % url)
        self.debug("[DEBUG][CouchDB] _mkTicket(): doc: %s" % doc)
        
        def return_ticket(result, ticket, data):
            return ticket
            
        d = treq.post(url, data=doc, auth=(self._couch_user, self._couch_passwd),
                        headers=Headers({
                            'Accept': ['application/json'], 
                            'Content-Type': ['application/json']}))
        d.addCallback(http_status_filter, [(201,201)], CouchDBError)
        d.addCallback(treq.content)
        d.addCallback(return_ticket, ticket, data)
        
        return d

    @defer.inlineCallbacks
    def _fetch_ticket(self, ticket):
        """
        Fetch a ticket representation from CouchDB.
        """
        url = '''%(scheme)s%(host)s:%(port)s/%(db)s/_design/views/_view/get_ticket''' % {
            'scheme': self._scheme,
            'host': self._couch_host,
            'port': self._couch_port,
            'db': self._couch_db}
        url = url.encode('utf-8')
        params = {'key': json.dumps(ticket.encode('utf-8'))}

        self.debug("[DEBUG][CouchDB] _fetch_ticket(), url: %s" % url)
        self.debug("[DEBUG][CouchDB] _fetch_ticket(), params: %s" % str(params))

        response = yield treq.get(url, 
                    params=params, 
                    headers=Headers({'Accept': ['application/json']}),
                    auth=(self._couch_user, self._couch_passwd))
        response = yield http_status_filter(response, [(200,200)], CouchDBError)
        doc = yield treq.json_content(response)
        rows = doc[u'rows']
        if len(rows) > 0:
            entry = rows[0][u'value']
            entry[u'expires'] = parse_date(entry[u'expires'])
            if u'pgts' in entry:
                entry[u'pgts'] = set(entry[u'pgts'])
            defer.returnValue(entry)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _update_ticket(self, _id, _rev, data):
        """
        Update a ticket in CouchDB.
        """
        data[u'expires'] = data[u'expires'].strftime('%Y-%m-%dT%H:%M:%S')
        if u'pgts' in data:
            data[u'pgts'] = list(data[u'pgts'])
        url = '''%(scheme)s%(host)s:%(port)s/%(db)s/%(docid)s''' % {
            'scheme': self._scheme,
            'host': self._couch_host,
            'port': self._couch_port,
            'db': self._couch_db,
            'docid': _id}
        url = url.encode('utf-8')
        params = {
            'rev': _rev.encode('utf-8')
        }

        self.debug("[DEBUG][CouchDB] _update_ticket(), url: %s" % url)
        self.debug("[DEBUG][CouchDB] _update_ticket(), params: %s" % str(params))

        try:
            doc = json.dumps(data)
        except Exception as ex:
            self.debug("[DEBUG][CouchDB] Failed to serialze doc:\n%s" % (str(data)))
            raise

        response = yield treq.put(
                            url, 
                            params=params,
                            data=doc, 
                            auth=(self._couch_user, self._couch_passwd),
                            headers=Headers({
                                'Accept': ['application/json'], 
                                'Content-Type': ['application/json']}))
        response = yield http_status_filter(response, [(201,201)], CouchDBError)
        doc = yield treq.json_content(response)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _delete_ticket(self, _id, _rev):
        """
        Delete a ticket from CouchDB.
        """
        url = '''%(scheme)s%(host)s:%(port)s/%(db)s/%(docid)s''' % {
            'scheme': self._scheme,
            'host': self._couch_host,
            'port': self._couch_port,
            'db': self._couch_db,
            'docid': _id}
        url = url.encode('utf-8')
        params = {'rev': _rev}

        self.debug('[DEBUG][CouchDB] _delete_ticket(), url: %s' % url)
        self.debug('[DEBUG][CouchDB] _delete_ticket(), params: %s' % str(params))

        response = yield treq.delete(
                            url,
                            params=params, 
                            auth=(self._couch_user, self._couch_passwd),
                            headers=Headers({'Accept': ['application/json']}))
        response = yield http_status_filter(response, [(200,200)], CouchDBError)
        resp_text = yield treq.content(response)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _expireTicket(self, val):
        """
        This function should only be called when a ticket is expired via
        a timeout or indirectly (e.g. TGT expires so derived PGTs are expired).
        """
        entry = yield self._fetch_ticket(val)
        if entry is not None:
            _id = entry['_id']
            _rev = entry['_rev']
            del entry[u'_id']
            del entry[u'_rev']
            yield self._delete_ticket(_id, _rev)
            yield self._expire_callback(val, entry, False)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _useTicket(self, ticket, _consume=True):
        """
        Consume a ticket, producing the data that was associated with the ticket
        when it was created.

        @raise InvalidTicket: If the ticket doesn't exist or is no longer valid.
        """
        entry = yield self._fetch_ticket(ticket)
        if entry is not None:
            _id = entry[u'_id']
            _rev = entry[u'_rev']
            expires = entry[u'expires']
            now = datetime.datetime.today()
            if now >= expires:
                raise InvalidTicket("Ticket has expired.")
            del entry[u'_id']
            del entry[u'_rev']
            if _consume:
                yield self._delete_ticket(_id, _rev)
                yield self._expire_callback(ticket, entry, True)
            else:
                if ticket.startswith(u'PT-'):
                    timeout = self.lifespan
                elif ticket.startswith(u'ST-'):
                    timeout = self.lifespan
                elif ticket.startswith(u'LT-'):
                    timeout = self.lt_lifespan
                elif ticket.startswith(u'PGT-'):
                    timeout = self.pgt_lifespan
                elif ticket.startswith(u'TGC-'):
                    timeout = self.cookie_lifespan
                else:
                    timeout = 10
                now = datetime.datetime.today()
                expires = now + datetime.timedelta(seconds=timeout)
                entry[u'expires'] = expires
                yield self._update_ticket(_id, _rev, entry)
            defer.returnValue(entry)
        else:
            raise InvalidTicket("Ticket '%s' does not exist." % ticket)

    @defer.inlineCallbacks
    def _informTGTOfService(self, st, service, tgt):
        """
        Record in the TGT that a service has requested an ST.
        """
        entry = yield self._fetch_ticket(tgt)
        if entry is None:
            raise InvalidTicket("Ticket '%s' does not exist." % tgt)
        _id = entry[u'_id']
        _rev = entry[u'_rev']
        del entry[u'_id']
        del entry[u'_rev']
        services = entry.setdefault('services', {})
        services[service] = st
        yield self._update_ticket(_id, _rev, entry)
        defer.returnValue(st)
        
    @defer.inlineCallbacks
    def _informTGTOfPGT(self, pgt, tgt):
        """
        Record in the TGT that a service has requested an ST.
        """
        if not pgt.startswith("PGT-"):
            raise InvalidTicket("PGT '%s' is not valid." % pgt)
        if not tgt.startswith("TGC-"):
            raise InvalidTicket("TGT '%s' is not valid." % tgt)
        entry = yield self._fetch_ticket(tgt)
        if entry is None:
            raise InvalidTicket("Ticket '%s' does not exist." % tgt)
        _id = entry[u'_id']
        _rev = entry[u'_rev']
        del entry[u'_id']
        del entry[u'_rev']
        pgts = entry.setdefault('pgts', set([]))
        pgts.add(pgt)
        yield self._update_ticket(_id, _rev, entry)
        defer.returnValue(pgt)

    def mkLoginTicket(self, service):
        """
        Create a login ticket.
        """
        d = self._validService(service)
        def cb(_):
            return self._mkTicket('LT-', {
                'service': service,
            }, _timeout=self.lt_lifespan)
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
                if data[u'service'] != service:
                    raise InvalidTicket()
            return d.addCallback(cb)
        return self._validService(service).addCallback(doit)

    @defer.inlineCallbacks
    def mkServiceTicket(self, service, tgt_id, primaryCredentials):
        """
        Create a service ticket
        """
        if not tgt_id.startswith("TGC-"):
            raise InvalidTicket()
        entry = yield self._fetch_ticket(tgt_id)
        if entry is None:
            raise InvalidTicket("Invalid TGT '%s'." % tgt_id)
        del entry[u'_id']
        del entry[u'_rev']
        tgt = entry
        yield self._validService(service)
        ticket = yield self._mkTicket('ST-', {
                'avatar_id': tgt['avatar_id'],
                'service': service,
                'primary_credentials': primaryCredentials,
                'tgt': tgt_id,
            })
        yield self._informTGTOfService(ticket, service, tgt_id)
        defer.returnValue(ticket)  

    def useServiceTicket(self, ticket, service, requirePrimaryCredentials=False):
        """
        Get the data associated with a service ticket.
        """
        return self._useServiceOrProxyTicket(ticket, service, requirePrimaryCredentials)

    @defer.inlineCallbacks
    def mkProxyTicket(self, service, pgt):
        """
        Create a proxy ticket
        """
        if not pgt.startswith("PGT-"):
            raise InvalidTicket()

        pgt_info = yield self._fetch_ticket(pgt)
        if pgt_info is None:
            raise InvalidTicket("PGT '%s' is invalid." % pgt)
        pgturl = pgt_info['pgturl']
        try:
            tgt = pgt_info[u'tgt']
        except KeyError:
            raise InvalidTicket("PGT '%s' is invalid." % pgt)
        yield self._validService(service)
        pt = yield self._mkTicket('PT-', {
                'avatar_id': pgt_info[u'avatar_id'],
                'service': service,
                'primary_credentials': False,
                'pgturl': pgturl,
                'pgt': pgt,
                'tgt': tgt,
                'proxy_chain': pgt_info[u'proxy_chain'],
            })
        yield self._informTGTOfService(pt, service, tgt)
        defer.returnValue(pt)

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
                if data[u'service'] != service:
                    raise InvalidTicket()
                if requirePrimaryCredentials and data['primary_credentials'] == False:
                    raise InvalidTicket("This ticket was not issued in response to primary credentials.")
                return data
            return d.addCallback(cb)
        return self._validService(service).addCallback(doit)

    @defer.inlineCallbacks
    def mkProxyGrantingTicket(self, service, ticket, tgt, pgturl, proxy_chain=None):
        """
        Create Proxy Granting Ticket
        """
        if not (ticket.startswith("ST-") or ticket.startswith("PT-")):
            raise InvalidTicket()
        tgt_info = yield self._fetch_ticket(tgt)
        if tgt_info is None:
            raise InvalidTicket("TGT '%s' is invalid." % tgt)
        del tgt_info[u'_id']
        del tgt_info[u'_rev']
        yield self._validService(service)
        charset = self.charset
        iou = 'PGTIOU-' + (''.join([random.choice(charset) for n in range(256)]))
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
        data[u'proxy_chain'] = new_proxy_chain 
    
        pgt = yield self._mkTicket('PGT-', data, _timeout=self.pgt_lifespan)
        yield self._informTGTOfPGT(pgt, tgt)
        defer.returnValue({'iou': iou, 'pgt': pgt})

    def mkTicketGrantingCookie(self, avatar_id):
        """
        Create a ticket to be used in a cookie.
        """
        return self._mkTicket('TGC-', {'avatar_id': avatar_id}, _timeout=self.cookie_lifespan)


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
            #SLO
            services = data.get('services', {})
            self.reactor.callLater(0.0, self._notifyServicesSLO, services)
            #PGTs
            pgts = data.get(u'pgts', {})
            for pgt in pgts:
                self._expireTicket(pgt)
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
            dt = datetime.datetime.today()
            issue_instant = dt.strftime("%Y-%m-%dT%H:%M:%S")
            identifier = str(uuid.uuid4())
            
            data = template % {
                'identifier': xml_escape(identifier),
                'issue_instant': xml_escape(issue_instant),
                'service_ticket': xml_escape(st)
            }
            d = treq.post(service, data=data, _timeout=30).addCallback(treq.content)
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
        
