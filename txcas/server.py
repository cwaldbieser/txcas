

#Standard library
import cgi
import datetime
import random
import string
import sys
from textwrap import dedent
from urllib import urlencode
import uuid
from xml.sax.saxutils import escape as xml_escape

#Application modules
from txcas.interface import ICASUser

#External modules
from klein import Klein

import treq

from twisted.cred.portal import Portal, IRealm
from twisted.cred.credentials import UsernamePassword
from twisted.internet import defer, reactor
from zope.interface import implements
from twisted.python import log


#=======================================================================

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }

def escape_html(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)

def make_cas_attributes(attribs):
    """
    Create CAS attributes from a list of (key, value) tuples.

    E.g.:
    <cas:attributes>
         <cas:firstname>John</cas:firstname>
         <cas:lastname>Doe</cas:lastname>
         <cas:title>Mr.</cas:title>
         <cas:email>jdoe@example.orgmailto:jdoe@example.org</cas:email>
         <cas:affiliation>staff</cas:affiliation>
         <cas:affiliation>faculty</cas:affiliation>
   </cas:attributes>
    """
    if len(attribs) == 0:
        return ""
    parts = ["<cas:attributes>"]
    for k, v in attribs:
        k = sanitize_keyname(k)
        parts.append("    <cas:%s>%s</cas:%s>" % (k, xml_escape(v), k))
    parts.append("</cas:attributes>") 
    return '\n'.join(parts)

def sanitize_keyname(name):
    include = set(string.ascii_letters + "-_")
    s = ''.join(ch for ch in name if ch in include)
    return s

class CASError(Exception):
    pass

class InvalidTicket(CASError):
    pass


class InvalidService(CASError):
    pass


class CookieAuthFailed(CASError):
    pass

class NotSSOService(CASError):
    pass


class ServerApp(object):

    app = Klein()
    cookie_name = 'tgc'

    
    def __init__(self, ticket_store, realm, checkers, validService=None,
                 requireSSL=True, page_views=None, validate_pgturl=True):
        """
        Initialize an instance of the CAS server.

        @param ticket_store: The ticket store to use.
        @param realm: The t.c.p.Portal asks the realm for an avatar.
        @param checkers: A list of credential checkers to try (in order).
        @param validService: A callable that takes a service as an argument 
            and returns True if the server will authenticate for that service.
        @param requireSSL: Require SSL for Tcket Granting Cookie
        @param page_views: A mapping of functions that are used to render
            custom pages.
            - All views may either be synchronous or async (deferreds).
            - List of views:
                - login: rendered when credentials are requested.
                    - Should accept args (loginTicket, service, request).
                    - Rendered page should POST to /login according to CAS protocol.
                - login_success: Rendered when no service is specified and a
                    valid SSO session already exists.
                    - Should accept args (avatar, request)
                - logout: Rendered on logout.
                    - Should accept args (request,).
                - invalid_service: Rendered when an invalid service is provided.
                    - Should accept args (service, request).
                - error5xx: Rendered on an internal error.
                    - Should accept args (err, request).
                    - `err` is a twisted.python.failure.Failure
        @param validate_pgturl: If True, follow the protocol and validate the pgtUrl
            peer.  Useful to set to False for development purposes.
                 
        """
        self.cookies = {}
        self.ticket_store = ticket_store
        self.portal = Portal(realm)
        self.requireSSL = requireSSL
        map(self.portal.registerChecker, checkers)
        self.validService = validService or (lambda x: True)
        self.validate_pgturl = validate_pgturl

        default_page_views = {
                'login': self._renderLogin,
                'login_success': self._renderLoginSuccess,
                'logout': self._renderLogout,
                'invalid_service': self._renderInvalidService,
                'error5xx': self._renderError5xx,
            }
        if page_views is None:
            page_views = default_page_views
        else:
            default_page_views.update(page_views)
            page_views = default_page_views
        self.page_views = page_views

    #ENHANCEMENT: There should be a /proxyValidate endpoint.
    
    @app.route('/login', methods=['GET'])
    def login_GET(self, request):
        """
        Present a username/password login page to the browser.
        """
        service = request.args.get('service', [""])[0]
        renew = request.args.get('renew', [""])[0]
        if renew != "":
            return self._presentLogin(request)
            
        d = self._authenticateByCookie(request)
        d.addErrback(lambda _:self._presentLogin(request))
        def service_err(err, request):
            err.trap(InvalidService)
            err.printTraceback(file=sys.stderr)
            request.setResponseCode(403)
            return defer.maybeDeferred(
                self.page_views['invalid_service'], service, request)
        d.addErrback(service_err, request)
        return d.addErrback(self.page_views['error5xx'], request)


    def _authenticateByCookie(self, request):
        tgc = request.getCookie(self.cookie_name)
        if not tgc:
            return defer.fail(CookieAuthFailed("No cookie"))
        # Q: Should the ticket-granting cookie be checked for expiration?
        # I think a browser won't send expired cookies.  Anyway, expiration
        # should happen on the server.
        service = request.args.get('service', [""])[0]
        d = self.ticket_store.useTicketGrantingCookie(tgc, service)

        def eb(err, request):
            err.trap(InvalidTicket, NotSSOService)
            # delete the cookie
            request.addCookie(self.cookie_name, '',
                              expires='Thu, 01 Jan 1970 00:00:00 GMT')
            return err
        d.addErrback(eb, request)
        return d.addCallback(self._authenticated, False, service, request)

    def _presentLogin(self, request):
        # If the login is presented, the TGC should be removed and the TGT
        # should be expired.
        def expireTGT():
            tgc = request.getCookie(self.cookie_name)
            if tgc:
                #Delete the cookie.
                request.addCookie(
                    self.cookie_name, '', expires='Thu, 01 Jan 1970 00:00:00 GMT')
                #Expire the ticket.
                d = self.ticket_store.expireTGT(tgc)
                return d
            return None
        service = request.args.get('service', [""])[0]
        gateway = request.args.get('gateway', [""])[0]
        if gateway != "" and service != "":
            #Redirect to `service` with no ticket.
            request.redirect(service)            
            request.finish()
            return
        return defer.maybeDeferred(
            expireTGT).addCallback(
            lambda x: service).addCallback(
            self.ticket_store.mkLoginTicket).addCallback(
            self.page_views['login'], service, request)
            

    def _authenticated(self, user, primaryCredentials, service, request):
        """
        Call this after authentication has succeeded to finish the request.
        """
        tgc = request.getCookie(self.cookie_name)
        
        @defer.inlineCallbacks
        def maybeAddCookie(user, request):
            ticket = request.getCookie(self.cookie_name)
            if not ticket:
                path = request.URLPath().sibling('').path
                ticket = yield self.ticket_store.mkTicketGrantingCookie(user)
                request.addCookie(self.cookie_name, ticket, path=path,
                                  secure=self.requireSSL)
                request.cookies[-1] += '; HttpOnly'
            defer.returnValue((user, ticket))

        def mkServiceTicket(user_tgc, service, tgc):
            user, tgc = user_tgc
            return self.ticket_store.mkServiceTicket(user, service, tgc, primaryCredentials)

        def redirect(ticket, service, request):
            query = urlencode({
                'ticket': ticket,
            })
            request.redirect(service + '?' + query)

        d = maybeAddCookie(user, request)
        if service != "":
            d.addCallback(mkServiceTicket, service, tgc)
            d.addCallback(redirect, service, request)
        else:
            d.addCallback(self.page_views['login_success'], request)
        return d.addErrback(self.page_views['error5xx'], request)

    def _renderLogin(self, ticket, service, request):
        html_parts = []
        html_parts.append(dedent('''\
        <html>
            <body>
                <form method="post" action="">
                    Username: <input type="text" name="username" />
                    <br />Password: <input type="password" name="password" />
                    <input type="hidden" name="lt" value="%(lt)s" />
        ''')) % {
            'lt': cgi.escape(ticket),
        }
        if service != "":
            html_parts.append(
                '            '
                '<input type="hidden" name="service" value="%(service)s" />' % {
                    'service': service
                })
        html_parts.append(dedent('''\
                    <input type="submit" value="Sign in" />
                </form>
            </body>
        </html>
        '''))
        return '\n'.join(html_parts)

    def _renderLoginSuccess(self, avatar, request):
        html = dedent("""\
            <html>
                <body>
                    <h1>A CAS Session Exists</h1>
                    <p>
                        A CAS session exists for account '%s'.
                    </p>
                </body>
            </html>
            """) % escape_html(avatar.username)
        return html
        
    def _renderLogout(self, request):
        return "You have been logged out."
        
    def _renderInvalidService(self, service, request):
        html = dedent("""\
            <html>
                <head>
                    <title>Invalid Service</title>
                </head>
                <body>
                    <h1>Invalid Service</h1>
                    <p>
                        The service provided is not authorized to use this CAS
                        implementation.
                    </p>
                </body>
            </html>
            """)
        request.setResponseCode(403)
        return html
        
    def _renderError5xx(self, err, request):
        err.printTraceback(file=sys.stderr)
        html = dedent("""\
            <html>
                <head>
                    <title>Internal Error - 500</title>
                </head>
                <body>
                    <h1>HTTP 500 - Internal Error</h1>
                    <p>
                        Please contact your system administrator.
                    </p>
                </body>
            </html>
            """)
        request.setResponseCode(500)
        return html

    @app.route('/login', methods=['POST'])
    def login_POST(self, request):
        """
        Accept a username/password, verify the credentials and redirect them
        appropriately.
        """
        service = request.args.get('service', [""])[0]
        renew = request.args.get('renew', [""])[0]
        username = request.args.get('username', [None])[0]
        password = request.args.get('password', [None])[0]
        ticket = request.args.get('lt', [None])[0]

        def checkPassword(_, username, password):
            credentials = UsernamePassword(username, password)
            return self.portal.login(credentials, None, ICASUser)

        def extract_avatar(avatarAspect):
            interface, avatar, logout = avatarAspect
            return avatar

        def eb(err, service, request):
            # ENHANCEMENT: It would be much better if this errorback 
            # could trap something like an "AuthError" and throw other
            # errors to the 5xx handler.
            # I am not sure what kind of errors the credentail checkers
            # will raise, though.
            err.printTraceback(file=sys.stderr)
            params = {}
            for argname, arglist in request.args.iteritems():
                if argname in ('service', 'renew',):
                    params[argname] = arglist
            query = urlencode(params, doseq=True)
            request.redirect('/login?' + query)

        # check credentials
        d = self.ticket_store.useLoginTicket(ticket, service)
        d.addCallback(checkPassword, username, password)
        d.addCallback(extract_avatar)
        d.addCallback(self._authenticated, True, service, request)
        d.addErrback(eb, service, request)
        return d


    @app.route('/logout', methods=['GET'])
    def logout_GET(self, request):
        service = request.args.get('service', [""])[0]
        def _validService(_, service):
            def eb(err):
                err.trap(InvalidService)
                return defer.maybeDeferred(
                    self.page_views['invalid_service'], service, request)
            return defer.maybeDeferred(
                self.validService, service).addErrback(eb)
                
        tgc = request.getCookie(self.cookie_name)
        if tgc:
            #Delete the cookie.
            request.addCookie(
                self.cookie_name, '', expires='Thu, 01 Jan 1970 00:00:00 GMT')
            #Expire the ticket.
            d = self.ticket_store.expireTGT(tgc)
        else:
            d = defer.maybeDeferred(lambda : None)

        if service != "":
            def redirect(_):
                request.redirect(service)
            d.addCallback(
                _validService, service).addCallback(
                redirect).addErrback(
                self.page_views['error5xx'], request)
        else:
            d.addCallback(
                self.page_views['logout']).addErrback(
                self.page_views['error5xx'], request)

        return d


    @app.route('/validate', methods=['GET'])
    def validate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        ticket = request.args.get('ticket', [""])[0]
        service = request.args.get('service', [""])[0]
        renew = request.args.get('renew', [""])[0]
        if service == "" or ticket == "":
            request.setResponseCode(403)
            return 'no\n\n'

        if renew != "":
            require_pc = True
        else:
            require_pc = False        
        d = self.ticket_store.useServiceTicket(ticket, service, require_pc)

        def renderUsername(user):
            return 'yes\n' + user.username + '\n'

        def renderFailure(err, request):
            err.trap(InvalidTicket)
            request.setResponseCode(403)
            return 'no\n\n'

        d.addCallback(renderUsername)
        d.addErrback(renderFailure, request)
        d.addErrback(self.page_views['error5xx'], request)
        return d        

    @app.route('/serviceValidate', methods=['GET'])
    def serviceValidate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        ticket = request.args.get('ticket', [None])[0]
        service = request.args.get('service', [None])[0]
        pgturl = request.args.get('pgtUrl', [""])[0]
        renew = request.args.get('renew', [""])[0]
        
        if service is None or ticket is None:
            request.setResponseCode(400)
            return "Bad request"
        
        if renew != "":
            require_pc = True
        else:
            require_pc = False
        d = self.ticket_store.useServiceTicket(ticket, service, require_pc)

        def renderSuccess(results):
            avatar = results['avatar']
            iou = results.get('iou', None)
            
            doc_begin = dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                    <cas:authenticationSuccess>
                    <cas:user>%s</cas:user>
                """) % xml_escape(avatar.username)
            doc_attributes = make_cas_attributes(avatar.attribs)
            doc_proxy = ""
            if iou is not None:
                doc_proxy = "    <cas:proxyGrantingTicket>%s</cas:proxyGrantingTicket>" % (
                    xml_escape(iou))
            doc_end = dedent("""\
                    </cas:authenticationSuccess>
                </cas:serviceResponse>
                """)
            doc_parts = [doc_begin]
            for part in (doc_attributes, doc_proxy,):
                if len(part) > 0:
                    doc_parts.append(part)
            doc_parts.append(doc_end)
            return '\n'.join(doc_parts)

        def renderFailure(err, request):
            err.trap(InvalidTicket)
            request.setResponseCode(403)
            doc_fail = dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                   <cas:authenticationFailure code="INVALID_TICKET">
                      Ticket %s not recognized`    
                   </cas:authenticationFailure>
                </cas:serviceResponse>
                """) % xml_escape(ticket)
            return doc_fail

        d.addCallback(self._validateProxy, pgturl, service, ticket, request)
        d.addCallback(renderSuccess)
        d.addErrback(renderFailure, request)
        d.addErrback(self.page_views['error5xx'], request)
        return d        

    def _validateProxy(self, avatar, pgturl, service, ticket, request):
        """
        Validate service callback.
        Generate PGT + IOU.
        POST both to pgturl.
        Return avatar *and* IOU.
        """
        results = {'avatar': avatar}
        if pgturl == "":
            return results
        
        def _mkPGT(_):
            return self.ticket_store.mkProxyGrantingTicket(avatar, service, ticket)
        
        def _sendTicketAndIou(pgt_info, pgturl):
            """
            """
            pgt = pgt_info['pgt']
            iou = pgt_info['iou']
            def iou_cb(_, pgtiou):
                """
                Return the iou parameter.
                """
                return pgtiou
                
            q = {'pgtId': pgt, 'pgtIou': iou}
            return treq.get(pgturl + '?' + urlencode(q)).addCallback(iou_cb, iou)
            
        def _package_result(iou, avatar):
            d = {'iou': iou, 'avatar': avatar}
            return d
        
        if self.validate_pgturl:
            d = treq.get(pgturl)
        else:
            d = defer.Deferred()
        d.addCallback(_mkPGT)
        d.addCallback(_sendTicketAndIou, pgturl)
        d.addCallback(_package_result, avatar)
        return d

class User(object):

    implements(ICASUser)

    username = None
    attribs = None
    
    def __init__(self, username, attribs):
        self.username = username
        self.attribs = attribs
   
    def logout(self):
        pass 


class UserRealm(object):


    implements(IRealm)


    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        """
        if not ICASUser in interfaces:
            raise NotImplementedError("This realm only implements ICASUser.")
        attribs = [
            ('email', "%s@lafayette.edu" % avatarId),
            ('domain', 'lafayette.edu'),]
        # ENHANCEMENT: This method can also return a deferred that returns
        # (interface, avatar, logout).  Useful if reading user information
        # from a database or LDAP directory.
        avatar = User(avatarId, attribs)
        return (ICASUser, avatar, avatar.logout)



class InMemoryTicketStore(object):
    """
    A ticket store that exists entirely in system memory.
    """

    lifespan = 10
    cookie_lifespan = 60 * 60 * 24 * 2
    charset = string.ascii_letters + string.digits + '-'


    def __init__(self, reactor=reactor, valid_service=None, 
                    is_sso_service=None):
        self.reactor = reactor
        self._tickets = {}
        self._delays = {}
        self.valid_service = valid_service or (lambda x:True)
        self.is_sso_service = is_sso_service or (lambda x: True)

    def debug(self, msg):
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
        self._tickets[ticket] = data
        self.debug("Added ticket '%s' with data: %s" % (ticket, str(data)))
        dc = self.reactor.callLater(timeout, self.expireTicket, ticket)
        self._delays[ticket] = (dc, timeout)
        return defer.succeed(ticket)


    def expireTicket(self, val):
        try:
            del self._tickets[val]
            del self._delays[val]
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
                self.debug("Consumed ticket '%s'." % ticket)
            else:
                dc, timeout = self._delays[ticket]
                dc.reset(timeout)
            return defer.succeed(val)
        except KeyError:
            return defer.fail(InvalidTicket())
        except Exception as ex:
            sys.stderr.write(str(ex))
            sys.stderr.write("\n")
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

    def mkLoginTicket(self, service):
        """
        Create a login ticket.
        """
        d = self._validService(service)
        def cb(_):
            return self._mkTicket('LT-', {
                'service': service,
            }, _timeout=3600) #Login ticket timeout
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


    def mkServiceTicket(self, user, service, tgt, primaryCredentials):
        """
        Create a service ticket
        """
        if not tgt.startswith("TGC-"):
            raise InvalidTicket()
        def doit(_):
            return self._mkTicket('ST-', {
                'user': user,
                'service': service,
                'primary_credentials': primaryCredentials,
            })
        d = self._validService(service)
        d.addCallback(doit)
        d.addCallback(self._informTGTOfService, service, tgt)
        
        return d


    def useServiceTicket(self, ticket, service, requirePrimaryCredentials=False):
        """
        Get the user associated with a service ticket.
        """
        if not ticket.startswith("ST-"):
            raise InvalidTicket()
        def doit(_):
            d = self._useTicket(ticket)
            def cb(data):
                if data['service'] != service:
                    raise InvalidTicket()
                if requirePrimaryCredentials and data['primary_credentials'] == False:
                    raise InvalidTicket("This ticket was not issued in response to primary credentials.")
                return data['user']
            return d.addCallback(cb)
        return self._validService(service).addCallback(doit)


    def mkProxyGrantingTicket(self, avatar, service, ticket):
        """
        Create Proxy Granting Ticket
        """
        if not (ticket.startswith("ST-") or ticket.startswith("PT-")):
            raise InvalidTicket()
        
        def doit(_):
            charset = string.ascii_letters + string.digits
            iou = 'PGTIOU-' + (''.join([random.choice(charset) for n in range(256)]))
            return self._mkTicket('PGT-', {
                'user': avatar,
                'service': service,
                'st_or_pt': ticket,
                'iou': iou,
            }).addCallback(lambda pgt : {'iou': iou, 'pgt': pgt})
        
        d = self._validService(service)
        d.addCallback(doit)
        return d

    def mkTicketGrantingCookie(self, user):
        """
        Create a ticket to be used in a cookie.
        """
        return self._mkTicket('TGC-', {'user': user}, _timeout=self.cookie_lifespan)


    def useTicketGrantingCookie(self, ticket, service):
        """
        Get the user associated with this ticket.
        """
        def cb(_): 
            d = self._useTicket(ticket, _consume=False)
            def extract_user(data):
                return data['user']
            return d.addCallback(extract_user)
        if service != "":
            return self._isSSOService(service).addCallback(cb)
        else:
            return cb(None)

    def expireTGT(self, ticket):
        """
        Expire the TGT identified by 'ticket'.
        """
        if not ticket.startswith("TGC-"):
            raise InvalidTicket()
        
        d = self._useTicket(ticket)
        def cb(data):
            """
            Remove any returned data from the ticket.
            """
            self.debug("Expired TGT '%s'." % ticket)
            services = data.get('services', {})
            self.reactor.callLater(0.0, self._notifyServicesSLO, services)
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
            d = treq.post(service, data=data)
            dlist.append(d)
        return defer.DeferredList(dlist, consumeErrors=True)
        
            
            
            



