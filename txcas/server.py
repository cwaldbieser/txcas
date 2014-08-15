

#Standard library
import cgi
import string
import sys
from textwrap import dedent
from urllib import urlencode
import urlparse
from xml.sax.saxutils import escape as xml_escape

#Application modules
from txcas.constants import VIEW_LOGIN, VIEW_LOGIN_SUCCESS, VIEW_LOGOUT, \
                        VIEW_INVALID_SERVICE, VIEW_ERROR_5XX, VIEW_NOT_FOUND
from txcas.exceptions import CASError, InvalidTicket, InvalidService, \
                        CookieAuthFailed, NotSSOService, NotHTTPSError, \
                        InvalidProxyCallback, ViewNotImplementedError, \
                        BadRequestError
import txcas.http
from txcas.interface import ICASUser, ITicketStore
from txcas.utils import http_status_filter

#External modules
from klein import Klein

import treq

from twisted.cred.portal import Portal, IRealm
from twisted.cred.credentials import UsernamePassword
from twisted.cred.error import Unauthorized, UnauthorizedLogin
from twisted.internet import defer, reactor
from twisted.python import log
import twisted.web.http
from twisted.web.static import File
import werkzeug.exceptions
from zope.interface import implements


#=======================================================================

def redirectJSHack(self, url):
    """
    Redirect using JS hack.
    """
    html = dedent("""\
        <html>
            <head>
                <title>Yale Central Authentication Service</title>
                <script> window.location.href="%(url)s";</script>
            </head>
            <body>
                <noscript>
                    <p>CAS login successful.</p>
                    <p>Please proceed to %(url)s .</p>
                </noscript>
            </body>
        </html>
        """) % {'url': escape_html(url)}
    self.write(html)
    self.finish()
    
def redirect303(self, url):
    """
    Redirect using 303
    """
    self.setResponseCode(303)
    self.setHeader(b"location", url)
    
    
twisted.web.http.Request.redirectJSHack = redirectJSHack
twisted.web.http.Request.redirect303 = redirect303
twisted.web.http.Request.redirect302 = twisted.web.http.Request.redirect
twisted.web.http.Request.redirect = twisted.web.http.Request.redirect303

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }

def get_single_param(request, param):
    """
    Checks to make sure there is *exactly* one parameter, `param` in
    request.args and returns its value.
    If the named parameter does not exist or exists multiple times, this
    function raises a txcas.exceptions.BadRequestError
    """
    args = request.args
    if not param in args:
        raise BadRequestError("The parameter '%s' is missing." % param)
    value_list = args[param]
    if len(value_list) != 1:
        raise BadRequestError("Multiple values for parameter '%s' were provided." % param)
    return value_list[0]
    
def get_single_param_or_default(request, param, default=None):
    """
    Checks to make sure there is *exactly* one parameter, `param` in
    request.args and returns its value.
    
    If the named parameter does not exist, return `default`.
    
    If the named parameter exists multiple times, this
    function raises a txcas.exceptions.BadRequestError.
    """
    args = request.args
    if not param in args:
        return default
    value_list = args[param]
    if len(value_list) != 1:
        raise BadRequestError("Multiple values for parameter '%s' were provided." % param)
    return value_list[0]

def escape_html(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)

def log_cas_event(label, attribs):
    """
    Log a CAS event.
    """
    parts = []
    for k,v in attribs:
        parts.append('''%s="%s"''' % (k, v))
    tail = ' '.join(parts)
    log.msg('''[INFO][CAS] label="%s" %s''' % (label, tail))

def log_http_event(request, redact_args=None):
    """
    """
    args = dict(request.args)
    if redact_args is not None:
        for arg in redact_args:
            if arg in args:
                args[arg] = ['*******']
    msg = '''[INFO][HTTP] method="%(method)s path="%(path)s" args="%(args)s"''' % {
        'path': request.path,
        'method': request.method,
        'args': args,
        }
    log.msg(msg)

def log_ticket_expiration(ticket, data, explicit):
    """
    """
    if not explicit:
        attribs = [('ticket', ticket)]
        for key, label in [('service', 'service'), ('avatar_id', 'username'), 
                            ('tgt', 'TGT'), ('pgt', 'PGT'), 
                            ('primary_credentials', 'primary_credentials'),
                            ('proxy_chain', 'proxy_chain')]:
            if key in data:
                val = data[key]
                if key == 'proxy_chain':
                    val = ', '.join(val)
                attribs.append((key, data[key]))
        log_cas_event("Ticket expired", attribs)

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
    if attribs is None or len(attribs) == 0:
        return ""
    parts = ["        <cas:attributes>"]
    for k, v in attribs:
        k = sanitize_keyname(k)
        parts.append("            <cas:%s>%s</cas:%s>" % (k, xml_escape(v), k))
    parts.append("        </cas:attributes>") 
    return '\n'.join(parts)

def sanitize_keyname(name):
    include = set(string.ascii_letters + "-_")
    s = ''.join(ch for ch in name if ch in include)
    return s

def replace_result(_, replacement):
    """
    Replace a result with `replacement`.
    """
    return replacement

def extract_avatar(result):
    """
    Extract the avatarAspect from (iface, aspect, logout).
    """
    iface, aspect, logout = result
    return aspect



#=======================================================================
# The server app
#=======================================================================

class ServerApp(object):

    app = Klein()
    cookie_name = 'tgc'

    
    def __init__(self, ticket_store, realm, checkers, validService=None,
                 requireSSL=True, page_views=None, validate_pgturl=True,
                 static=None):
        """
        Initialize an instance of the CAS server.

        @param ticket_store: The ticket store to use.
        @param realm: The t.c.p.Portal asks the realm for an avatar.
        @param checkers: A list of credential checkers to try (in order).
        @param validService: A callable that takes a service as an argument 
            and returns True if the server will authenticate for that service.
        @param requireSSL: Require SSL for Ticket Granting Cookie
        @param page_views: A mapping of functions that are used to render
            custom pages.
            - All views may either be synchronous or async (deferreds).
            - List of views:
                - login: rendered when credentials are requested.
                    - Should accept args (loginTicket, service, failed, request).
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
                - not_found: Rendered when the requested resource is not found.
                    - Should accept `request`.
        @param validate_pgturl: If True, follow the protocol and validate the pgtUrl
            peer.  Useful to set to False for development purposes.
        @param static_dir: None or path to a static folder to serve content
            from at /static.
        """
        assert ticket_store is not None, "No Ticket Store was configured."
        assert realm is not None, "No Realm was configured."
        assert len(checkers) > 0, "No Credential Checkers were configured."
        for n, checker in enumerate(checkers):
            assert checker is not None, "Credential Checker #%d was not configured." % n
        
        self.cookies = {}
        self.ticket_store = ticket_store
        self.portal = Portal(realm)
        self.realm = realm
        self.requireSSL = requireSSL
        map(self.portal.registerChecker, checkers)
        self.validService = validService or (lambda x: True)
        self.validate_pgturl = validate_pgturl
        self._static = static

        default_page_views = {
                VIEW_LOGIN: self._renderLogin,
                VIEW_LOGIN_SUCCESS: self._renderLoginSuccess,
                VIEW_LOGOUT: self._renderLogout,
                VIEW_INVALID_SERVICE: self._renderInvalidService,
                VIEW_ERROR_5XX: self._renderError5xx,
                VIEW_NOT_FOUND: self._renderNotFound,
            }
        self._default_page_views = default_page_views
        if page_views is None:
            page_views = default_page_views
        else:
            temp = dict(default_page_views)
            temp.update(page_views)
            page_views = temp
            del temp
        self.page_views = page_views
        
        self.ticket_store.register_ticket_expiration_callback(log_ticket_expiration)

    def _set_response_code_filter(self, result, code, request, msg=None):
        """
        Set the response code during deferred chain processing.
        """
        request.setResponseCode(code, msg=msg)
        return result
        
    def _log_failure_filter(self, err, request):
        """
        Log a failure.
        """
        log.msg('[ERROR] type="error" client_ip="%s" uri="%s"' % (request.getClientIP(), request.uri))
        log.err(err)
        return err

    def _get_page_view(self, symbol, *args):
        """
        """
        def eb(err, symbol, *args):
            err.trap(ViewNotImplementedError) 
            log.err(err)            

            return defer.maybeDeferred(self._default_page_views[symbol], *args)

        d = defer.maybeDeferred(self.page_views[symbol], *args)
        d.addErrback(eb, symbol, *args) 
        return d

    def _page_view_callback(self, _, symbol, *args):
        """
        """
        d = self._get_page_view(symbol, *args)
        return d

    def _page_view_result_callback(self, result, symbol, *args):
        """
        """
        d = self._get_page_view(symbol, result, *args)
        return d

    def _page_view_errback(self, err, symbol, *args):
        """
        """
        d = self._get_page_view(symbol, err, *args) 
        return d

    @app.route('/login', methods=['GET'])
    def login_GET(self, request):
        """
        Present a username/password login page to the browser.
        OR
        authenticate using an existing TGC.
        """
        log_http_event(request)
        service = get_single_param_or_default(request, 'service', "")
        renew = get_single_param_or_default(request, 'renew', "")
        if renew != "":
            return self._presentLogin(request)
            
        def service_err(err, service, request):
            err.trap(InvalidService)
            log.err(err)
            request.setResponseCode(403)
            return self._get_page_view(VIEW_INVALID_SERVICE, service, request)

        d = self._authenticateByCookie(request)
        d.addErrback(lambda _:self._presentLogin(request))
        d.addErrback(service_err, service, request)
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX,  request)
        return d

    def _authenticateByCookie(self, request):
        tgc = request.getCookie(self.cookie_name)
        if not tgc:
            return defer.fail(CookieAuthFailed("No cookie"))
        # Q: Should the ticket-granting cookie be checked for expiration?
        # I think a browser won't send expired cookies.  Anyway, expiration
        # should happen on the server.
        service = get_single_param_or_default(request, 'service', "")

        def log_tgc_auth(result, request):
            client_ip = request.getClientIP()
            avatar_id = result['avatar_id']
            log_cas_event("Authenticated via TGC", [
                        ('client_ip', client_ip), ('username', avatar_id)])
            return result

        def extract_avatar_id(result):
            return result['avatar_id']

        def eb(err, request):
            err.trap(InvalidTicket, NotSSOService)
            # delete the cookie
            request.addCookie(self.cookie_name, '',
                              expires='Thu, 01 Jan 1970 00:00:00 GMT')
            return err

        d = self.ticket_store.useTicketGrantingCookie(tgc, service)
        d.addCallback(log_tgc_auth, request)
        d.addCallback(extract_avatar_id)
        d.addErrback(eb, request)
        return d.addCallback(self._authenticated, False, service, request)

    def _presentLogin(self, request, failed=False):
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
        service = get_single_param_or_default(request, 'service', "")
        gateway = get_single_param_or_default(request, 'gateway', "")
        if gateway != "" and service != "":
            #Redirect to `service` with no ticket.
            request.redirect(service)            
            request.finish()
            return
       
        def service_err(err, service, request):
            err.trap(InvalidService)
            log.err(err)
            request.setResponseCode(403)
            return self._get_page_view(VIEW_INVALID_SERVICE, service, request)
 
        d = defer.maybeDeferred(expireTGT)
        d.addCallback(lambda x: service)
        d.addCallback(self.ticket_store.mkLoginTicket)
        d.addCallback(self._page_view_result_callback, VIEW_LOGIN, service, failed, request)
        d.addErrback(service_err, service, request)
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX, request)
        return d
            

    def _authenticated(self, avatar_id, primaryCredentials, service, request):
        """
        Call this after authentication has succeeded to finish the request.
        """
        tgc = request.getCookie(self.cookie_name)
        
        @defer.inlineCallbacks
        def maybeAddCookie(avatar_id, service, request):
            ticket = request.getCookie(self.cookie_name)
            if not ticket:
                path = request.URLPath().sibling('').path
                ticket = yield self.ticket_store.mkTicketGrantingCookie(avatar_id)
                request.addCookie(self.cookie_name, ticket, path=path,
                                  secure=self.requireSSL)
                request.cookies[-1] += '; HttpOnly'
                attribs = [
                    ('client_ip', request.getClientIP()),
                    ('username', avatar_id),
                    ('TGC', ticket),]
                if service != "":
                    attribs.append(('service', service))
                log_cas_event("Created TGC", attribs)
            defer.returnValue(ticket)

        def mkServiceTicket(tgc, service, request):
            
            def log_service_ticket_created(ticket, service, tgc, request):
                client_ip = request.getClientIP()
                log_cas_event("Created service ticket", [
                            ('client_ip', client_ip), 
                            ('ticket', ticket),
                            ('service', service),
                            ('TGC', tgc),])
                return ticket
            
            def log_failed_to_create_ticket(err, service, tgc, request):
                client_ip = request.getClientIP()
                log_cas_event("Failed to create service ticket", [
                    ('client_ip', client_ip), 
                    ('service', service),
                    ('TGC', tgc)])
                return err
                
            return self.ticket_store.mkServiceTicket(service, tgc, primaryCredentials).addCallback(
                log_service_ticket_created, service, tgc, request).addErrback(
                log_failed_to_create_ticket, service, tgc, request)
            
        def redirect(ticket, service, request):
            query = urlencode({
                'ticket': ticket,
            })
            request.redirect(service + '?' + query)

        d = maybeAddCookie(avatar_id, service, request)
        if service != "":
            d.addCallback(mkServiceTicket, service, request)
            d.addCallback(redirect, service, request)
        else:
            d.addCallback(replace_result, avatar_id)
            d.addCallback(self.realm.requestAvatar, None, ICASUser)
            d.addCallback(extract_avatar)
            d.addCallback(self._page_view_result_callback, VIEW_LOGIN_SUCCESS, request)
            
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX, request)
        return d

    def _renderLogin(self, ticket, service, failed, request):
        html_parts = []
        html_parts.append(dedent('''\
        <html>
            <body>
                <form method="post" action="">
                    Username: <input type="text" name="username" />
                    <br />Password: <input type="password" name="password" />
                    <input type="hidden" name="lt" value="%(lt)s" />
        ''') % {
            'lt': cgi.escape(ticket),
        })
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
        
    def _renderNotFound(self, request):
        return dedent("""\
            <html>
            <head>
                <title>Not Found</title>
            </head>
            <body>
                <h1>Not Found</h1>
                <p>
                The resource you were looking for was not found.
                </p>
            </body>
            </html>
            """)

    @app.route('/login', methods=['POST'])
    def login_POST(self, request):
        """
        Accept a username/password, verify the credentials and redirect them
        appropriately.
        """
        log_http_event(request, redact_args=['password'])
        service = get_single_param_or_default(request, 'service', "")
        renew = get_single_param_or_default(request, 'renew', "")
        username = get_single_param_or_default(request, 'username', None)
        password = get_single_param_or_default(request, 'password', None)
        ticket = get_single_param_or_default(request, 'lt', None)

        def checkPassword(_, username, password):
            credentials = UsernamePassword(username, password)
            return self.portal.login(credentials, None, ICASUser)

        def log_auth_failed(err, username, request):
            err.trap(Unauthorized)
            client_ip = request.getClientIP()
            log_cas_event("Failed to authenticate using primary credentials", [
                        ('client_ip', client_ip), ('username', username)])
            
            return err

        def log_authentication(result, username, request):
            client_ip = request.getClientIP()
            log_cas_event("Authenticated using primary credentials", [
                        ('client_ip', client_ip), ('username', username)])
            return result

        def inject_avatar_id(_, avatar_id):
            return avatar_id

        def eb(err, service, request):
            if not err.check(Unauthorized):
                log.err(err)

            d = self._presentLogin(request, failed=True)
            return d

        # check credentials
        d = self.ticket_store.useLoginTicket(ticket, service)
        d.addCallback(checkPassword, username, password)
        d.addErrback(log_auth_failed, username, request)
        d.addCallback(log_authentication, username, request)
        d.addCallback(inject_avatar_id, username)
        d.addCallback(self._authenticated, True, service, request)
        d.addErrback(eb, service, request)
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX,  request)
        return d


    @app.route('/logout', methods=['GET'])
    def logout_GET(self, request):
        log_http_event(request)
        service = get_single_param_or_default(request, 'service', "")
        def _validService(_, service):
            def eb(err):
                err.trap(InvalidService)
                return self._get_page_view(VIEW_INVALID_SERVICE, service, request)
            return defer.maybeDeferred(
                self.validService, service).addErrback(eb)
                
        tgc = request.getCookie(self.cookie_name)
        if tgc:
            #Delete the cookie.
            request.addCookie(
                self.cookie_name, '', expires='Thu, 01 Jan 1970 00:00:00 GMT')
            #Expire the ticket.
            def log_ticket_expired(result, tgc, request):
                log_cas_event("Explicitly logged out of SSO", [
                    ('client_ip', request.getClientIP()),
                    ('TGC', tgc)])
                return result
            d = self.ticket_store.expireTGT(tgc)
            d.addCallback(log_ticket_expired, tgc, request)
        else:
            d = defer.maybeDeferred(lambda : None)

        if service != "":
            def redirect(_):
                request.redirect(service)
            d.addCallback(_validService, service)
            d.addCallback(redirect)
        else:
            d.addCallback(self._page_view_callback, VIEW_LOGOUT, request)

        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX, request)
        return d


    @app.route('/validate', methods=['GET'])
    def validate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        log_http_event(request)
        ticket = get_single_param_or_default(request, 'ticket', "")
        service = get_single_param_or_default(request, 'service', "")
        renew = get_single_param_or_default(request, 'renew', "")
        if service == "" or ticket == "":
            request.setResponseCode(403)
            return 'no\n\n'

        if renew != "":
            require_pc = True
        else:
            require_pc = False        
        d = self.ticket_store.useServiceTicket(ticket, service, require_pc)

        def renderUsername(data, ticket, service, request):
            avatar_id = data['avatar_id']
            
            def successResult(result, ticket_info, ticket, service, request):
                iface, avatarAspect, logout = result
                attribs = [
                    ('client_ip', request.getClientIP()),
                    ('user', avatarAspect.username),
                    ('ticket', ticket),
                    ('service', service),
                    ('TGT', ticket_info['tgt']),
                    ('primary_credentials', ticket_info['primary_credentials']),]
                if 'pgt' in ticket_info:
                    attribs.append(("PGT", ticket_info['pgt']))
                if 'proxy_chain' in ticket_info:
                    attribs.append(("proxy_chain", ', '.join(ticket_info['proxy_chain'])))
                log_cas_event("Validated service ticket (/validate)", attribs)
                return 'yes\n' + avatarAspect.username + '\n'
            
            return self.realm.requestAvatar(avatar_id, None, ICASUser).addCallback(
                successResult, data, ticket, service, request)
            
        def renderFailure(err, ticket, service, request):
            log_cas_event("Failed to validate service ticket (/validate).", [
                ('client_ip', request.getClientIP()),
                ('ticket', ticket),
                ('service', service),])
            err.trap(InvalidTicket)
            request.setResponseCode(403)
            return 'no\n\n'

        d.addCallback(renderUsername, ticket, service, request)
        d.addErrback(renderFailure, ticket, service, request)
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX, request)
        return d        

    @app.route('/serviceValidate', methods=['GET'])
    def serviceValidate_GET(self, request):
        log_http_event(request)
        return self._serviceOrProxyValidate(request, False)
        
    @app.route('/proxyValidate', methods=['GET'])
    def proxyValidate_GET(self, request):
        log_http_event(request)
        return self._serviceOrProxyValidate(request, True)
    
    def _serviceOrProxyValidate(self, request, proxyValidate=True):
        """
        Validate a service ticket or proxy ticket, consuming the ticket in the process.
        """
        ticket = get_single_param_or_default(request, 'ticket', None)
        service = get_single_param_or_default(request, 'service', None)
        pgturl = get_single_param_or_default(request, 'pgtUrl', "")
        renew = get_single_param_or_default(request, 'renew', "")
        
        if service is None or ticket is None:
            request.setResponseCode(400)
            return "Bad request"
        
        if renew != "":
            require_pc = True
        else:
            require_pc = False
       
        if proxyValidate: 
            d = self.ticket_store.useServiceOrProxyTicket(ticket, service, require_pc)
        else:
            d = self.ticket_store.useServiceTicket(ticket, service, require_pc)

        def getAvatar(ticket_data):
            def avatarResult(result, ticket_data):
                """
                Append the avatarAspect to the ticket data.
                """
                iface, avatarAspect, logout = result
                ticket_data['avatar'] = avatarAspect
                return ticket_data
            return self.realm.requestAvatar(ticket_data['avatar_id'], None, ICASUser).addCallback(
                avatarResult, ticket_data) 

        def renderSuccess(results, ticket, request):
            avatar = results['avatar']
            
            attribs = [
                ('client_ip', request.getClientIP()),
                ('user', avatar.username),
                ('ticket', ticket),
                ('service', service),
                ('TGT', results['tgt']),
                ('primary_credentials', results['primary_credentials']),]
            if 'pgt' in results:
                attribs.append(("PGT", results['pgt']))
            if 'proxy_chain' in results:
                attribs.append(("proxy_chain", ', '.join(results['proxy_chain'])))
            log_cas_event("Validated ticket.", attribs)
            
            iou = results.get('iou', None)
            proxy_chain = results.get('proxy_chain', None)
            
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
            doc_proxy_chain = ""
            if proxy_chain is not None:
                parts = ['''        <cas:proxies>''']
                for pgturl in proxy_chain:
                    parts.append("""            <cas:proxy>%s</cas:proxy>""" % xml_escape(pgturl))
                parts.append('''        </cas:proxies>''')
                doc_proxy_chain = '\n'.join(parts)
                del parts
            doc_end = dedent("""\
                    </cas:authenticationSuccess>
                </cas:serviceResponse>
                """)
            doc_parts = [doc_begin]
            for part in (doc_attributes, doc_proxy, doc_proxy_chain):
                if len(part) > 0:
                    doc_parts.append(part)
            doc_parts.append(doc_end)
            return '\n'.join(doc_parts)

        def renderFailure(err, ticket, request):
            log_cas_event("Failed to validate ticket.", [
                ('client_ip', request.getClientIP()),
                ('ticket', ticket)])
            err.trap(InvalidTicket, InvalidProxyCallback, InvalidService)
            request.setResponseCode(403)
            code = "INVALID_TICKET"
            if err.check(InvalidProxyCallback):
                code = "INVALID_PROXY_CALLBACK"
            elif err.check(InvalidService):
                code = "INVALID_SERVICE"
            doc_fail = dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                   <cas:authenticationFailure code="%(code)s">
                      Validation failed for ticket %(ticket)s.    
                   </cas:authenticationFailure>
                </cas:serviceResponse>
                """) % {
                    'code': xml_escape(code),
                    'ticket': xml_escape(ticket),}
            return doc_fail

        d.addCallback(self._validateProxyUrl, pgturl, service, ticket, request)
        d.addCallback(getAvatar)
        d.addCallback(renderSuccess, ticket, request)
        d.addErrback(renderFailure, ticket, request)
        d.addErrback(self._log_failure_filter, request)
        d.addErrback(self._set_response_code_filter, 500, request)
        d.addErrback(self._page_view_errback, VIEW_ERROR_5XX, request)
        return d        

    def _validateProxyUrl(self, data, pgturl, service, ticket, request):
        """
        Validate service callback.
        Generate PGT + IOU.
        POST both to pgturl.
        Return avatar.
        Optionally return IOU, proxy_chain.
        """
        # NOTE: `data` is the validated ST or PT data.
        # `ticket` is the ST or PT *identifier*, but the ticket has already
        # been consumed at this point.  The ID is needed just to in case a 
        # PGT is created and we want to record its origin ST/PT.
        avatar_id = data['avatar_id']
        tgt = data['tgt']

        # If the validated ticket was a PT, extract the proxy_chain that was used
        # to create *its* parent PGT so it can be added to the proxy chain for
        # the requested PGT.
        #
        # E.g. Service A obtains a PGT.  It uses PGT-A to get PT-A and request
        # a service from B.  Service B uses PT-A to get PGT-B.  It requests
        # PT-B from CAS, and uses PT-B to request service from C.  C validates
        # PT-B.  The response to C would include the pgturls for A (first) and
        # B (second).
        if 'proxy_chain' in data:
            proxy_chain = data['proxy_chain']
        else:
            proxy_chain = None

        if pgturl == "":
            return data
        
        def _mkPGT(_):
            return self.ticket_store.mkProxyGrantingTicket(
                service, ticket, tgt, pgturl, proxy_chain=proxy_chain)
        
        def _sendTicketAndIou(pgt_info, pgturl, reqlib):
            """
            """
            pgt = pgt_info['pgt']
            iou = pgt_info['iou']
            def iou_cb(resp_text, pgtiou):
                """
                Return the iou parameter.
                """
                return pgtiou
                
            q = {'pgtId': pgt, 'pgtIou': iou}
            log_cas_event("Sending pgtId and pgtIou to client.", [
                ('pgturl', pgturl),
                ('pgtIou', iou),
                ('pgtId', pgt),])
            d = reqlib.get(pgturl, params=q, timeout=30)
            d.addCallback(http_status_filter, [(200, 200)], InvalidProxyCallback)
            d.addCallback(reqlib.content)
            d.addCallback(iou_cb, iou)
            return d
            
        def _package_result(iou, data):
            data['iou'] = iou
            return data
        
        reqlib = treq
        if self.validate_pgturl:
            p = urlparse.urlparse(pgturl)
            if p.scheme.lower() != "https":
                raise NotHTTPSError("The pgtUrl '%s' is not HTTPS.")
        else:
            reqlib = txcas.http
            
        d = reqlib.get(pgturl)
        d.addCallback(http_status_filter, [(200, 200)], InvalidProxyCallback)
        d.addCallback(reqlib.content)
        
        d.addCallback(_mkPGT)
        d.addCallback(_sendTicketAndIou, pgturl, reqlib)
        d.addCallback(_package_result, data)
        
        return d

    @app.route('/proxy', methods=['GET'])
    def proxy_GET(self, request):
        log_http_event(request)
        try:
            pgt = get_single_param(request, 'pgt')
            targetService = get_single_param(request, 'targetService')
        except BadRequestError as ex:
            log.err(ex)
            request.setResponseCode(400)
            # Enhancement: page view
            return "Bad Request"
        
        # Validate the PGT and get the PT
        def successResult(ticket, targetService, pgt, request):
            log_cas_event("Issued proxy ticket", [
                ('client_ip', request.getClientIP()),
                ('ticket', ticket),
                ('targetService', targetService),
                ('PGT', pgt),])
            return dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                    <cas:proxySuccess>
                        <cas:proxyTicket>%(ticket)s</cas:proxyTicket>
                    </cas:proxySuccess>
                </cas:serviceResponse>
                """) % {'ticket': xml_escape(ticket)}

        def failureResult(err, targetService, pgt, request):
            log_cas_event("Failed to issue proxy ticket", [
                ('client_ip', request.getClientIP()),
                ('targetService', targetService),
                ('PGT', pgt),])
            if not err.check(InvalidTicket, InvalidService):
                log.err(err)
            return dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                    <cas:proxyFailure code="INVALID_REQUEST">
                        Error requesting proxy ticket.       
                    </cas:proxyFailure>
                </cas:serviceResponse>
                """)

        d = defer.maybeDeferred(self.ticket_store.mkProxyTicket, targetService, pgt)
        d.addCallback(successResult, targetService, pgt, request)
        d.addErrback(failureResult, targetService, pgt, request)
        return d

    @app.route('/static/', methods=['GET'], branch=True)
    def static_GET(self, request):
        static = self._static
        if static is None:
            log.msg('[ERROR] type="not_found" client_ip="%s" uri="%s"' % (
                        request.getClientIP(), request.uri))
            return self._get_page_view(VIEW_NOT_FOUND, request)
        else:
            return File(static)

    @app.handle_errors(werkzeug.exceptions.NotFound)
    def error_handler(self, request, failure):
        log.msg('[ERROR] type="not_found" client_ip="%s" uri="%s"' % (
                    request.getClientIP(), request.uri))
        return self._get_page_view(VIEW_NOT_FOUND, request)


    @app.handle_errors(BadRequestError)
    def handle_bad_request(self, request, failure):
        log.msg('[ERROR] type="bad_request" client_ip="%s" uri="%s"' % (
                    request.getClientIP(), request.uri))
        return self._get_page_view(VIEW_ERROR_5XX, failure, request)
        
            
            
            



