from twisted.cred.portal import Portal, IRealm
from twisted.cred.credentials import UsernamePassword
from twisted.internet import defer, reactor
from zope.interface import implements

from klein import Klein

from txcas.interface import ICASUser

from urllib import urlencode

import uuid
import random
import string
import cgi
from xml.sax.saxutils import escape as xml_escape
from textwrap import dedent
import sys


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

class InvalidTicket(Exception):
    pass


class InvalidService(Exception):
    pass


class CookieAuthFailed(Exception):
    pass



class ServerApp(object):

    app = Klein()
    cookie_name = 'tgc'

    
    def __init__(self, ticket_store, realm, checkers, validService=None,
                 requireSSL=True, renderLogin=None):
        self.cookies = {}
        self.ticket_store = ticket_store
        self.portal = Portal(realm)
        self.requireSSL = requireSSL
        map(self.portal.registerChecker, checkers)
        self.validService = validService or (lambda x: True)
        # ENHANCEMENT: A function to allow you to render your own
        # custom login page.  Should accept (loginTicket, service).
        # The rendered page should POST to /login and should include 
        # the login ticket provided and the service callback.
        self.renderLogin = renderLogin

    #ENHANCEMENT: There should be a /proxyValidate endpoint.
    
    #ENHANCEMENT: There should be a /logout endpoint.

    @app.route('/login', methods=['GET'])
    def login_GET(self, request):
        """
        Present a username/password login page to the browser.
        """
        d = self._authenticateByCookie(request)
        d.addErrback(lambda _:self._presentLogin(request))
        def eb(r, request):
            request.setResponseCode(400)
        return d.addErrback(eb, request)


    def _authenticateByCookie(self, request):
        tgc = request.getCookie(self.cookie_name)
        if not tgc:
            return defer.fail(CookieAuthFailed("No cookie"))
        # Q: Should the ticket-granting cookie be checked for expiration?
        service = request.args['service'][0]
        d = self.ticket_store.useTicketGrantingCookie(tgc, service)

        # XXX untested
        def eb(err, request):
            # delete the cookie
            request.addCookie(self.cookie_name, '',
                              expires='Thu, 01 Jan 1970 00:00:00 GMT')
            return err
        d.addErrback(eb, request)
        return d.addCallback(self._authenticated, service, request)


    def _presentLogin(self, request):
        # ENHANCEMENT Login page should be customizable.
        # - Below, `render()` could be a default, but the server should
        # allow you to provide your own `render(login_ticket, service)`
        # that allows you to render your own page.
        # - Any additional information to the custom `render()` could be
        # provided by class state or a closure, for example.
        service = request.args['service'][0]
        d = self.ticket_store.mkLoginTicket(service)
        def render(ticket, service):
            return '''
            <html>
                <body>
                    <form method="post" action="">
                        Username: <input type="text" name="username" />
                        <br />Password: <input type="password" name="password" />
                        <input type="hidden" name="lt" value="%(lt)s" />
                        <input type="hidden" name="service" value="%(service)s" />
                        <input type="submit" value="Sign in" />
                    </form>
                </body>
            </html>
            ''' % {
                'lt': cgi.escape(ticket),
                'service': cgi.escape(service),
            }
        return d.addCallback(render, service)


    def _authenticated(self, user, service, request):
        """
        Call this after authentication has succeeded to finish the request.
        """
        @defer.inlineCallbacks
        def maybeAddCookie(user, request):
            if not request.getCookie(self.cookie_name):
                path = request.URLPath().sibling('').path
                ticket = yield self.ticket_store.mkTicketGrantingCookie(user)
                request.addCookie(self.cookie_name, ticket, path=path,
                                  secure=self.requireSSL)
                request.cookies[-1] += '; HttpOnly'
            defer.returnValue(user)

        def mkServiceTicket(user, service):
            return self.ticket_store.mkServiceTicket(user, service)

        def redirect(ticket, service, request):
            query = urlencode({
                'ticket': ticket,
            })
            request.redirect(service + '?' + query)

        d = maybeAddCookie(user, request)
        d.addCallback(mkServiceTicket, service)
        return d.addCallback(redirect, service, request)


    @app.route('/login', methods=['POST'])
    def login_POST(self, request):
        """
        Accept a username/password, verify the credentials and redirect them
        appropriately.
        """
        service = request.args['service'][0]
        username = request.args['username'][0]
        password = request.args['password'][0]
        ticket = request.args['lt'][0]

        def checkPassword(_, username, password):
            credentials = UsernamePassword(username, password)
            return self.portal.login(credentials, None, ICASUser)

        def extract_avatar(avatarAspect):
            interface, avatar, logout = avatarAspect
            return avatar

        def eb(err, service, request):
            query = urlencode({
                'service': service,
            })
            request.redirect('/login?' + query)
            request.setResponseCode(403)

        # check credentials
        d = self.ticket_store.useLoginTicket(ticket, service)
        d.addCallback(checkPassword, username, password)
        d.addCallback(extract_avatar)
        d.addCallback(self._authenticated, service, request)
        d.addErrback(eb, service, request)
        return d


    @app.route('/logout', methods=['GET'])
    def logout_GET(self, request):
        tgc = request.getCookie(self.cookie_name)
        self.ticket_store.expireTicket(tgc)
        request.addCookie(self.cookie_name, '',
                          expires='Thu, 01 Jan 1970 00:00:00 GMT')
        return 'You have been logged out'


    @app.route('/validate', methods=['GET'])
    def validate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        ticket = request.args['ticket'][0]
        service = request.args['service'][0]
        d = self.ticket_store.useServiceTicket(ticket, service)

        def renderUsername(user):
            return 'yes\n' + user.username + '\n'

        def renderFailure(err, request):
            request.setResponseCode(403)
            return 'no\n\n'

        d.addCallback(renderUsername)
        d.addErrback(renderFailure, request)
        return d        

    @app.route('/serviceValidate', methods=['GET'])
    def serviceValidate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        ticket = request.args['ticket'][0]
        service = request.args['service'][0]
        d = self.ticket_store.useServiceTicket(ticket, service)

        def renderSuccess(avatar):
            doc_begin = dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                    <cas:authenticationSuccess>
                    <cas:user>%s</cas:user>
                """) % xml_escape(avatar.username)
            doc_attributes = make_cas_attributes(avatar.attribs)
            doc_proxy = ""
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
            err.printTraceback(file=sys.stderr)
            request.setResponseCode(403)
            doc_fail = dedent("""\
                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                   <cas:authenticationFailure code="INVALID_TICKET">
                      Ticket %s not recognized`    
                   </cas:authenticationFailure>
                </cas:serviceResponse>
                """) % xml_escape(ticket)
            return doc_fail

        d.addCallback(renderSuccess)
        d.addErrback(renderFailure, request)
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

    def _validService(self, service):
        def cb(result):
            if not result:
                raise InvalidService(service)
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
        dc = self.reactor.callLater(timeout, self.expireTicket, ticket)
        self._delays[ticket] = (dc, timeout)
        return defer.succeed(ticket)


    def expireTicket(self, val):
        try:
            del self._tickets[val]
            del self._delays[val]
        except KeyError:
            pass


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

        XXX
        """
        def doit(_):
            data = self._useTicket(ticket)
            def cb(data):
                if data['service'] != service:
                    raise InvalidTicket()
            return data.addCallback(cb)
        return self._validService(service).addCallback(doit)


    def mkServiceTicket(self, user, service):
        """
        Create a service ticket

        XXX
        """
        def doit(_):
            return self._mkTicket('ST-', {
                'user': user,
                'service': service,
            })
        return self._validService(service).addCallback(doit)


    def useServiceTicket(self, ticket, service):
        """
        Get the user associated with a service ticket.
        """
        # Q: Should the ticket store additional information that is 
        # returned besides the username?
        def doit(_):
            data = self._useTicket(ticket)
            def cb(data):
                if data['service'] != service:
                    raise InvalidTicket()
                return data['user']
            return data.addCallback(cb)
        return self._validService(service).addCallback(doit)


    def mkTicketGrantingCookie(self, user):
        """
        Create a ticket to be used in a cookie.

        XXX
        """
        return self._mkTicket('TGC-', {'user': user}, _timeout=self.cookie_lifespan)


    def useTicketGrantingCookie(self, ticket, service):
        """
        Get the user associated with this ticket.
        """
        def cb(_): 
            data = self._useTicket(ticket, _consume=False)
            def extract_user(data):
                return data['user']
            return data.addCallback(extract_user)
        return self._isSSOService(service).addCallback(cb)






