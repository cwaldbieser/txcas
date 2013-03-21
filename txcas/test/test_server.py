from twisted.trial.unittest import TestCase
from twisted.internet import defer, task, reactor, utils, protocol
from twisted.cred.portal import Portal, IRealm
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.web import server
from twisted.web.test.test_web import DummyChannel
from twisted.web.http_headers import Headers
from twisted.python.filepath import FilePath

from mock import Mock
from urlparse import urlparse, parse_qs

from zope.interface import implements
from zope.interface.verify import verifyObject

from txcas.server import (ServerApp, UserRealm, InMemoryTicketStore,
                          InvalidTicket)
from txcas.interface import IUser

from xml.dom.minidom import parseString
from StringIO import StringIO
import os
import re
import sys

from collections import defaultdict



class FakeRequest(server.Request):


    def __init__(self, method='GET', path='/', args=None, isSecure=False,
                 headers=None):
        server.Request.__init__(self, DummyChannel(), False)
        self.requestHeaders = Headers(headers)
        self.args = args or {}
        self.method = method
        self.uri = path
        self.clientproto = 'HTTP/1.1'
        self.prepath = path.split('/')[1:]
        self.postpath = []
        self.setHost('127.0.0.1', 8080, isSecure)
        self.responseHeaders = defaultdict(lambda:[])
        self.responseCode = None
        self.redirected = None
        self.parseCookies()


    def setHeader(self, key, value):
        self.responseHeaders[key].append(value)


    def setResponseCode(self, code):
        self.responseCode = code


    def redirect(self, where):
        self.redirected = where



class InMemoryTicketStoreTest(TestCase):


    def getStore(self):
        self.clock = task.Clock()
        store = InMemoryTicketStore(reactor=self.clock)
        return store


    @defer.inlineCallbacks
    def test_mkTicket(self):
        """
        You can make and use tickets
        """
        store = self.getStore()
        lt = yield store._mkTicket('LT-', 'some service')
        self.assertTrue(lt.startswith('LT-'))
        self.assertEqual(len(lt), 256)
        r = yield store._useTicket(lt)
        self.assertEqual(r, 'some service', "Should return the data associated"
                         " with the ticket during creation")


    @defer.inlineCallbacks
    def test_mkTicket_expire(self):
        store = self.getStore()
        t = yield store._mkTicket('LT-', 'something')
        self.clock.advance(store.lifespan)

        self.assertFailure(store._useTicket(t), InvalidTicket)


    @defer.inlineCallbacks
    def test_useTicket_thenExpire(self):
        """
        If a ticket is used, then expiry shouldn't fail.
        """
        store = self.getStore()
        t = yield store._mkTicket('LT-', 'something')
        yield store._useTicket(t)
        self.clock.advance(store.lifespan)


    @defer.inlineCallbacks
    def test_loginTicket_service(self):
        """
        You can make login tickets associated with a service
        """
        store = self.getStore()
        t = yield store.mkLoginTicket(service='service')
        self.assertTrue(t.startswith('LT-'))
        yield store.useLoginTicket(t, service='service')


    @defer.inlineCallbacks
    def test_loginTicket_badService(self):
        """
        It is a failure to use a login ticket with the wrong service.
        """
        store = self.getStore()
        t = yield store.mkLoginTicket(service='service')
        self.assertTrue(t.startswith('LT-'))
        self.assertFailure(store.useLoginTicket(t, service='different service'),
                           InvalidTicket)


    @defer.inlineCallbacks
    def test_serviceTicket_validation(self):
        """
        You can validate a service ticket
        """
        store = self.getStore()
        t = yield store.mkServiceTicket('username', 'service')
        self.assertTrue(t.startswith('ST-'))
        username = yield store.useServiceTicket(t, 'service')
        self.assertEqual(username, 'username')


    @defer.inlineCallbacks
    def test_serviceTicket_badService(self):
        """
        If the service used to validate a ticket doesn't match, it should fail.
        """
        store = self.getStore()
        t = yield store.mkServiceTicket('username', 'foo')
        self.assertFailure(store.useServiceTicket(t, 'bar'), InvalidTicket)


    @defer.inlineCallbacks
    def test_ticketGrantingCookie(self):
        """
        These tickets have a longer, extendable timeout and aren't consumed
        when used.
        """
        store = self.getStore()
        t = yield store.mkTicketGrantingCookie('username')
        self.assertTrue(t.startswith('TGC-'))

        # move ahead a little bit
        self.clock.advance(store.cookie_lifespan/2)

        username = yield store.useTicketGrantingCookie(t)
        self.assertEqual(username, 'username')
        
        # it should be extended beyond the last access
        self.clock.advance(store.cookie_lifespan-1)
        username = yield store.useTicketGrantingCookie(t)
        self.assertEqual(username, 'username')

        self.clock.advance(store.cookie_lifespan)
        self.assertFailure(store.useTicketGrantingCookie(t), InvalidTicket)



class UserRealmTest(TestCase):


    def test_IRealm(self):
        verifyObject(IRealm, UserRealm())


    def test_requestAvatar(self):
        """
        This should return an IUser if requested.
        """
        store = UserRealm()
        avatar = store.requestAvatar('foo', None, IUser)
        self.assertTrue(IUser.providedBy(avatar), 'Avatar should implement'
                        ' IUser: %r' % (avatar,))
        self.assertEqual(avatar.username, 'foo')



class ServerAppTest(TestCase):


    def test_init(self):
        """
        It should accept a UserStore on init
        """
        checker = InMemoryUsernamePasswordDatabaseDontUse()
        realm = UserRealm()

        app = ServerApp(None, realm, [checker], 'services')
        self.assertEqual(app.ticket_store, None)
        self.assertEqual(app.portal.realm, realm)
        self.assertIn(checker, app.portal.checkers.values())
        self.assertEqual(app.validService, 'services')



class FunctionalTest(TestCase):

    timeout = 3


    def setUp(self):
        checker = InMemoryUsernamePasswordDatabaseDontUse(foo='something')
        realm = UserRealm()
        self.clock = task.Clock()
        app = ServerApp(InMemoryTicketStore(reactor=self.clock), realm,
                        [checker], lambda x: True)
        self.app = app
        self.resource = app.app.resource()


    def getInputs(self, text):
        """
        Get a dictionary of inputs and their values from a blob of html
        """
        parsed = parseString(text)
        forms = parsed.getElementsByTagName('form')
        form = forms[0]
        inputs = form.getElementsByTagName('input')
        ret = {}
        for i in inputs:
            ret[i.getAttribute('name')] = {
                'value': i.getAttribute('value'),
            }
        return ret


    @defer.inlineCallbacks
    def test_basicSuccess(self):
        """
        You can log in and verify tickets
        """
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': ['http://www.example.com'],
        })

        body = yield self.app.login_GET(request)

        parsed = parseString(body)
        forms = parsed.getElementsByTagName('form')
        self.assertEqual(len(forms), 1, "There should only be one form")
        form = forms[0]
        inputs = form.getElementsByTagName('input')
        inputs = [(x.getAttribute('name'), x.getAttribute('value'), x.getAttribute('type')) for x in inputs]

        lt_input = [x for x in inputs if x[0] == 'lt'][0]
        lt_value = lt_input[1]
        self.assertTrue(lt_value.startswith('LT-'), repr(lt_value))
        self.assertIn(('username', '', 'text'), inputs)
        self.assertIn(('password', '', 'password'), inputs)
        self.assertIn(('lt', lt_value, 'hidden'), inputs)
        self.assertIn(('service', 'http://www.example.com', 'hidden'), inputs)

        # POST /login
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [lt_value],
            'service': ['http://www.example.com'],
        })

        body = yield self.app.login_POST(request)
        redirect_url = request.redirected
        self.assertTrue(redirect_url.startswith('http://www.example.com'),
                        redirect_url)
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        ticket = qs['ticket'][0]
        self.assertTrue(ticket.startswith('ST-'))
        self.assertEqual(len(ticket), 256)

        # GET /validate
        request = FakeRequest(args={
            'service': ['http://www.example.com'],
            'ticket': [ticket],
        })

        body = yield self.app.validate_GET(request)
        self.assertEqual(body, 'yes\nfoo\n')


    @defer.inlineCallbacks
    def test_login_badpassword(self):
        """
        The user's password has to match
        """
        app = self.app

        # GET
        request = FakeRequest(args={
            'service': ['http://www.example.com'],
        })

        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST with wrong password
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['bad password'],
            'lt': [inputs['lt']['value']],
            'service': [inputs['service']['value']],
        })
        body = yield self.app.login_POST(request)

        self.assertEqual(request.responseCode, 403, "Should be forbidden")
        redirect_url = request.redirected
        self.assertTrue(redirect_url.startswith('/login?'))
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        self.assertEqual(qs['service'][0], 'http://www.example.com',
                         "Should redirect for the same service")


    @defer.inlineCallbacks
    def test_login_badservice(self):
        """
        If the service provided in POST doesn't match that in GET, then fail.
        """
        app = self.app
        request = FakeRequest(args={
            'service': ['foo'],
        })

        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST with wrong service
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': ['different service'],
        })
        body = yield self.app.login_POST(request)

        self.assertEqual(request.responseCode, 403)


    @defer.inlineCallbacks
    def test_validate_badservice(self):
        """
        If the service provided to /validate doesn't match the service provided
        to /login then fail the validation.
        """
        app = self.app
        request = FakeRequest(args={
            'service': ['foo'],
        })

        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': ['foo'],
        })
        body = yield self.app.login_POST(request)
        redirect_url = request.redirected
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        ticket = qs['ticket'][0]
        
        # GET /validate with wrong service
        request = FakeRequest(args={
            'ticket': [ticket],
            'service': ['different'],
        })

        body = yield self.app.validate_GET(request)
        self.assertEqual(request.responseCode, 403)
        self.assertEqual(body, 'no\n\n')


    @defer.inlineCallbacks
    def test_ticket_granting_cookie_success(self):
        """
        After authenticating once, a client should be able to reuse a
        ticket-granting cookie to authenticate again without having to put
        in credentials.
        """
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': ['foo'],
        })
        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST /login
        request = FakeRequest(method='POST', path='/cas/login', args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': ['foo'],
        })
        body = yield self.app.login_POST(request)
        self.assertTrue(len(request.cookies) >= 1, "Should have at least one"
                        " cookie")
        cookie = request.cookies[0]
        parts = cookie.split('; ')
        self.assertIn('Secure', parts)
        self.assertIn('HttpOnly', parts)
        self.assertIn('Path=/cas/', parts)
        name, value = parts[0].split('=', 1)
        self.assertEqual(name, self.app.cookie_name)
        self.assertTrue(value.startswith('TGC-'))
        
        # GET /login again with the cookie for a different service
        parts.remove('Secure')
        parts.remove('HttpOnly')
        request = FakeRequest(args={
            'service': ['somewhere'],
        }, headers={
            'Cookie': ['; '.join(parts)],
        })
        body = yield self.app.login_GET(request)
        redirect_url = request.redirected
        self.assertTrue(redirect_url.startswith('somewhere'), redirect_url)
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        ticket = qs['ticket'][0]

        self.assertEqual(len(request.cookies), 0, "Should not set the cookie "
                         "again")

        # GET /validate
        request = FakeRequest(args={
            'service': ['somewhere'],
            'ticket': [ticket],
        })

        body = yield self.app.validate_GET(request)
        self.assertEqual(body, 'yes\nfoo\n')


    @defer.inlineCallbacks
    def test_logout(self):
        """
        You can log out (which will invalidate the ticket granting cookie)
        """
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': ['foo'],
        })
        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST /login
        request = FakeRequest(method='POST', path='/cas/login', args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': ['foo'],
        })
        body = yield self.app.login_POST(request)
        self.assertTrue(len(request.cookies) >= 1, "Should have at least one"
                        " cookie")
        cookie = request.cookies[0]

        # GET /logout
        request = FakeRequest(headers={
            'Cookie': [cookie],
        })
        body = yield self.app.logout_GET(request)

        # GET /login again with the cookie
        request = FakeRequest(args={
            'service': ['somewhere'],
        }, headers={
            'Cookie': [cookie],
        })
        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)
        self.assertIn('lt', inputs)


