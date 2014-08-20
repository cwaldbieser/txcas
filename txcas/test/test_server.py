
# Standard modules
from collections import defaultdict
import ConfigParser
import os
import os.path
import re
from StringIO import StringIO
import sys
from urlparse import urlparse, parse_qs
from xml.dom.minidom import parseString


# Application modules
from txcas.basic_realm import BasicRealm
from txcas.couchdb_ticket_store import CouchDBTicketStore
import txcas.exceptions
from txcas.in_memory_ticket_store import InMemoryTicketStore
from txcas.interface import ICASUser
from txcas.server import ServerApp 
from txcas.settings import load_defaults, export_settings_to_dict

# External modules
from twisted.cred.portal import Portal, IRealm
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.internet import defer, task, reactor, utils, protocol
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase
from twisted.web import server
from twisted.web.test.test_web import DummyChannel
from twisted.web.http_headers import Headers
from zope.interface import implements
from zope.interface.verify import verifyObject


def load_config(defaults=None):
    """
    """
    scp = load_defaults(defaults)
    path = os.path.join(os.path.dirname(__file__), "tests.cfg")
    scp.read([path])
    
    return scp
    

class FakeRequest(server.Request):
    """
    A fake request object.
    """

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



class TicketStoreTester(object):
    """
    Test a ticket store.
    """
    
    ticket_size = 256
    service = "http://service.example.net/theservice"
    proxied_service = "http://service.example.net/the/proxied/service"
    pgturl = "http://service.example.net/pgtcallback"
    avatar_id = "jane.smith"
    
    def setUp(self):
        self.clock = task.Clock()
        store = self.getStore(self.clock)
        store.ticket_size = self.ticket_size
        self.store = store
    
    def getStore(self, clock):
        """
        Implement this to create and return a ticket store.
        """
        raise NotImplementedError()

    @defer.inlineCallbacks
    def makeTicketGrantingCookie(self):
        """
        Create a TGT. 
        """
        tgt = yield self.store.mkTicketGrantingCookie(self.avatar_id)
        defer.returnValue(tgt)

    @defer.inlineCallbacks
    def makeProxyGrantingTicket(self):
        """
        Create a PGT. 
        """
        store = self.store
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(self.service, tgt, False)
        result = yield self.store.mkProxyGrantingTicket(
                    self.service, 
                    st, 
                    tgt, 
                    self.pgturl, 
                    proxy_chain=None)
        pgt = result['pgt']
        iou = result['iou']
        defer.returnValue((tgt, st, pgt, iou))

    @defer.inlineCallbacks
    def test_LT_spec(self):
        """
        Test LT characteristics.
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        # Create ticket.
        lt = yield store.mkLoginTicket(service)
        self.assertTrue(lt.startswith('LT-'))
        yield self.assertEqual(len(lt), ticket_size)
        
    @defer.inlineCallbacks
    def test_LT_validation(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        # Create ticket.
        lt = yield store.mkLoginTicket(service)
        # Use ticket.
        yield store.useLoginTicket(lt, service)
        
    @defer.inlineCallbacks
    def test_LT_invalid_spec(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        # Create ticket.
        lt = "Not a valid ticket"
        # Use ticket.
        yield self.assertFailure(store.useLoginTicket(lt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_LT_invalid_ticket(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        # Create ticket.
        lt = "LT-" + ('X'*max(ticket_size-3, 1))
        # Use ticket.
        yield self.assertFailure(store.useLoginTicket(lt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_LT_expired_ticket(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        # A ticket that expired over time should also fail.
        lt = yield store.mkLoginTicket(service)
        self.clock.advance(store.lt_lifespan)
        yield self.assertFailure(store.useLoginTicket(lt, service), txcas.exceptions.InvalidTicket)

    @defer.inlineCallbacks
    def test_ST_spec(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(service, tgt, False)
        yield self.assertTrue(st.startswith('ST-'))
        yield self.assertEqual(len(st), ticket_size)
        
    @defer.inlineCallbacks
    def _ST_validate(self, validate_func):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create ST
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(service, tgt, False)
        
        result = yield validate_func(st, service)
        stored_service = result['service']
        stored_avatar_id = result['avatar_id']
        stored_tgt = result['tgt']
        self.assertTrue('primary_credentials' in result, 
                "ST result should have `primary_credentials` flag.")
        yield self.assertEqual(stored_service, service, 
            "Should return the service associated with the ticket during creation")
        yield self.assertEqual(stored_avatar_id, avatar_id, 
            "Should return the avatar_id associated with the ticket during creation")
        yield self.assertEqual(stored_tgt, tgt, 
            "Should return the tgt associated with the ticket during creation")
        
    @defer.inlineCallbacks
    def test_ST_serviceValidate(self):
        """
        """
        yield self._ST_validate(self.store.useServiceTicket)
        
    @defer.inlineCallbacks
    def test_ST_proxyValidate(self):
        """
        """
        yield self._ST_validate(self.store.useServiceOrProxyTicket)
        
 
        
    @defer.inlineCallbacks
    def _ST_reuse(self, validate_func):
        """
        """
        store = self.store
        service = self.service
        
        # Create ST
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(service, tgt, False)
        # Use
        yield validate_func(st, service)
        # Reuse
        yield self.assertFailure(validate_func(st, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_ST_reuse_serviceValidate(self):
        """
        """
        yield self._ST_reuse(self.store.useServiceTicket)
        
    @defer.inlineCallbacks
    def test_ST_reuse_proxyValidate(self):
        """
        """
        yield self._ST_reuse(self.store.useServiceOrProxyTicket)

    @defer.inlineCallbacks
    def _ST_expire(self, validate_func):
        """
        """
        store = self.store
        service = self.service
        
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(service, tgt, False)
        self.clock.advance(store.st_lifespan)
        yield self.assertFailure(validate_func(st, service), txcas.exceptions.InvalidTicket)

    @defer.inlineCallbacks
    def test_ST_expire_serviceValidate(self):
        """
        """
        yield self._ST_expire(self.store.useServiceTicket)
        
    @defer.inlineCallbacks
    def test_ST_expire_proxyValidate(self):
        """
        """
        yield self._ST_expire(self.store.useServiceOrProxyTicket)
        
    @defer.inlineCallbacks
    def _ST_bad_service(self, validate_func):
        """
        """
        store = self.store
        service = self.service
        
        tgt = yield self.makeTicketGrantingCookie()
        st = yield store.mkServiceTicket(service, tgt, False)
        bad_service = service + '/badservice'
        yield self.assertFailure(validate_func(st, bad_service), txcas.exceptions.InvalidService)
        
    @defer.inlineCallbacks
    def test_ST_bad_service_serviceValidate(self):
        yield self._ST_bad_service(self.store.useServiceTicket)
        
    @defer.inlineCallbacks
    def test_ST_bad_service_proxyValidate(self):
        yield self._ST_bad_service(self.store.useServiceOrProxyTicket)
        
    @defer.inlineCallbacks
    def test_PT_spec(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        yield self.assertTrue(pt.startswith('PT-'))
        yield self.assertEqual(len(pt), ticket_size)
        
    @defer.inlineCallbacks
    def test_PT_serviceValidate(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        yield self.assertFailure(store.useServiceTicket(pt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_PT_proxyValidate(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        result = yield store.useServiceOrProxyTicket(pt, service)
        stored_service = result['service']
        stored_avatar_id = result['avatar_id']
        stored_tgt = result['tgt']
        stored_pgt = result['pgt']
        stored_pgturl = result['pgturl']
        stored_proxy_chain = result['proxy_chain']
        yield self.assertTrue('primary_credentials' in result, 
                "ST result should have `primary_credentials` flag.")
        yield self.assertEqual(stored_service, service, 
            "Should return the service associated with the ticket during creation")
        yield self.assertEqual(stored_avatar_id, avatar_id, 
            "Should return the avatar_id associated with the ticket during creation")
        yield self.assertEqual(stored_tgt, tgt, 
            "Should return the tgt associated with the ticket during creation")
        yield self.assertEqual(stored_pgt, pgt, 
            "Should return the pgt associated with the ticket during creation")
        proxy_chain = [self.pgturl]
        yield self.assertEqual(
                stored_proxy_chain, 
                proxy_chain, 
                "Stored proxy chain '%s' != '%s'" % (str(stored_proxy_chain), str(proxy_chain)))
        
    @defer.inlineCallbacks
    def test_PT_bad_spec(self):
        """
        """
        store = self.store
        service = self.service
        
        pt = 'XY-badticket'
        yield self.assertFailure(store.useServiceOrProxyTicket(pt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_PT_reuse(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        yield store.useServiceOrProxyTicket(pt, service)
        yield self.assertFailure(store.useServiceOrProxyTicket(pt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_PT_invalid(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        
        pt = 'PT-' + 'x' * (max(1, ticket_size-3))
        yield self.assertFailure(store.useServiceOrProxyTicket(pt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_PT_expire(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        self.clock.advance(store.pt_lifespan)
        yield self.assertFailure(store.useServiceOrProxyTicket(pt, service), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_PT_bad_service(self):
        """
        """
        store = self.store
        ticket_size = self.ticket_size
        service = self.service
        avatar_id = self.avatar_id
        
        # Create PT
        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()
        pt = yield store.mkProxyTicket(service, pgt)
        bad_service = service + '/badservice'
        yield self.assertFailure(store.useServiceOrProxyTicket(pt, bad_service), txcas.exceptions.InvalidService)
        
    @defer.inlineCallbacks
    def test_PGT_spec(self):
        store = self.store
        ticket_size = self.ticket_size
        service = self.service

        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()

        yield self.assertTrue(pgt.startswith('PGT-'))
        yield self.assertEqual(len(pgt), ticket_size)
        
    @defer.inlineCallbacks
    def test_PGT_expire(self):
        store = self.store
        service = self.service

        tgt, st, pgt, iou = yield self.makeProxyGrantingTicket()

        # Should not be able to use PGT after it has expired.
        self.clock.advance(store.pgt_lifespan)
        yield self.assertFailure(store.mkProxyTicket(service, pgt), txcas.exceptions.InvalidTicket)
        
    @defer.inlineCallbacks
    def test_TGT_spec(self):
        store = self.store
        ticket_size = self.ticket_size
        service = self.service

        tgt = yield self.makeTicketGrantingCookie()
        yield self.assertTrue(tgt.startswith('TGC-'))
        yield self.assertEqual(len(tgt), ticket_size)

    @defer.inlineCallbacks
    def test_TGT_expire(self):
        store = self.store
        ticket_size = self.ticket_size
        service = self.service

        tgt = yield self.makeTicketGrantingCookie()
        yield self.assertTrue(tgt.startswith('TGC-'))
        yield self.assertEqual(len(tgt), ticket_size)

        # Should not be able to use TGT after it has expired.
        self.clock.advance(store.tgt_lifespan)
        yield self.assertFailure(store.mkServiceTicket(service, tgt, False), txcas.exceptions.InvalidTicket)


class InMemoryTicketStoreTest(TicketStoreTester, TestCase):
    """
    """
        
    def getStore(self, clock):
        store = InMemoryTicketStore(reactor=clock, verify_cert=False)
        return store
    
class CouchDBTicketStoreTest(TicketStoreTester, TestCase):
    """
    """
    def __init__(self, *args, **kwds):
        super(CouchDBTicketStoreTest, self).__init__(*args, **kwds)

        # Should these tests be run?
        defaults = {'TESTS': {'couchdb_ticket_store': 0}}
        scp = load_config(defaults=defaults)
        couchdb_ticket_store = scp.getboolean('TESTS', 'couchdb_ticket_store')
        if not couchdb_ticket_store:
            self.__class__.skip = "Not configured to run CouchDB ticket store tests."
            return
        try:
            if scp.has_section('CouchDB'):
                self.couch_host = scp.get('CouchDB', 'host')
                self.couch_port = scp.getint('CouchDB', 'port')
                self.couch_db = scp.get('CouchDB', 'db')
                self.couch_user = scp.get('CouchDB', 'user')
                self.couch_passwd = scp.get('CouchDB', 'passwd')
                self.use_https = scp.getboolean('CouchDB', 'https')
                self.verify_cert = scp.getboolean('CouchDB', 'verify_cert')
        except ConfigParser.Error as ex:
            self.skip = "Could not read CouchDB settings: %s" % str(ex)
            return
        
        # No way to run the real-time tests.
        methods = [
            'test_LT_expired_ticket',
            'test_PGT_expire',
            'test_PT_expire',
            'test_ST_expire_proxyValidate',
            'test_ST_expire_serviceValidate',
            'test_TGT_expire',
        ]
        for method_name in methods:
            fn = getattr(self.__class__, method_name)
            fn.__func__.skip = "Only real-time expirations work with this ticket store."
        
    def getStore(self, clock):
        store = CouchDBTicketStore(
                    self.couch_host, 
                    self.couch_port, 
                    self.couch_db,
                    self.couch_user, 
                    self.couch_passwd, 
                    self.use_https,
                    reactor=clock, 
                    verify_cert=self.verify_cert)
        return store


#class ServerAppTest(TestCase):
#
#
#    def test_init(self):
#        """
#        It should accept a UserStore on init
#        """
#        checker = InMemoryUsernamePasswordDatabaseDontUse()
#        realm = UserRealm()
#
#        app = ServerApp(None, realm, [checker], 'services')
#        self.assertEqual(app.ticket_store, None)
#        self.assertEqual(app.portal.realm, realm)
#        self.assertIn(checker, app.portal.checkers.values())
#        self.assertEqual(app.validService, 'services')
#
#

#class FunctionalTest(TestCase):
#
#    timeout = 3
#
#
#    def setUp(self):
#        checker = InMemoryUsernamePasswordDatabaseDontUse(foo='something')
#        realm = UserRealm()
#        self.clock = task.Clock()
#        app = ServerApp(InMemoryTicketStore(reactor=self.clock), realm,
#                        [checker], lambda x: True)
#        self.app = app
#        self.resource = app.app.resource()
#
#
#    def getInputs(self, text):
#        """
#        Get a dictionary of inputs and their values from a blob of html
#        """
#        parsed = parseString(text)
#        forms = parsed.getElementsByTagName('form')
#        form = forms[0]
#        inputs = form.getElementsByTagName('input')
#        ret = {}
#        for i in inputs:
#            ret[i.getAttribute('name')] = {
#                'value': i.getAttribute('value'),
#            }
#        return ret
#
#
#    @defer.inlineCallbacks
#    def test_basicSuccess(self):
#        """
#        You can log in and verify tickets
#        """
#        app = self.app
#
#        # GET /login
#        request = FakeRequest(args={
#            'service': ['http://www.example.com'],
#        })
#
#        body = yield self.app.login_GET(request)
#
#        parsed = parseString(body)
#        forms = parsed.getElementsByTagName('form')
#        self.assertEqual(len(forms), 1, "There should only be one form")
#        form = forms[0]
#        inputs = form.getElementsByTagName('input')
#        inputs = [(x.getAttribute('name'), x.getAttribute('value'), x.getAttribute('type')) for x in inputs]
#
#        lt_input = [x for x in inputs if x[0] == 'lt'][0]
#        lt_value = lt_input[1]
#        self.assertTrue(lt_value.startswith('LT-'), repr(lt_value))
#        self.assertIn(('username', '', 'text'), inputs)
#        self.assertIn(('password', '', 'password'), inputs)
#        self.assertIn(('lt', lt_value, 'hidden'), inputs)
#        self.assertIn(('service', 'http://www.example.com', 'hidden'), inputs)
#
#        # POST /login
#        request = FakeRequest(args={
#            'username': ['foo'],
#            'password': ['something'],
#            'lt': [lt_value],
#            'service': ['http://www.example.com'],
#        })
#
#        body = yield self.app.login_POST(request)
#        redirect_url = request.redirected
#        self.assertTrue(redirect_url.startswith('http://www.example.com'),
#                        redirect_url)
#        parsed = urlparse(redirect_url)
#        qs = parse_qs(parsed.query)
#        ticket = qs['ticket'][0]
#        self.assertTrue(ticket.startswith('ST-'))
#        self.assertEqual(len(ticket), 256)
#
#        # GET /validate
#        request = FakeRequest(args={
#            'service': ['http://www.example.com'],
#            'ticket': [ticket],
#        })
#
#        body = yield self.app.validate_GET(request)
#        self.assertEqual(body, 'yes\nfoo\n')
#
#
#    @defer.inlineCallbacks
#    def test_login_badpassword(self):
#        """
#        The user's password has to match
#        """
#        app = self.app
#
#        # GET
#        request = FakeRequest(args={
#            'service': ['http://www.example.com'],
#        })
#
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#
#        # POST with wrong password
#        request = FakeRequest(args={
#            'username': ['foo'],
#            'password': ['bad password'],
#            'lt': [inputs['lt']['value']],
#            'service': [inputs['service']['value']],
#        })
#        body = yield self.app.login_POST(request)
#
#        self.assertEqual(request.responseCode, 403, "Should be forbidden")
#        redirect_url = request.redirected
#        self.assertTrue(redirect_url.startswith('/login?'))
#        parsed = urlparse(redirect_url)
#        qs = parse_qs(parsed.query)
#        self.assertEqual(qs['service'][0], 'http://www.example.com',
#                         "Should redirect for the same service")
#
#
#    @defer.inlineCallbacks
#    def test_login_badservice(self):
#        """
#        If the service provided in POST doesn't match that in GET, then fail.
#        """
#        app = self.app
#        request = FakeRequest(args={
#            'service': ['foo'],
#        })
#
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#
#        # POST with wrong service
#        request = FakeRequest(args={
#            'username': ['foo'],
#            'password': ['something'],
#            'lt': [inputs['lt']['value']],
#            'service': ['different service'],
#        })
#        body = yield self.app.login_POST(request)
#
#        self.assertEqual(request.responseCode, 403)
#
#
#    @defer.inlineCallbacks
#    def test_validate_badservice(self):
#        """
#        If the service provided to /validate doesn't match the service provided
#        to /login then fail the validation.
#        """
#        app = self.app
#        request = FakeRequest(args={
#            'service': ['foo'],
#        })
#
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#
#        # POST
#        request = FakeRequest(args={
#            'username': ['foo'],
#            'password': ['something'],
#            'lt': [inputs['lt']['value']],
#            'service': ['foo'],
#        })
#        body = yield self.app.login_POST(request)
#        redirect_url = request.redirected
#        parsed = urlparse(redirect_url)
#        qs = parse_qs(parsed.query)
#        ticket = qs['ticket'][0]
#        
#        # GET /validate with wrong service
#        request = FakeRequest(args={
#            'ticket': [ticket],
#            'service': ['different'],
#        })
#
#        body = yield self.app.validate_GET(request)
#        self.assertEqual(request.responseCode, 403)
#        self.assertEqual(body, 'no\n\n')
#
#
#    @defer.inlineCallbacks
#    def test_invalidServices(self):
#        """
#        If the service doesn't match the validService function, fail all
#        service-related requests
#        """
#        app = self.app
#        app.ticket_store.valid_service = lambda x: False
#
#        request = FakeRequest(args={
#            'service': ['foo'],
#        })
#
#        body = yield self.app.login_GET(request)
#        self.assertEqual(request.responseCode, 400)
#
#
#    @defer.inlineCallbacks
#    def test_ticket_granting_cookie_success(self):
#        """
#        After authenticating once, a client should be able to reuse a
#        ticket-granting cookie to authenticate again without having to put
#        in credentials.
#        """
#        app = self.app
#
#        # GET /login
#        request = FakeRequest(args={
#            'service': ['foo'],
#        })
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#
#        # POST /login
#        request = FakeRequest(method='POST', path='/cas/login', args={
#            'username': ['foo'],
#            'password': ['something'],
#            'lt': [inputs['lt']['value']],
#            'service': ['foo'],
#        })
#        body = yield self.app.login_POST(request)
#        self.assertTrue(len(request.cookies) >= 1, "Should have at least one"
#                        " cookie")
#        cookie = request.cookies[0]
#        parts = cookie.split('; ')
#        self.assertIn('Secure', parts)
#        self.assertIn('HttpOnly', parts)
#        self.assertIn('Path=/cas/', parts)
#        name, value = parts[0].split('=', 1)
#        self.assertEqual(name, self.app.cookie_name)
#        self.assertTrue(value.startswith('TGC-'))
#        
#        # GET /login again with the cookie for a different service
#        parts.remove('Secure')
#        parts.remove('HttpOnly')
#        request = FakeRequest(args={
#            'service': ['somewhere'],
#        }, headers={
#            'Cookie': ['; '.join(parts)],
#        })
#        body = yield self.app.login_GET(request)
#        redirect_url = request.redirected
#        self.assertTrue(redirect_url.startswith('somewhere'), redirect_url)
#        parsed = urlparse(redirect_url)
#        qs = parse_qs(parsed.query)
#        ticket = qs['ticket'][0]
#
#        self.assertEqual(len(request.cookies), 0, "Should not set the cookie "
#                         "again")
#
#        # GET /validate
#        request = FakeRequest(args={
#            'service': ['somewhere'],
#            'ticket': [ticket],
#        })
#
#        body = yield self.app.validate_GET(request)
#        self.assertEqual(body, 'yes\nfoo\n')
#
#
#    @defer.inlineCallbacks
#    def test_logout(self):
#        """
#        You can log out (which will invalidate the ticket granting cookie)
#        """
#        app = self.app
#
#        # GET /login
#        request = FakeRequest(args={
#            'service': ['foo'],
#        })
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#
#        # POST /login
#        request = FakeRequest(method='POST', path='/cas/login', args={
#            'username': ['foo'],
#            'password': ['something'],
#            'lt': [inputs['lt']['value']],
#            'service': ['foo'],
#        })
#        body = yield self.app.login_POST(request)
#        self.assertTrue(len(request.cookies) >= 1, "Should have at least one"
#                        " cookie")
#        cookie = request.cookies[0]
#
#        # GET /logout
#        request = FakeRequest(headers={
#            'Cookie': [cookie],
#        })
#        body = yield self.app.logout_GET(request)
#
#        # GET /login again with the cookie
#        request = FakeRequest(args={
#            'service': ['somewhere'],
#        }, headers={
#            'Cookie': [cookie],
#        })
#        body = yield self.app.login_GET(request)
#        inputs = self.getInputs(body)
#        self.assertIn('lt', inputs)
#
#
