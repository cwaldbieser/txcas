
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
from txcas.casuser import User
from txcas.client_cert_checker import ClientCertificateChecker
from txcas.constants import (
    VIEW_LOGIN,
    VIEW_LOGIN_SUCCESS,
    VIEW_LOGOUT,
    VIEW_INVALID_SERVICE,
    VIEW_ERROR_5XX,
    VIEW_NOT_FOUND)
from txcas.couchdb_ticket_store import CouchDBTicketStore
import txcas.exceptions
from txcas.in_memory_ticket_store import InMemoryTicketStore
from txcas.interface import ICASUser, IServiceManager
from txcas.jinja_view_provider import Jinja2ViewProvider
from txcas.server import ServerApp 
from txcas.settings import load_defaults, export_settings_to_dict
# External modules
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.cred.portal import Portal, IRealm
from twisted.internet import defer, task, reactor, utils, protocol
from twisted.internet.address import IPv4Address
from twisted.internet.interfaces import ISSLTransport
from twisted.python.failure import Failure
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase
from twisted.web import microdom
from twisted.web import server
from twisted.web.http_headers import Headers
from twisted.web.test.test_web import DummyChannel
from zope.interface import directlyProvides, implements
from zope.interface.verify import verifyObject


def load_config(defaults=None):
    scp = load_defaults(defaults)
    path = os.path.join(os.path.dirname(__file__), "tests.cfg")
    scp.read([path])
    return scp
   
class FakeSubject(object):
    def __init__(self, components):
        self.components = components
    def get_components(self):
        return self.components
 
class FakeClientCert(object):
    def __init__(self, subject):
        self.subject = subject
    def get_subject(self):
        return self.subject

class FakeTransport(object):
    """
    A fake transport.
    """

class FakeSSLTransport(FakeTransport):
    """
    A fake SSL transport.
    """
    implements(ISSLTransport)

    def __init__(self, client_cert=None):
        self._client_cert = client_cert

    def getPeerCertificate(self):
        return self._client_cert

class FakeRequest(server.Request):
    """
    A fake request object.
    """

    def __init__(self, method='GET', path='/', args=None, isSecure=False,
                 headers=None, client_ip='127.0.0.1'):
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
        self.client_ip = '127.0.0.1'
        #self.isSecure = isSecure

    def getClientIP(self):
        return self.client_ip

    def setHeader(self, key, value):
        self.responseHeaders[key].append(value)

    def setResponseCode(self, code, message=None):
        self.responseCode = code

    def redirect(self, where):
        self.redirected = where

class FakeServiceManager(object):
    implements(IServiceManager)

    def __init__(self, is_valid_service_func=None, is_sso_func=None):
        self.is_sso_func = is_sso_func or (lambda s: True)
        self.is_valid_service_func =  is_valid_service_func or (lambda s: True)

    def getMatchingService(self, service):
        """
        Return the entry for the first matching service or None.
        """
        return defer.succeed({'name': service})

    def isValidService(self, service):
        """
        Returns True if the service is valid; False otherwise.
        """
        if self.is_valid_service_func(service):
            return defer.succeed(True)
        else:
            return defer.succeed(False)

    def isSSOService(self, service):
        """
        Returns True if the service participates in SSO.
        Returns False if the service will only accept primary credentials.
        """
        if self.is_sso_func(service):
            return defer.succeed(True)
        else:
            return defer.succeed(False)

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

class Jinja2ViewProviderTest(TestCase):
    """
    """
    view_types = [VIEW_LOGIN, VIEW_LOGIN_SUCCESS, VIEW_LOGOUT, 
                VIEW_INVALID_SERVICE, VIEW_ERROR_5XX, 
                VIEW_NOT_FOUND,]
    view_args = {
        VIEW_LOGIN: ['LT-xyzzy', 'http://service.example.net/service', False, FakeRequest()],
        VIEW_LOGIN_SUCCESS: [User('jane.smith', []), FakeRequest()],
        VIEW_LOGOUT: [FakeRequest()],
        VIEW_INVALID_SERVICE: ['http://service.example.net/service', FakeRequest()],
        VIEW_ERROR_5XX: [Failure(Exception("A failure")), FakeRequest()],
        VIEW_NOT_FOUND: [FakeRequest()],
    }

    service_manager = None

    def setUp(self):
        """
        """
        path = os.path.join(os.path.dirname(__file__), 'test_jinja2_templates')
        self.view_provider = Jinja2ViewProvider(path)
        self.view_provider.service_manager = self.service_manager

    def tearDown(self):
        """
        """
        pass

    @defer.inlineCallbacks
    def test_provideView(self):
        """
        """
        view_types = self.view_types
        view_provider = self.view_provider
        for view_type in view_types:
            result = yield view_provider.provideView(view_type)
            self.assertIsNot(result, None)

    @defer.inlineCallbacks
    def _tst_view_provider(self, view_type):
        view_func = yield self.view_provider.provideView(view_type)
        args = self.view_args[view_type]
        out = yield view_func(*args)

    @defer.inlineCallbacks
    def test_login(self):
        yield self._tst_view_provider(VIEW_LOGIN)
        
    @defer.inlineCallbacks
    def test_login_success(self):
        yield self._tst_view_provider(VIEW_LOGIN_SUCCESS)

    @defer.inlineCallbacks
    def test_logout(self):
        yield self._tst_view_provider(VIEW_LOGOUT)

    @defer.inlineCallbacks
    def test_invalid_service(self):
        yield self._tst_view_provider(VIEW_INVALID_SERVICE)

    @defer.inlineCallbacks
    def test_error_5xx(self):
        yield self._tst_view_provider(VIEW_ERROR_5XX)

    @defer.inlineCallbacks
    def test_not_found(self):
        yield self._tst_view_provider(VIEW_NOT_FOUND)

class Jinja2ViewProviderWithServiceManagerTest(Jinja2ViewProviderTest):
    service_manager = FakeServiceManager()

class ServerAppTest(TestCase):

    def test_init(self):
        """
        """
        checker = InMemoryUsernamePasswordDatabaseDontUse()
        realm = BasicRealm()
        ticket_store = InMemoryTicketStore()

        app = ServerApp(ticket_store, realm, [checker], 'services')
        self.assertIs(app.ticket_store, ticket_store)
        self.assertEqual(app.cred_requestor_portal.realm, realm)
        self.assertEqual(app.cred_acceptor_portal.realm, realm)
        self.assertIn(checker, app.cred_acceptor_portal.checkers.values())
        self.assertEqual(app.validService, 'services')

class ClientCertCheckerTest(TestCase):

    def setUp(self):
        """
        """
        xform = lambda x: ''.join(list(reversed(x)))
        self.checker = ClientCertificateChecker(subject_part='CN', transform=xform)

    @defer.inlineCallbacks
    def test_no_ssl(self):
        """
        """
        transport = FakeTransport()
        checker = self.checker
        yield self.assertFailure(checker.requestAvatarId(transport), UnauthorizedLogin)

    @defer.inlineCallbacks
    def test_no_peer_cert(self):
        transport = FakeSSLTransport()
        checker = self.checker
        yield self.assertFailure(checker.requestAvatarId(transport), UnauthorizedLogin)

    
    @defer.inlineCallbacks
    def test_no_subject_match(self):
        cert = FakeClientCert(FakeSubject([('OU', 'foo'), ('O', 'baz')]))
        transport = FakeSSLTransport(cert)
        checker = self.checker
        yield self.assertFailure(checker.requestAvatarId(transport), UnauthorizedLogin)

    @defer.inlineCallbacks
    def test_success(self):
        cert = FakeClientCert(FakeSubject([('CN', 'frobnitzification'), ('OU', 'foo'), ('O', 'baz')]))
        transport = FakeSSLTransport(cert)
        checker = self.checker
        avatar_id = yield checker.requestAvatarId(transport)
        self.assertEqual(avatar_id, 'noitacifiztinborf')

class FunctionalTest(TestCase):

    timeout = 3
    service = 'http://www.example.com/service'

    def setUp(self):
        checker = InMemoryUsernamePasswordDatabaseDontUse(foo='something')
        realm = BasicRealm()
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
    def _getLoginTicket(self):
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': [self.service],
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
        self.assertIn(('service', self.service, 'hidden'), inputs)

        defer.returnValue(lt_value)

    @defer.inlineCallbacks
    def _setup_for_validation(self):
        """
        You can log in and validate tickets
        """
        lt_value = yield self._getLoginTicket()

        # POST /login
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [lt_value],
            'service': [self.service],
        })

        body = yield self.app.login_POST(request)
        redirect_url = request.redirected
        self.assertTrue(redirect_url.startswith(self.service),
                        redirect_url)
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        ticket = qs['ticket'][0]
        self.assertTrue(ticket.startswith('ST-'))
        ticket_size = self.app.ticket_store.ticket_size
        self.assertEqual(len(ticket), ticket_size)
        defer.returnValue(ticket)

    @defer.inlineCallbacks
    def test_validate(self):
        ticket = yield self._setup_for_validation()
        app = self.app
         
        # GET /validate
        request = FakeRequest(args={
            'service': [self.service],
            'ticket': [ticket],
        })

        body = yield app.validate_GET(request)
        self.assertEqual(body, 'yes\nfoo\n')

    @defer.inlineCallbacks
    def _serviceOrProxyValidate(self, validate_func):
        ticket = yield self._setup_for_validation()
        app = self.app
         
        # GET /serviceValidate
        request = FakeRequest(args={
            'service': [self.service],
            'ticket': [ticket],
        })

        body = yield validate_func(request)
        doc = microdom.parseString(body)
        elms = doc.getElementsByTagName("cas:authenticationSuccess")
        if len(elms) > 0:
            elms = doc.getElementsByTagName("cas:user")
            if len(elms) > 0:
                elm = elms[0]
                username = elm.childNodes[0].value
        self.assertEqual(username, 'foo')

    @defer.inlineCallbacks
    def test_serviceValidate(self):
        app = self.app
        yield self._serviceOrProxyValidate(app.serviceValidate_GET)
    

    @defer.inlineCallbacks
    def test_proxyValidate(self):
        app = self.app
        yield self._serviceOrProxyValidate(app.proxyValidate_GET)

    @defer.inlineCallbacks
    def test_login_badpassword(self):
        """
        The user's password has to match
        """
        app = self.app
        lt = yield self._getLoginTicket()

        # POST with wrong password
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['bad password'],
            'lt': [lt],
            'service': [self.service],
        })
        body = yield self.app.login_POST(request)

        self.assertEqual(request.responseCode, 403, "Should be forbidden")


    @defer.inlineCallbacks
    def test_login_badservice(self):
        """
        If the service provided in POST doesn't match that in GET, then fail.
        """
        app = self.app
        lt = yield self._getLoginTicket()

        # POST with wrong service
        request = FakeRequest(args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [lt],
            'service': ['different service'],
        })
        body = yield self.app.login_POST(request)
        errors = self.flushLoggedErrors(txcas.exceptions.InvalidService)
        self.assertEqual(request.responseCode, 403)


    @defer.inlineCallbacks
    def test_validate_badservice(self):
        """
        If the service provided to /validate doesn't match the service provided
        to /login then fail the validation.
        """
        app = self.app
        ticket = yield self._setup_for_validation()

        # GET /validate with wrong service
        request = FakeRequest(args={
            'ticket': [ticket],
            'service': ['different'],
        })

        body = yield self.app.validate_GET(request)
        self.assertEqual(request.responseCode, 403)
        self.assertEqual(body, 'no\n\n')

    @defer.inlineCallbacks
    def _serviceOrProxyValidate_badservice(self, validate_func):
        """
        """
        app = self.app
        ticket = yield self._setup_for_validation()

        # GET /validate with wrong service
        request = FakeRequest(args={
            'ticket': [ticket],
            'service': ['different'],
        })

        body = yield validate_func(request)
        self.assertEqual(request.responseCode, 403)
        doc = microdom.parseString(body)
        elms = doc.getElementsByTagName("cas:authenticationFailure")
        self.assertEqual(len(elms), 1)

    @defer.inlineCallbacks
    def test_serviceValidate_badservice(self):
        """
        """
        app = self.app
        yield self._serviceOrProxyValidate_badservice(self.app.serviceValidate_GET)

    @defer.inlineCallbacks
    def test_proxyValidate_badservice(self):
        """
        """
        app = self.app
        yield self._serviceOrProxyValidate_badservice(self.app.proxyValidate_GET)


    @defer.inlineCallbacks
    def test_invalidServices(self):
        """
        If the service doesn't match the validService function, fail all
        service-related requests
        """
        app = self.app
        service_manager = FakeServiceManager(is_valid_service_func=lambda s: False)
        app.validService = service_manager.isValidService
        app.ticket_store.service_manager = service_manager

        request = FakeRequest(args={
            'service': ['foo'],
        })

        body = yield self.app.login_GET(request)
        errors = self.flushLoggedErrors(txcas.exceptions.InvalidService)
        self.assertEqual(request.responseCode, 403)


    @defer.inlineCallbacks
    def _get_st_from_tgc(self, service, validate_func):
        """
        After authenticating once, a client should be able to reuse a
        ticket-granting cookie to authenticate again without having to put
        in credentials.
        """
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': [self.service],
        })
        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST /login
        request = FakeRequest(method='POST', path='/cas/login', args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': [self.service],
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
            'service': [service],
        }, headers={
            'Cookie': ['; '.join(parts)],
        })
        body = yield self.app.login_GET(request)
        redirect_url = request.redirected
        self.assertTrue(redirect_url.startswith(service), redirect_url)
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query)
        ticket = qs['ticket'][0]

        self.assertEqual(len(request.cookies), 0, "Should not set the cookie "
                         "again")

        # GET /validate
        request = FakeRequest(args={
            'service': [service],
            'ticket': [ticket],
        })

        body = yield validate_func(request)
        defer.returnValue(body)

    @defer.inlineCallbacks
    def test_tgc_st_via_validate(self):
        service = 'http://www.somewhere.net/protected'
        body = yield self._get_st_from_tgc(service, self.app.validate_GET)
        self.assertEqual(body, 'yes\nfoo\n')

    @defer.inlineCallbacks
    def _tgc_st_via_serviceOrProxyValidate(self, validate_func):
        service = 'http://www.somewhere.net/protected'
        body = yield self._get_st_from_tgc(service, validate_func)
        username = None
        doc = microdom.parseString(body)
        elms = doc.getElementsByTagName("cas:authenticationSuccess")
        if len(elms) > 0:
            elms = doc.getElementsByTagName("cas:user")
            if len(elms) > 0:
                elm = elms[0]
                username = elm.childNodes[0].value
        self.assertEqual(username, 'foo')

    @defer.inlineCallbacks
    def test_tgc_st_via_serviceValidate(self):
        yield self._tgc_st_via_serviceOrProxyValidate(self.app.serviceValidate_GET)

    @defer.inlineCallbacks
    def test_tgc_st_via_proxyValidate(self):
        yield self._tgc_st_via_serviceOrProxyValidate(self.app.proxyValidate_GET)

    @defer.inlineCallbacks
    def test_logout(self):
        """
        You can log out (which will invalidate the ticket granting cookie)
        """
        app = self.app

        # GET /login
        request = FakeRequest(args={
            'service': [self.service],
        })
        body = yield self.app.login_GET(request)
        inputs = self.getInputs(body)

        # POST /login
        request = FakeRequest(method='POST', path='/cas/login', args={
            'username': ['foo'],
            'password': ['something'],
            'lt': [inputs['lt']['value']],
            'service': [self.service],
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


