
from __future__ import print_function
from functools import partial
import glob
from OpenSSL import crypto, SSL
import pem
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet.interfaces import (
    IListeningPort,
    IStreamServerEndpointStringParser,
    IStreamServerEndpoint)
from twisted.internet import ssl
from twisted.internet.defer import maybeDeferred
from twisted.internet.task import LoopingCall
from twisted.plugin import IPlugin
from twisted.python.filepath import FilePath
from twisted.python import log
from zope.interface import implements

def parseInt_(value, exceptionFactory=None):
    try:
        return int(value)
    except (TypeError, ValueError) as ex:
        if failMsg is not None:
            raise exceptionFactory()
        else:
            raise

def pem_cert_to_x509(pem_cert):
    return crypto.load_certificate(crypto.FILETYPE_PEM, str(pem_cert))

def createSSLContext_(**kwargs):
    privateKey = kwargs.get('privateKey', None)
    assert privateKey is not None, '`tls:` endpoint requires `privateKey` option.'
    certKey = kwargs.get('certKey', privateKey)
    extraCertChain = kwargs.get('extraCertChain', None)
    sslmethod = kwargs.get('sslmethod', None)
    dhParameters = kwargs.get('dhParameters', None)
    authorities_file = kwargs.get('authorities', None)
    if authorities_file is not None:
        verify_client = True
    else:
        verify_client = False
    pem_files = [privateKey, certKey]
    if extraCertChain is not None:
        pem_files.append(extraCertChain)
    kwds = {'method': SSL.SSLv23_METHOD}
    if verify_client:
        authorities = [pem_cert_to_x509(cert)
            for cert in pem.parse_file(authorities_file)]
        kwds['caCerts'] = authorities
        kwds['verify'] = verify_client
    if dhParameters is not None:
        kwds['dhParameters'] = pem.DiffieHellmanParameters.fromFile(dhParameters)
    ctxFactory = pem.certificateOptionsFromFiles(
        *pem_files,
        **kwds) 
    ssl_context = ctxFactory.getContext()
    ssl_context.set_options(SSL.OP_NO_SSLv2)
    if sslmethod is not None:
        ssl_method_options = sslmethod.split('+')
        for ssl_opt in ssl_method_options:
            ssl_context.set_options(ssl_opt)
    return (verify_client, ctxFactory)


class SSL4ServerEndpointWrapper(object):
    implements(IStreamServerEndpoint)
    checkRevokeInterval = 60

    def __init__(self, reactor, kwds, revoke_file=None):
        self.wrapped_ = SSL4ServerEndpoint(reactor, **kwds)
        self.revoke_file = revoke_file
        self.revoke_state = {
            'revoked': set([]),
            'last_mod_time': None,}
        if revoke_file is not None:
            self.loop_call = LoopingCall(self.load_revokations)
            self.loop_call.start(self.checkRevokeInterval)
        ctx = kwds['sslContextFactory']
        ssl_context = ctx.getContext()
        ssl_context.set_verify(SSL.VERIFY_PEER, self.ssl_callback)

    def ssl_callback(self, conn, x509, errno, errdepth, ok):
        revoke_state = self.revoke_state
        try:
            revoked = revoke_state['revoked']
            subject = tuple(x509.get_subject().get_components())
            issuer = tuple(x509.get_issuer().get_components())
            if (subject, issuer) in revoked:
                return False
            return ok
        except:
            return False

    def load_revokations(self):
        """
        Load PEM formatted certificates that are no longer trustworthy
        and store the suject and issuer.
        `cert_list` is the path to a file that contains glob-like patterns
        to PEM-formatted certificates.
        """
        revoke_file = self.revoke_file
        revoke_state = self.revoke_state 
        if revoke_file is not None:
            last_mod_time = revoke_state['last_mod_time']
            fp = FilePath(revoke_file)
            if not fp.exists():
                return
            mod_time = fp.getModificationTime()
            if last_mod_time is None or mod_time > last_mod_time:
                log.msg("[INFO] Loading revoked certificate files specified in '{0}'.".format(
                    revoke_file))
                revoke_state['last_mod_time'] = mod_time
                revoked = set([])
                with open(revoke_file) as f:
                    for line in f:
                        pattern = line.rstrip('\r\n')
                        if pattern == '' or pattern.startswith('#'):
                            continue
                        for path in glob.glob(pattern):
                            certs = [pem_cert_to_x509(cert)
                                for cert in pem.parse_file(path)]
                            for certificate in certs:
                                revoked.add((
                                    tuple(certificate.get_subject().get_components()),
                                    tuple(certificate.get_issuer().get_components())))
                revoke_state['revoked'] = revoked

    def listen(self, protocolFactory):
        d = self.wrapped_.listen(protocolFactory)
        d.addCallback(self.wrapListeningPort_)
        return d

    def wrapListeningPort_(self, listeningPort):
        return SSL4ServerListeningPortWrapper(listeningPort)

class SSL4ServerListeningPortWrapper(object):
    implements(IListeningPort)

    def __init__(self, wrapped):
        self.wrapped_ = wrapped

    def startListening(self):
        return self.wrapped_.startListening()

    def stopListening(self):
        d = maybeDeferred(self.wrapped_.stopListening)
        return d

    def getHost(self):
        return self.wrapped_.getHost()


class TLSServerEndpointParser(object):
    """
    Like endpoint string 'ssl:' for servers.

    `sslmethod` accepts multiple SSL method options joined by '+'.
    `authorities` is a file containing one or more CA certs used to verify
      client certificates.
    """
    implements(IPlugin, IStreamServerEndpointStringParser)
    
    prefix = 'tls'

    def parseStreamServer(self, reactor, *args, **kwargs):
        # port, interface, backlog
        # certKey, privateKey, extraCertChain, sslmethod, dhParameters
        passthru = lambda x: x
        xlate = {
            'port': partial(parseInt_, exceptionFactory=lambda: Exception(
                "`port` must be an integer.")),
            'backlog': partial(parseInt_, exceptionFactory=lambda: Exception(
                "`backlog` must be an integer.")),
            'interface': passthru,
        }
        kwds = {}
        for key, value in kwargs.items():
            xlator = xlate.get(key, None)
            if xlator is not None:
                kwds[key] = xlator(value)
        verify_client, ctx = createSSLContext_(**kwargs)
        kwds['sslContextFactory'] = ctx 
        assert 'port' in kwds, "`tls:` endpoint requires `port`."
        if verify_client:
            revoke_file = kwargs.get('revokeFile', None)
            return SSL4ServerEndpointWrapper(reactor, kwds, revoke_file)
        else:
            return SSL4ServerEndpoint(reactor, **kwds)
        
