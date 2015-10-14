
#=======================================================================
# A custom IPolicyForHTTPS that allows *adding* extra CAs to the OS
# supplied CA bundle.
# Use this as the `contextFactory` for `twisted.web.client.Agent`.
#=======================================================================

# External modules
from OpenSSL import crypto
import pem
from twisted.internet import ssl, defer 
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.components import proxyForInterface
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer


class AddExtraTrustRoots(proxyForInterface(IOpenSSLClientConnectionCreator)):
    def __init__(self, extraTrustRoots, original):
        self._extraTrustRoots = extraTrustRoots
        super(AddExtraTrustRoots, self).__init__(original)


    def clientConnectionForTLS(self, tlsProtocol):
        connection = (super(AddExtraTrustRoots, self).clientConnectionForTLS(tlsProtocol))
        cert_store = connection.get_context().get_cert_store()
        for cert in self._extraTrustRoots:
            cert_store.add_cert(cert)
        return connection
 
@implementer(IPolicyForHTTPS)
class CustomPolicyForHTTPS(object):
    """
    SSL connection creator for web clients.
    """
    def __init__(self, extraTrustRoots=None):
        if extraTrustRoots is None:
            extraTrustRoots = []
        self._extraTrustRoots = extraTrustRoots

    def creatorForNetloc(self, hostname, port):
        return AddExtraTrustRoots(
            self._extraTrustRoots, 
            ssl.optionsForClientTLS(hostname.decode("ascii")))


def pem_cert_to_x509(pem_cert):
    return crypto.load_certificate(crypto.FILETYPE_PEM, str(pem_cert))

def createCustomPolicyFactoryFromPEMs(*pem_files):
    authorities = []
    for pem_file in pem_files:
        for cert in pem.parse_file(pem_file):
            authorities.append(pem_cert_to_x509(cert))
    
    def _policyFactory():
        return CustomPolicyForHTTPS(authorities)

    return _policyFactory
