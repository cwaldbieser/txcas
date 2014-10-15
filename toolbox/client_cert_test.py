#! /usr/bin/env python

# Standard library
import argparse
import sys

# External modules
from OpenSSL import SSL
from twisted.internet import ssl, task, defer 
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.components import proxyForInterface
from twisted.python.modules import getModule
from twisted.web.client import getPage

class CustomClientConnectionCreator(proxyForInterface(IOpenSSLClientConnectionCreator)):
    def __init__(self, ssl_opts, original):
        self._ssl_opts = ssl_opts
        super(CustomClientConnectionCreator, self).__init__(original)

    def clientConnectionForTLS(self, tlsProtocol):
        connection = (super(CustomClientConnectionCreator, self).clientConnectionForTLS(tlsProtocol))
        ssl_ctx = connection.get_context()
        ssl_ctx.set_options(self._ssl_opts)
        return connection


@defer.inlineCallbacks
def main(reactor, args):
    kwds = {}
    caCertData = args.ca_cert.read()
    client_cert = args.client_cert
    if client_cert is not None:
        clientData = args.client_cert.read()
        clientCertificate = ssl.PrivateCertificate.loadPEM(clientData)
        kwds['clientCertificate'] = clientCertificate 
    authority = ssl.Certificate.loadPEM(caCertData)

    host = args.host
    port = args.port
    netloc = "%s:%d" % (host, port)
    ssl_opts = SSL.OP_NO_SSLv2
    if not args.sslv3:
        ssl_opts |= SSL.OP_NO_SSLv3
    if args.no_tlsv1:
        ssl_opts |= SSL.OP_NO_TLSv1
    if args.no_tlsv1_1:
        ssl_opts |= SSL.OP_NO_TLSv1_1
    if args.no_tlsv1_2:
        ssl_opts |= SSL.OP_NO_TLSv1_2
    extraCertificateOptions = {'method': SSL.SSLv23_METHOD}
    kwds['extraCertificateOptions'] = extraCertificateOptions
    options = ssl.optionsForClientTLS( unicode(host), authority, **kwds)
    options = CustomClientConnectionCreator(ssl_opts, options) 
    s = yield getPage("https://%s/login" % netloc, contextFactory=options)
    print s

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Present Client Certificates to Server")

    parser.add_argument(
        'ca_cert',
        action='store',
        type=argparse.FileType('rb'),
        help='Use PEM formatted CA_CERT when checking *server* certificate signature.')
    parser.add_argument(
        '--client-cert',
        action='store',
        type=argparse.FileType('rb'),
        help='Use PEM formatted client certificate+private key.  Cert will be presented to server during SSL handshake.')
    parser.add_argument(
        '--host',
        action='store',
        default='localhost',
        help='Connect to HOST')
    parser.add_argument(
        '--port',
        action='store',
        type=int,
        default=443,
        help='Connect to PORT')
    parser.add_argument(
        '--resource',
        action='store',
        default='/login',
        help='Request RESOURCE.')
    parser.add_argument(
        '--sslv3',
        action='store_true',
        help='Allow SSLv3 (not recommended).')
    parser.add_argument(
        '--no-tlsv1',
        action='store_true',
        help='Disallow TLSv1.')
    parser.add_argument(
        '--no-tlsv1_1',
        action='store_true',
        help='Disallow TLSv1.1.')
    parser.add_argument(
        '--no-tlsv1_2',
        action='store_true',
        help='Disallow TLSv1.2.')

    args = parser.parse_args()

    task.react(main, [args])

