#! /usr/bin/env python

# Standard library
import argparse
import sys

# External modules
from OpenSSL import SSL
from twisted.internet import ssl, task, defer 
from twisted.python.modules import getModule
from twisted.web.client import getPage

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
    extra_cert_opts = {}
    if args.ssl_method:
        m = getattr(SSL, '%s_METHOD' % args.ssl_method)
        extra_cert_opts['method'] = m
        kwds['extraCertificateOptions'] = extra_cert_opts 
    options = ssl.optionsForClientTLS( unicode(host), authority, **kwds)
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
        '--ssl-method',
        action='store',
        choices=['SSLv23', 'SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2'],
        help='SSL method.')

    args = parser.parse_args()

    task.react(main, [args])

