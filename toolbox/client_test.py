#!/usr/bin/env python
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.internet import ssl, task, protocol, endpoints, defer, reactor
from twisted.python.modules import getModule

from twisted.web.client import getPage
from twisted.web.http_headers import Headers

@defer.inlineCallbacks
def main(reactor):
    certData = getModule(__name__).filePath.sibling('public.pem').getContent()
    authData = getModule(__name__).filePath.sibling('combined.pem').getContent()
    clientCertificate = ssl.PrivateCertificate.loadPEM(authData)
    authority = ssl.Certificate.loadPEM(certData)

    options = ssl.optionsForClientTLS(u'kepler', authority, clientCertificate)
    #endpoint = endpoints.SSL4ClientEndpoint(reactor, 'localhost', 9800,
    #                                        options)
    s = yield getPage("https://localhost:9800/login", contextFactory=options)
    print s

if __name__ == '__main__':
    task.react(main)

#if __name__ == '__main__':
#    import ssl_clientauth_client
#    task.react(ssl_clientauth_client.main)
