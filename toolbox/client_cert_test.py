#!/usr/bin/env python
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

# Standard library
import sys

# External modules
from twisted.internet import ssl, task, defer 
from twisted.python.modules import getModule
from twisted.web.client import getPage

@defer.inlineCallbacks
def main(reactor, netloc):
    caCertData = getModule(__name__).filePath.sibling('authority.cert.pem').getContent()
    clientData = getModule(__name__).filePath.sibling('client.pem').getContent()
    clientCertificate = ssl.PrivateCertificate.loadPEM(clientData)
    authority = ssl.Certificate.loadPEM(caCertData)

    options = ssl.optionsForClientTLS(u'kepler', authority, clientCertificate)
    s = yield getPage("https://%s/login" % netloc, contextFactory=options)
    print s

def usage():
    sys.stderr.write("Usage: %s [NETLOC]>\n" % sys.argv[0])

if __name__ == '__main__':
    argv = sys.argv[1:]
    if len(argv) == 0:
        netloc = "localhost:9800"
    elif len(argv) == 1:
        netloc = argv[0]
    else:
        usage()
        sys.exit(1)
    task.react(main, [netloc])

