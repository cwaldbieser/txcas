#! /usr/bin/env python

from txcas.interface import ITicketStore 

from twisted.plugin import getPlugins
from twisted.cred.portal import IRealm
from twisted.cred.checkers import ICredentialsChecker


print "== ITicketStore test =="
for n, thing in enumerate(getPlugins(ITicketStore)):
    print "%02d %s" % (n, thing)
    print

print "== IRealm test =="
for n, thing in enumerate(getPlugins(IRealm)):
    print "%02d %s" % (n, thing)
    print

print "== ICredentialsChecker test =="
for n, thing in enumerate(getPlugins(ICredentialsChecker)):
    print "%02d %s" % (n, thing)
    print
