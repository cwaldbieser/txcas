#! /usr/bin/env python

from txcas.interface import IRealmFactory, ITicketStore 

from twisted.plugin import getPlugins
from twisted.cred.strcred import ICheckerFactory


print "== ITicketStore test =="
for n, thing in enumerate(getPlugins(ITicketStore)):
    print "%02d %s" % (n, thing)
    print thing.__class__.__name__
    print

print "== IRealmFactory test =="
for n, thing in enumerate(getPlugins(IRealmFactory)):
    print "%02d %s" % (n, thing)
    print thing.__class__.__name__
    print

print "== ICredentialsChecker test =="
for n, thing in enumerate(getPlugins(ICheckerFactory)):
    print "%02d %s" % (n, thing)
    print thing.__class__.__name__
    print
