#! /usr/bin/env python

from txcas.interface import IRealmFactory, IServiceManagerFactory, ITicketStoreFactory 

from twisted.plugin import getPlugins
from twisted.cred.strcred import ICheckerFactory


print "== ITicketStore test =="
for n, thing in enumerate(getPlugins(ITicketStoreFactory)):
    print "%02d %s" % (n, thing)
    print thing.tag
    print

print "== IRealmFactory test =="
for n, thing in enumerate(getPlugins(IRealmFactory)):
    print "%02d %s" % (n, thing)
    print thing.tag
    print

print "== ICredentialsChecker test =="
for n, thing in enumerate(getPlugins(ICheckerFactory)):
    print "%02d %s" % (n, thing)
    print thing.authType
    print

print "== IServiceManagerFactory test =="
for n, thing in enumerate(getPlugins(IServiceManagerFactory)):
    print "%02d %s" % (n, thing)
    print thing.tag
    print

print
