#! /usr/bin/env python

from txcas.interface import (
    IRealmFactory, 
    IServiceManagerFactory, 
    ITicketStoreFactory, 
    IViewProviderFactory)
from twisted.internet.interfaces import IStreamServerEndpointStringParser

from twisted.plugin import getPlugins
from twisted.cred.strcred import ICheckerFactory


print "== ITicketStore test =="
for n, thing in enumerate(getPlugins(ITicketStoreFactory)):
    print("%02d %s" % (n, thing))
    print(thing.tag)
    print("")

print "== IRealmFactory test =="
for n, thing in enumerate(getPlugins(IRealmFactory)):
    print("%02d %s" % (n, thing))
    print(thing.tag)
    print("")

print "== ICredentialsChecker test =="
for n, thing in enumerate(getPlugins(ICheckerFactory)):
    print("%02d %s" % (n, thing))
    print(thing.authType)
    print("")

print "== IServiceManagerFactory test =="
for n, thing in enumerate(getPlugins(IServiceManagerFactory)):
    print("%02d %s" % (n, thing))
    print(thing.tag)
    print("")

print "== IViewProviderFactory test =="
for n, thing in enumerate(getPlugins(IViewProviderFactory)):
    print("%02d %s" % (n, thing))
    print(thing.tag)
    print("")

print("== IStreamServerEndpointStringParser ==")
for n, thing in enumerate(getPlugins(IStreamServerEndpointStringParser)):
    print("%02d %s" % (n, thing))
    print(thing.prefix)
    print("")
print("")
