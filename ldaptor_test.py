#! /usr/bin/env python

# Standard library
import ConfigParser
import StringIO
import os.path
import textwrap

#External modules
from twisted.internet import reactor, defer
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector

def load_defaults():
    """
    Load default settings.
    """
    settings = textwrap.dedent("""\
        [LDAP]
        host = 127.0.0.1
        port = 389
        """)
    scp = ConfigParser.SafeConfigParser()
    buf = StringIO.StringIO(settings)
    scp.readfp(buf)
    return scp
    
def load_settings():
    scp = load_defaults()
    thisdir = os.path.dirname(__file__)
    config_file_basename = "ldaptor_test"
    local_path = os.path.join(thisdir, "%s.cfg" % config_file_basename)
    user_path = os.path.expanduser("~/%src" % config_file_basename)
    scp.read([user_path, local_path])
    return scp
    

@defer.inlineCallbacks
def example():
    scp = load_settings()
    host=scp.get('LDAP', 'host')
    port=scp.getint('LDAP', 'port')
    basedn=scp.get('LDAP', 'basedn')
    binddn=scp.get('LDAP', 'binddn')
    bindpw=scp.get('LDAP', 'bindpw')
    query = '(uid=pumpkin)'
    print "host", host[0]
    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    overrides = {basedn: (host, 389)}
    client = yield c.connect(basedn, overrides=overrides)
    client = yield client.startTLS()
    yield client.bind(binddn, bindpw)
    o = ldapsyntax.LDAPEntry(client, basedn)
    #results = yield o.search(filterText=query, attributes=['uid', 'memberOf'])
    results = yield o.search(filterText=query)
    #results = yield o.search(filterText=query, attributes=[])
    for entry in results:
        # Print the LDIF representation.
        print entry
        print
        #Access the DN
        print entry.dn
        # Print attribute values.
        for x in entry['uid']:
            print x
        print
if __name__ == '__main__':
    df = example()
    df.addErrback(lambda err: err.printTraceback())
    df.addCallback(lambda _: reactor.stop())
    reactor.run()
