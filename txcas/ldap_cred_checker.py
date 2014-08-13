
# Standard library
from textwrap import dedent
import sys

# Application modules
import txcas.settings
import txcas.utils

# External modules
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector
from ldaptor.protocols.ldap.ldaperrors import LDAPInvalidCredentials

from twisted.cred import credentials
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.strcred import ICheckerFactory
from twisted.internet import defer, reactor
from twisted.plugin import IPlugin
from twisted.python import log
from zope.interface import implements

#==============================================================================
#==============================================================================

def escape_filter_chars(assertion_value,escape_mode=0):
    """
    This function shamelessly copied from python-ldap module.
    
    Replace all special characters found in assertion_value
    by quoted notation.

    escape_mode
      If 0 only special chars mentioned in RFC 2254 are escaped.
      If 1 all NON-ASCII chars are escaped.
      If 2 all chars are escaped.
    """
    if escape_mode:
        r = []
        if escape_mode==1:
            for c in assertion_value:
                if c < '0' or c > 'z' or c in "\\*()":
                    c = "\\%02x" % ord(c)
                r.append(c)
        elif escape_mode==2:
            for c in assertion_value:
                r.append("\\%02x" % ord(c))
        else:
          raise ValueError('escape_mode must be 0, 1 or 2.')
        s = ''.join(r)
    else:
        s = assertion_value.replace('\\', r'\5c')
        s = s.replace(r'*', r'\2a')
        s = s.replace(r'(', r'\28')
        s = s.replace(r')', r'\29')
        s = s.replace('\x00', r'\00')
    return s

#==============================================================================
#==============================================================================

class LDAPAdminBindError(Exception):
    pass

#==============================================================================
#==============================================================================

class LDAPSimpleBindChecker(object):

    implements(IPlugin, ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)


    def __init__(self, host, port, basedn, binddn, bindpw, query_template='(uid=%(username)s)'):
        self._host = host
        self._port = port
        self._basedn = basedn
        self._binddn = binddn
        self._bindpw = bindpw
        self._query_template = query_template


    def requestAvatarId(self, credentials):
        
        def eb(err):
            if not err.check(UnauthorizedLogin, LDAPInvalidCredentials):
                log.err(err)
            raise UnauthorizedLogin()
            
        return self._make_connect(credentials).addErrback(
            eb)

    @defer.inlineCallbacks
    def _make_connect(self, credentials):
        serverip = self._host
        basedn = self._basedn

        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, self._port)}
        client = yield c.connect(basedn, overrides=overrides)
        client = yield client.startTLS()
        dn = yield self._get_dn(client, credentials.username)
        yield client.bind(dn, credentials.password)
        
        defer.returnValue(credentials.username)
        
    @defer.inlineCallbacks
    def _get_dn(self, client, username):
        basedn = self._basedn
        binddn = self._binddn
        bindpw = self._bindpw
        query = self._query_template % {'username': escape_filter_chars(username)}
        
        try:
            yield client.bind(binddn, bindpw)
        except Exception as ex:
            log.err(ex)
            raise LDAPAdminBindError("Error binding with admin DN: %s." % binddn)
        o = ldapsyntax.LDAPEntry(client, basedn)
        results = yield o.search(filterText=query, attributes=['uid'])
        if len(results) != 1:
            raise UnauthorizedLogin()
        entry = results[0]
        defer.returnValue(entry.dn)
        
class LDAPSimpleBindCheckerFactory(object):
    """
    A checker factory for an LDAPSimpleBindChecker.
    """
    # The class needs to implement both of these interfaces
    # for the plugin system to find our factory.
    implements(ICheckerFactory, IPlugin)

    # This tells AuthOptionsMixin how to find this factory.
    authType = "ldap_simple_bind"

    # This is a one-line explanation of what arguments, if any,
    # your particular cred plugin requires at the command-line.
    argStringFormat = "A colon-separated key=value list."

    # This help text can be multiple lines. It will be displayed
    # when someone uses the "--help-auth-type special" command.
    authHelp = dedent('''\
            Uses a 2-stage BIND to determine if the credentials 
            presented are valid.  Valid options include:
            
            - host
            - port
            - basedn
            - binddn
            - bindpw 
            - query_template: default -> (uid=%(username)s)
              The %(username)s part will be interpolated with the (escaped)
              avatar ID.
            ''')

    # The types of credentials this factory supports.
    credentialInterfaces = (credentials.IUsernamePassword,)

    # This will be called once per command-line.
    def generateChecker(self, argstring=""):
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        ldap_settings = settings.get('LDAP', {})    
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            ldap_settings.update(argdict)
        missing = txcas.utils.get_missing_args(
                    LDAPSimpleBindChecker.__init__, ldap_settings, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][LDAPSimpleBindChecker] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n') 
            sys.exit(1)

        txcas.utils.filter_args(LDAPSimpleBindChecker.__init__, ldap_settings, ['self'])
        buf = ["[CONFIG][LDAPSimpleBindChecker] Settings:"]
        for k in sorted(ldap_settings.keys()):
            if k != "bindpw":
                v = ldap_settings[k]
            else:
                v = "*******"
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf)) 
        sys.stderr.write('\n') 
        return LDAPSimpleBindChecker(**ldap_settings)

        
        
