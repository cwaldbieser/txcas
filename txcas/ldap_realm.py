

# Standard library
from textwrap import dedent
import sys

# Application module
from txcas.interface import ICASUser, IRealmFactory

# Application modules
import txcas.settings

# External module
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector
from ldaptor.protocols.ldap.ldaperrors import LDAPInvalidCredentials

from twisted.cred.portal import IRealm
from twisted.internet import defer, reactor
from twisted.plugin import IPlugin
from zope.interface import implements

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

class User(object):

    implements(ICASUser)

    username = None
    attribs = None
    
    def __init__(self, username, attribs):
        self.username = username
        self.attribs = attribs
   
    def logout(self):
        pass 

class LDAPRealmFactory(object):
    """
    """
    implements(IPlugin, IRealmFactory)

    tag = "ldap_realm"

    opt_help = dedent('''\
            Builds an avatar from a fetched LDAP entry.
            LDAP attributes are translated into avatar
            attributes.  Valid options include:
            
            - host
            - port
            - basedn
            - binddn
            - bindpw 
            - query_template: default -> (uid=%(username)s)
              The %(username)s part will be interpolated with the (escaped)
              avatar ID.
            - attribs: A comma-separated list of attributes.
            ''')

    opt_usage = '''A colon-separated key=value list.'''

    def generateRealm(self, argstring=""):
        """
        """
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        ldap_settings = settings.get('LDAP', {})    
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            ldap_settings.update(argdict)
        buf = ["[CONFIG][LDAPRealm] Settings:"]
        for k in sorted(ldap_settings.keys()):
            if k != "bindpw":
                v = ldap_settings[k]
            else:
                v = "*******"
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf)) 
        sys.stderr.write('\n') 
        missing = txcas.utils.get_missing_args(
                    LDAPRealm.__init__, ldap_settings, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][LDAPRealm] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n') 
            sys.exit(1)
        if 'attribs' in ldap_settings:
            attribs = ldap_settings['attribs']
            attribs = attribs.split(',')
            ldap_settings['attribs'] = attribs

        txcas.utils.filter_args(LDAPRealm.__init__, ldap_settings, ['self'])
        return LDAPRealm(**ldap_settings) 

class LDAPRealm(object):


    implements(IRealm)
    
    def __init__(self, host, port, basedn, binddn, bindpw, query_template='(uid=%(username)s)', attribs=None):
        if attribs is None:
            attribs = []
        self._attribs = attribs
        self._host = host
        self._port = port
        self._basedn = basedn
        self._binddn = binddn
        self._bindpw = bindpw
        self._query_template = query_template

    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        """
            
        def cb(avatar):
            if not ICASUser in interfaces:
                raise NotImplementedError("This realm only implements ICASUser.")
            return (ICASUser, avatar, avatar.logout)
            
        d = self._get_avatar(avatarId)
        return d.addCallback(cb)
        
    @defer.inlineCallbacks
    def _get_avatar(self, avatarId):
        serverip = self._host
        basedn = self._basedn
        binddn = self._binddn
        bindpw = self._bindpw
        query = self._query_template % {'username': escape_filter_chars(avatarId)}

        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, self._port)}
        client = yield c.connect(basedn, overrides=overrides)
        client = yield client.startTLS()        
        yield client.bind(binddn, bindpw)
        o = ldapsyntax.LDAPEntry(client, basedn)
        results = yield o.search(filterText=query, attributes=self._attribs)
        if len(results) != 1:
            raise Exception("No unique account found for '%s'." % avatarId)
        entry = results[0]
        _attribs = self._attribs
        attribs = []
        for key in _attribs:
            if key in entry:
                valuelist = entry[key]
                for value in valuelist:
                    attribs.append((key, value))
        user = User(avatarId, attribs)
        defer.returnValue(user)
        
        
        
        
        
        
        
        
        
        
