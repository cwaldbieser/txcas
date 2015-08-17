
# Standard library
from textwrap import dedent
import sys
# Application module
from txcas.casuser import User
from txcas.interface import ICASUser, IRealmFactory, IServiceManagerAcceptor
# Application modules
from txcas.settings import get_bool, export_settings_to_dict, load_settings
import txcas.utils
# External module
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols.ldap.ldaperrors import LDAPInvalidCredentials
import pem
from twisted.cred.portal import IRealm
from twisted.internet import defer, reactor
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.ssl import Certificate, optionsForClientTLS, platformTrust
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


class LDAPTlsAuthorityError(Exception):
    pass


class LDAPRealmFactory(object):
    implements(IPlugin, IRealmFactory)
    tag = "ldap_realm"
    opt_help = dedent('''\
            Builds an avatar from a fetched LDAP entry.
            LDAP attributes are translated into avatar
            attributes.  Valid options include:
            
            - endpointstr 
            - basedn
            - binddn
            - bindpw 
            - query_template: default -> (uid=%(username)s)
              The %(username)s part will be interpolated with the (escaped)
              avatar ID.
            - attribs: A comma-separated list of attributes.
            - aliases: A comma-separated list of aliases.
            - service_based_attribs: Use attributes/aliases from service
              registry entry (found under key 'attributes'.
            - start_tls: Use StartTLS.
            - start_tls_hostname: Hostname to use with StartTLS (otherwise TLS is *not* verified).
            - start_tls_cacert: PEM formatted CA cert file to trust for StartTLS.
            ''')
    opt_usage = '''A colon-separated key=value list.'''

    def generateRealm(self, argstring=""):
        scp = load_settings('cas', syspath='/etc/cas')
        settings = export_settings_to_dict(scp)
        ldap_settings = settings.get('LDAP', {})  
        temp = settings.get("LDAPRealm", {})
        ldap_settings.update(temp)
        del temp  
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            ldap_settings.update(argdict)
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
        if 'aliases' in ldap_settings:
            aliases = ldap_settings['aliases']
            aliases = aliases.split(',')
            ldap_settings['aliases'] = aliases
        if 'service_based_attribs' in ldap_settings:
            ldap_settings['service_based_attribs'] = get_bool(ldap_settings['service_based_attribs'])
        if 'start_tls' in ldap_settings:
            ldap_settings['start_tls'] = get_bool(ldap_settings['start_tls'])
        txcas.utils.filter_args(LDAPRealm.__init__, ldap_settings, ['self'])
        buf = ["[CONFIG][LDAPRealm] Settings:"]
        for k in sorted(ldap_settings.keys()):
            if k != "bindpw":
                v = ldap_settings[k]
            else:
                v = "*******"
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf)) 
        sys.stderr.write('\n') 
        return LDAPRealm(**ldap_settings) 


class LDAPRealm(object):
    implements(IRealm, IServiceManagerAcceptor)
    service_manager = None
    
    def __init__(self, endpointstr, basedn, binddn, bindpw, 
                query_template='(uid=%(username)s)', 
                attribs=None, 
                aliases=None,
                service_based_attribs=False,
                start_tls=False,
                start_tls_hostname=None,
                start_tls_cacert=None):
        if attribs is None:
            attribs = []
        # Turn attribs into mapping of attrib_name => alias.
        if aliases is not None:
            assert len(aliases) == len(attribs), "[ERROR][LDAP REALM] Number of aliases must match number of attribs."
            attribs = dict(x for x in zip(attribs, aliases))
        else:
            attribs = dict((k,k) for k in attribs)
        self._attribs = attribs
        self._endpointstr = endpointstr
        self._basedn = basedn
        self._binddn = binddn
        self._bindpw = bindpw
        self._query_template = query_template
        self._service_based_attribs = service_based_attribs
        self._startTls = get_bool(start_tls)
        self._startTlsAuthority = self.getTlsAuthority_(start_tls_cacert)
        self._startTlsHostName = start_tls_hostname

    def getTlsAuthority_(self, startTlsCaCert):
        if startTlsCaCert is None:
            return None
        authorities = [str(cert) for cert in pem.parse_file(startTlsCaCert)] 
        if len(authorities) != 1:
            raise Exception(
                ("The provided CA cert file, '{0}', "
                "contained {1} certificates.  It must contain exactly one.").format(
                    startTlsCaCert, len(authorities)))
        return Certificate.loadPEM(authorities[0])

    def requestAvatar(self, avatarId, mind, *interfaces):

        def cb(avatar):
            if not ICASUser in interfaces:
                raise NotImplementedError("This realm only implements ICASUser.")
            return (ICASUser, avatar, avatar.logout)
            
        d = self._get_avatar(avatarId, mind)
        return d.addCallback(cb)
        
    @defer.inlineCallbacks
    def _get_avatar(self, avatarId, mind):
        endpointstr = self._endpointstr
        basedn = self._basedn
        binddn = self._binddn
        bindpw = self._bindpw
        query = self._query_template % {'username': escape_filter_chars(avatarId)}
        if self._service_based_attribs:
            if mind:
                service = mind['service']
            else:
                service = ""
            if service == "" or service is None or self.service_manager is None:
                attributes = self._attribs
            else:
                service_entry = yield defer.maybeDeferred(self.service_manager.getMatchingService, service)
                if service_entry and 'attributes' in service_entry:
                    attributes = service_entry['attributes']
                else:
                    attributes = self._attribs
        else:
            attributes = self._attribs
        e = clientFromString(reactor, self._endpointstr)
        client = yield connectProtocol(e, LDAPClient())
        startTls = self._startTls
        startTlsHostName = self._startTlsHostName
        startTlsAuthority = self._startTlsAuthority
        if startTls:
            startTlsArgs = []
            if startTlsHostName is not None:
                if startTlsAuthority is not None:
                    ctx = optionsForClientTLS(unicode(startTlsHostName), startTlsAuthority)
                else:
                    ctx = optionsForClientTLS(unicode(startTlsHostName), platformTrust())
                startTlsArgs.append(ctx)
            client = yield client.startTLS(*startTlsArgs)
        yield client.bind(binddn, bindpw)
        o = ldapsyntax.LDAPEntry(client, basedn)
        results = yield o.search(filterText=query, attributes=attributes.keys())
        yield client.unbind()
        if len(results) != 1:
            raise Exception("No unique account found for '%s'." % avatarId)
        entry = results[0]
        _attribs = attributes
        attribs = []
        for key, alias in _attribs.iteritems():
            if key in entry:
                valuelist = entry[key]
                for value in valuelist:
                    attribs.append((alias, value))
        user = User(avatarId, attribs)
        defer.returnValue(user)
