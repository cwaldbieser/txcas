
# Standard library
import functools
import string
from textwrap import dedent
import sys

# Application modules
from txcas.interface import ICASAuthWhen
import txcas.settings
import txcas.utils

# External modules
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred import credentials
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.strcred import ICheckerFactory
from twisted.internet import defer
from twisted.internet.interfaces import ISSLTransport
from twisted import plugin
from zope.interface import implements

def compose(*functions):
    return functools.reduce(lambda f, g: lambda x: f(g(x)), functions)

def strip_domain(s):
    pos = s.find('@')
    if pos != -1:
        s = s[:pos]
    return s

class ClientCertificateCheckerFactory(object):
    """
    A factory for a ClientCertificateChecker
    """
    # The class needs to implement both of these interfaces
    # for the plugin system to find our factory.
    implements(ICheckerFactory, plugin.IPlugin)

    # This tells AuthOptionsMixin how to find this factory.
    authType = "client_cert"

    # This is a one-line explanation of what arguments, if any,
    # your particular cred plugin requires at the command-line.
    argStringFormat = "A colon-separated key=value list."

    # This help text can be multiple lines. It will be displayed
    # when someone uses the "--help-auth-type special" command.
    authHelp = dedent("""\
        Extracts part of the subject from a client x509 certificate,
        optionally performs a transformation, and returns the result
        as the avatar ID. (Authentication takes place during the 
        SSL handshake).
        
        Options
        -------
        subject_part: The part of the subject to extract, e.g. "CN",
                      or "emailAddress".
        transform:    A comma-separated list of 'upper', 'lower',
                      'strip_domain'.  One or more transforms are
                      applied to the extracted subject part.. 
        auth_when:    Perform authentication when requesting the 
                      /login page ('cred_requestor', the default), or
                      when POSTing the username/password credentials
                      ('cred_acceptor').
        """)

    credentialInterfaces = (ISSLTransport,)

    # This will be called once per command-line.
    def generateChecker(self, argstring=""):
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        plugin_settings = settings.get('ClientCertificateChecker', {})
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            plugin_settings.update(argdict)
        missing = txcas.utils.get_missing_args(
                    ClientCertificateChecker.__init__, plugin_settings, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][ClientCertificateChecker] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n')
            sys.exit(1)

        txcas.utils.filter_args(ClientCertificateChecker.__init__, plugin_settings, ['self'])
        buf = ["[CONFIG][ClientCertificateChecker] Settings:"]
        for k in sorted(plugin_settings.keys()):
            v = plugin_settings[k]
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf))
        sys.stderr.write('\n')

        transform_s = plugin_settings.get('transform', None)
        if transform_s is not None:
            xforms = transform_s.split(',')
            funcs = []
            for xform in xforms:
                if xform == 'upper':
                    funcs.append(string.upper)
                elif xform == 'lower':
                    funcs.append(string.lower)
                elif xform == 'strip_domain':
                    funcs.append(strip_domain)
                else:
                    sys.stderr.write("Unknown transformation '%s'.\n" % xform)
                    sys.exit(1)
            transform = compose(*funcs)
            plugin_settings['transform'] = transform
        auth_when = plugin_settings.get('auth_when', 'cred_requestor')
        if auth_when not in ('cred_acceptor', 'cred_requestor'):
            sys.stderr.write(
                ("Unknown auth_when '%s'.  Must be 'cred_acceptor' or"
                " 'cred_requestor'.\n") % auth_when)
            sys.exit(1)
        return ClientCertificateChecker(**plugin_settings)

class ClientCertificateChecker(object):

    implements(ICredentialsChecker, ICASAuthWhen)
    credentialInterfaces = (ISSLTransport,)

    auth_when = 'cred_requestor'

    def __init__(self, subject_part='emailAddress', transform=None, auth_when=None):
        self.subject_part = subject_part
        self.transform = transform
        if auth_when is not None:
            self.auth_when = auth_when

    def requestAvatarId(self, credentials):
        """
        Extract an avatar ID from an ISSLTransport object.
        NOTE: Authentication has technically already happened during the SSL
        handshake.
        """
        if not ISSLTransport.providedBy(credentials):
            return defer.fail(UnauthorizedLogin("The credentials provided did not provide the ISSLTransport interface."))
        peer_cert = credentials.getPeerCertificate()
        if peer_cert is None:
            return defer.fail(UnauthorizedLogin("A client certificate was not provided!"))
        subject= peer_cert.get_subject()
        #issuer = peer_cert.get_issuer()
        transform = self.transform
        subject_components = subject.get_components()
        match_part = self.subject_part
        avatar_part = None
        for part, value in subject_components:
            if part == match_part:
                avatar_part = value
                break
        if avatar_part is None:
            return defer.fail(UnauthorizedLogin("Client certificate did not contain subject part '%s'." % match_part))
        if transform is not None:
            return defer.maybeDeferred(transform, avatar_part)
        else:
            return defer.succeed(avatar_part)


