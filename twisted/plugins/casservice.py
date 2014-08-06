

from zope.interface import implements

from twisted.cred import credentials, strcred
from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

from txcas.service import CASService




class Options(usage.Options, strcred.AuthOptionMixin):
    # This part is optional; it tells AuthOptionMixin what
    # kinds of credential interfaces the user can give us.
    supportedInterfaces = (credentials.IUsernamePassword,)

    optFlags = [["ssl", "s", "Use SSL"],]
    optParameters = [
                        ["port", "p", 9800, "The port number to listen on.", int],
                        ["cert-key", "c", None, "An x509 certificate file (PEM format)."],
                        ["private-key", "k", None, "An x509 private key (PEM format)."],
                    ]


class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "cas"
    description = "Central Authentication Service (CAS)."
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """
        parts = []
        if options["ssl"]:
            parts.append("ssl")
        else:
            parts.append("tcp")
        parts.append(str(options["port"]))
        certKey = options['cert-key']
        if certKey is not None:
            parts.append('certKey=%s' % certKey)
        privateKey = options['private-key']
        if privateKey is not None:
            parts.append('privateKey=%s' % privateKey)
        endpoint = ':'.join(parts)
        checkers = options.get("credCheckers", None)
        return CASService(endpoint, checkers=checkers)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
