
# Standard library
from textwrap import dedent

# Application module
from txcas.casuser import User
from txcas.interface import ICASUser, IRealmFactory

# External module
from twisted.cred.portal import IRealm
from twisted.internet import defer
from twisted.plugin import IPlugin
from zope.interface import implements


class BasicRealmFactory(object):
    """
    A basic realm factory.
    """
    implements(IPlugin, IRealmFactory)

    tag = "basic_realm"

    opt_help = dedent('''\
            A basic realm that creates an avatar from an ID with no
            attributes.
            ''')

    opt_usage = '''This type of realm has no options.'''

    def generateRealm(self, argstring=""):
        """
        Produce a BaiscRealm instance.
        """
        return BasicRealm() 

class BasicRealm(object):
    """
    A Basic user realm that maps an avatar ID to an avatar with a matching
    username and no attributes.
    """

    implements(IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        """
        def cb():
            if not ICASUser in interfaces:
                raise NotImplementedError("This realm only implements ICASUser.")
            avatar = User(avatarId, None)
            return (ICASUser, avatar, avatar.logout)
        return defer.maybeDeferred(cb)
