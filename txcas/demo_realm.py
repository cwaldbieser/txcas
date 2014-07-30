
# Application module
from txcas.interface import ICASUser

# External module
from twisted.cred.portal import IRealm
from twisted.internet import defer
from twisted.plugin import IPlugin
from zope.interface import implements

class User(object):

    implements(ICASUser)

    username = None
    attribs = None
    
    def __init__(self, username, attribs):
        self.username = username
        self.attribs = attribs
   
    def logout(self):
        pass 


class DemoRealm(object):


    implements(IPlugin, IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        """
        def cb():
            if not ICASUser in interfaces:
                raise NotImplementedError("This realm only implements ICASUser.")
            attribs = [
                ('email', "%s@example.org" % avatarId),
                ('domain', 'example.org'),]
            # ENHANCEMENT: This method can also return a deferred that returns
            # (interface, avatar, logout).  Useful if reading user information
            # from a database or LDAP directory.
            avatar = User(avatarId, attribs)
            return (ICASUser, avatar, avatar.logout)
        return defer.maybeDeferred(cb)
