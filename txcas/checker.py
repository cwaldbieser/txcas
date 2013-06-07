# XXX Not tested


from zope.interface import implements
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred import credentials
from twisted.internet import defer



class FunctionChecker(object):

    implements(ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)


    def __init__(self, checker_func):
        self.checker_func = checker_func


    def requestAvatarId(self, credentials):
        return defer.maybeDeferred(self.checker_func, credentials.username,
                                   credentials.password)

