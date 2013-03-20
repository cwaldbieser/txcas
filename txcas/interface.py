from zope.interface import Interface, Attribute


class IUser(Interface):

    username = Attribute('String username')


