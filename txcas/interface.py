from zope.interface import Interface, Attribute


class ICASUser(Interface):

    username = Attribute('String username')
    attribs = Attribute('List of (attribute, value) tuples.')


