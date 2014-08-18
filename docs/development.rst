===========
Development
===========

The |project| software makes heavy use of the `Twisted Plugin System`_.  The core software
implements the web interactions and delegates various operations to plugins.

-----------------------------------------
Basic File Layout and Script Requirements
-----------------------------------------
Plugin intergration code should be located in :file:`$PROJECT/twisted/plugins` 
in a Python script file. The script should assign global variables to
instances of a class or classes that implement the factory interface for the 
plugin you are developing.  For example, a file called 
:file:`/somewhere/on/your/PYTHONPATH/myspecialticketstore.py` might look something like::

    from txcas.interface import ITicketStore, ITicketStoreFactory
    from twisted.plugin import IPlugin
    from zope.interface import implements

    class WickedCoolTicketStoreFactory(object):
        """
        A factory for creating wicked-cool ticket stores!
        """
        implements(IPlugin, ITicketStoreFactory)

        tag = "wicked_cool_ticket_store"
        opt_help = "I am detailed help printed on the command line."
        opt_usage = "I am the brief help printed on the command line."

        def generateTicketStore(self, argstring=""):
            """
            This method returns an object that implements ITicketStore.
            It is configured via the string passed to this function, but it can 
            also pull settings out of the txcas configuration file.  The
            settings passed in should be given preference to those in the
            config file.
            """
            # Implementation is something you would need to code.
            # ...
            return a_shiny_new_ticket_store

The file :file:`$TXCAS_ROOT/twisted/plugins/myspecialticketstoreplugin.py` should contain 
something like::

    from myspecialticketstore import WicketCoolTicketStoreFactory
    import txcas.settings

    aplugin = WickedCoolTicketStoreFactory()

.. note::

    In the above example, the script that actually implements the 
    :py:class:`WickedCoolTicketStoreFactory` does not need to reside in the
    |project| project folder.  It can be located anywhere on your 
    :envvar:`PYTHONPATH`.

    The code that instantiates the plugin factory *should* reside in the
    :file:`$TXCAS_ROOT/twisted/plugins` folder.

The reason that factories are used is that many plugins tend to need some kind 
of configuration.  Factories can be created with no configuration, and they can
accept command line arguments that can be used in the configuration process.

If you look at the source code in :file:`txcas/interface.py`, you will see that
for each plugin type, there is an interface for a factory and an interface for 
the plugin the factory produces.

For more information on writing Twisted plugins, see `Writing a twistd Plugin`_

----------------
Kinds of Plugins
----------------
Credential checkers and `user realms`_ are are components of `Twisted Cred`_,
Twisted's pluggable authentication system.  Credential checkers authenticate
credentials presented.  User realms create :term:`avatar` s for authenticated
users.  Currently, |project| supports credential checkers that support 
`IUsernamePassword`_ credentials.

Ticket stores manage the tickets used by CAS.  They track ticket lifetimes, validate
them, and expire them.  Ticket stores may need to work with service managers to 
determine if a ticket ought to be created for a service provider, or if a service
provider participates in :term:`SSO`.

Service managers are used to decide whether a service provider is allowed to 
authenticate with a particular |project| instance, and whether or not a service 
provider will participate in :term:`SSO`.  Without a service manager, |project| runs
"open", meaning that **any** service provider may authenticate with it.

Service managers may also provide additional service entry meta-data to view 
providers.  This meta-data may be used to customize the view in specific 
situations (e.g. informing the user what service she is about to log into).

View providers are used to customize the web pages presented by the |project|
service.  This kind of customization makes it possible to preserve an overall
theme or appearance with the services that |project| protects.

***********
User Realms
***********        

User realms in |project| must ultimately produce an :term:`avatar`.  |project|
expects the avatar to be an instance of a class that implements the :py:class:`ICASUser`
interface.  The avatar should have both `username` and `attribs` properties.
If the avatar has no attributes, then `attribs` should be an empty list.




.. _Twisted Plugin System: http://twistedmatrix.com/documents/current/core/howto/plugin.html
.. _Writing a twistd Plugin: https://twistedmatrix.com/documents/current/core/howto/tap.html
.. _Twisted Cred: https://twistedmatrix.com/documents/current/core/howto/cred.html
.. _IUsernamePassword: https://twistedmatrix.com/documents/current/api/twisted.cred.credentials.IUsernamePassword.html


.. include:: placeholders.rst

