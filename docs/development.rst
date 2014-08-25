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
All unqualified interface references below are understood to belong to the
`txcas.interface` module.

**Credential checkers** and **user realms** are are components of `Twisted Cred`_,
Twisted's pluggable authentication system.  Credential checkers authenticate
credentials presented.  User realms create :term:`avatar` s for authenticated
users.  Currently, |project| supports credential checkers that consume credentials
that implement the `twisted.cred.credentials.IUsernamePassword`_ interface.  

Credential checker factories should implement the `twisted.cred.strcred.ICheckerFactory`_ 
interface.  Credential checkers should implement the `twisted.cred.checkers.ICredentialsChecker`_
interface.  User realm factories should implement the `IRealmFactory` interface.  
User realms should implement the `twisted.cred.portal.IRealm`_ interface. Avatars 
produced by a realm should implement the `ICASUser` interface.

**Ticket stores** manage the tickets used by CAS.  They track ticket lifetimes, 
validate them, and expire them.  Ticket stores may need to work with *service 
managers* to determine if a ticket ought to be created for a service provider, 
or if a service provider participates in :term:`SSO`.

Ticket store factories should implement the `ITicketStoreFactory` interface.
Ticket stores should implement `ITicketStore`.

**Service managers** are used to decide whether a service provider is allowed to 
authenticate with a particular |project| instance, and whether or not a service 
provider will participate in :term:`SSO`.  Without a service manager, |project| runs
"open", meaning that **any** service provider may authenticate with it.

Service manager factories should implement `IServiceManagerFactory`.
Service managers should implement `IServiceManager`.

Service managers may also provide additional service entry meta-data that 
other plugins can use.  This meta-data may be used to customize views or 
activate decision making logic in other components (e.g. the attributes 
included in a realm could be tailored to specific services).
If a plugin wants to receive a reference to the service manager, it should
implement the `IServiceManagerAcceptor` interface. 

**View providers** are used to customize the web pages presented by the |project|
service.  This kind of customization makes it possible to present a specific
theme or appearance that meshes with an organizational web site.

View provider factories should implement `IViewProviderFactory`.  View providers
should implement `IViewProvider`.  A view provider's :py:meth:`provideView`
method should return a callable if it provides a particular view or `None`
if it does not.

----------
Unit Tests
----------
|project| comes with its own unit tests.  To run the tests::

    $ trial txcas/test/test_server.py

You should see a number of test cases with statuses for each test:  **SKIPPED**,
**FAIL** or **OK**.  Tests that are skipped typically require some kind of 
middleware to be running that is difficult to emulate for the test.  An example
would be the CouchDB ticket store.  These tests tend to be slow and require 
configuration information to be passed to the test script.  To enable these
tests, copy the file :file:`txcas/test/tests.cfg.example` to 
:file:`txcas/test/tests.cfg`.  Edit the *Tests* section to enable the optional
tests.  Provide any required settings for the middleware in the appropriate
section and re-run the tests.

When developing your own plugins, it is recommended you develop your own unit 
tests.  For more information on unit testing with Twisted, see the `Trial`_
documentation and its associated `howto`_.


.. _Twisted Plugin System: http://twistedmatrix.com/documents/current/core/howto/plugin.html
.. _Writing a twistd Plugin: https://twistedmatrix.com/documents/current/core/howto/tap.html
.. _Twisted Cred: https://twistedmatrix.com/documents/current/core/howto/cred.html
.. _twisted.cred.strcred.ICheckerFactory: https://twistedmatrix.com/documents/current/api/twisted.cred.strcred.ICheckerFactory.html
.. _twisted.cred.checkers.ICredentialsChecker: https://twistedmatrix.com/documents/current/api/twisted.cred.checkers.ICredentialsChecker.html
.. _twisted.cred.portal.IRealm: https://twistedmatrix.com/documents/current/api/twisted.cred.portal.IRealm.html
.. _twisted.cred.credentials.IUsernamePassword: https://twistedmatrix.com/documents/current/api/twisted.cred.credentials.IUsernamePassword.html
.. _Trial: http://twistedmatrix.com/trac/wiki/TwistedTrial
.. _howto: http://twistedmatrix.com/documents/current/core/howto/trial.html

.. include:: placeholders.rst

