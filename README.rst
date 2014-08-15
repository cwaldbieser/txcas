A CAS server implemented with Twisted
+++++++++++++++++++++++++++++++++++++

.. highlight:: console

The protocol: http://www.jasig.org/cas/protocol


Examples
--------

Running the Demonstration
-------------------------
The service comes with a ready-to-run demonstration using a basic
credential checker (single user 'foo' with password 'password'), 
a demo user realm (provides 2 made up attributes), and an in-memory
ticket store.  Four simple services demonstrate interactions with
the CAS service.

Run the :program:`sample.py` script as follows::

    $ python sample.py

The CAS server will run on port 9800.
Service 1 runs on port 9801.
Service 2 runs on port 9802.
Service 3 runs on port 9803.
Service 4 runs on port 9804.
All services listen on localhost (127.0.0.1).

The demo runs *without* a :file:`cas.cfg` file, using default
settings.  You *can* create a config file, and the but
the demonstration program does not use the :file:`cas.tac` endpoint 
configuration.  The CAS server and the services run over HTTP (no SSL)
in the demonstration.  Running over HTTPS would require setting up
a self-signed cert at the minimum, and I really just wanted the
demo to run without any extra configuration.

Plugin options in the config are honored, so if you want to try 
out the demo using a CouchDB ticket store or an LDAP realm, you can.

Point a browser to service 1 at http://127.0.0.1:9801/ .  You
will be redirected to the CAS server to log in.  Use 'foo' and
'password' as the credentials and you will be redirected back
to the service.  You will see you are now logged in as 'foo'.

The log being printed to the console will have printed out the
/proxyValidate XML response, including some (ficticious) attributes
that were added to the avatar by the DemoUserRealm.

If you point your browser to service 2, your SSO session provided by
the CAS ticket granting cookie (TGC) will have transparently allowed
you to log into the second service without having to re-enter crdentials.

Service 2 will also allow you to proxy service 1, which will in turn
proxy service 4.  The result returned will show the complete proxy chain.

Service 3 requires you to use primary credentials to log in.

Running the Server
------------------
Copy :file:`cas.tac.example` to :file:`cas.tac`.  Then
edit the settings in :file:`cas.tac` then run it with::

    $ twistd -n -y cas.tac

To run as a daemon (in the background even when you log out 
of the shell), omit the `-n` option.

You can also run the server and specify the options 
from the command line.  The following example runs the server
on port 9800.::

    $ twistd -n cas -p 9800

To get a list of all command line options::

    $ twistd -n cas --help


Plugins
-------
Various plugins exist for Credential Checkers, User Realms, View Providers, 
and Ticket Stores.  These are configured in :file:`cas.cfg`.  Some plugins 
require additional dependencies.  E.g. the LDAP-based plugins require ldaptor 
(https://github.com/twisted/ldaptor).

Configuration
-------------
The endpoint for the service (port, HTTP or HTTPS, cert files, SSL options, etc.) 
can be configured in :file:`cas.tac` when running the server without command line options.  
The main configuration file is called :file:`cas.cfg` (or :file:`.casrc` if located in your
$HOME on UNIX-like systems).  The meanings of the sections are as follows:

- CAS: General CAS options
    - validate_pgturl: 1 (verify peer during proxy callback as per CAS protocol) or
      0 (do not verify peer-- useful when using self-signed cert during development
      and testing).
    - lt_timeout: Login Ticket timeout
    - st_timeout: Service Ticket timeout
    - pt_timeout: Proxy Ticket timeout
    - pgt_timeout: Proxy Granting Ticket timeout
    - tgt_timeout: Ticket Granting Ticket timeout
    - static_dir: Path to folder from which static content is served.

- PLUGINS: Defines what components to use.
    - cred_checker: Component to use for checking credentials.
      For a full list of cred checkers, execute::

      $ twistd -n cas --help-auth

    - realm: User realm used to return a CAS user
      For a full list of realms, execute::

      $ twistd -n cas --help-realms

    - view_provider: Provide a customized view of what various server pages
      look like.
      For a full list of view providers, execute::

      $ twistd -n cas --help-view-providers

    - service_manager: Manage service information including whether a service is
      valid and whether a service participates in SSO.
      For a full list of realms, execute::

      $ twistd -n cas --help-service-managers

    - ticket_store: Storage for CAS tickets.
      For a full list of ticket stores, execute::

      $ twistd -n cas --help-ticket-stores

A sample configuration file, :file:`cas.cfg.example` is provided to give an idea
of various sections and options.

The JSONServiceManager plugin uses a file in JSON format, 
:file:`serviceRegistry.json` to determine what services are allowed by the 
service.  While the keys shown in the config file have special meanings to the 
service manager, you can extend the entries with your own attributes which can 
be used in view providers.  The exact means by which this information is made 
available is specific to each view provider.

LDAP Configuration
==================
The LDAPSimpleBindChecker and LDAPUSerRealm plugins require a configuration
section called "LDAP" that supports the following options:

- host
- port
- basedn
- binddn
- bindpw

Currently this plugin assumes that the connection will be encrypted using 
StartTLS immediately after the connection is established.

CouchDB Configuration
=====================
The CouchDBTicketStore plugin requires a configuration section called
"CouchDB" with the following options:

- host
- port
- db
- user
- passwd
- https: 1 (use https) or 0 (use http)
- verify_cert: 1 (verify CouchDB cert) or
  0 (do not verify CouchDB cert-- useful when using self-signed cert during development
  and testing).

The CouchDB database itself will need to be configured with the appropriate views.
You can set up the database views by running the :program:`setup_couchdb.py` program.
You should create an empty database before running the script and have DB admin
credentials.  The script will prompt you for the necessary information.

Development
-----------

Developing Plugins
==================

Basic File Layout and Script Requirements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Plugins can be developed for credential checkers, user realms, and ticket stores.
Plugin intergration code should be located in $PROJECT/twisted/plugins in a 
Python script file.  The script should create a variables in the global 
namespace of the script which are *instances* of classes that implement the
required interface for the plugin you are developing.  For example, a file
called `$PROJECT/twisted/plugins/myspecialticketstore.py` might have something
like:

.. code-block:: python

    from mywickedcoolticketstore import WicketCoolTicketStore
    import txcas.settings

    # Read settings from [WickedCoolTicketStore] section.
    # ...

    aplugin = WickedCoolTicketStore(**settings)

For more details, see: https://twistedmatrix.com/documents/14.0.0/core/howto/tap.html#using-cred-with-your-tap

Configuring Plugins
^^^^^^^^^^^^^^^^^^^
Consider loading plugin settings from a unique section of :file:`cas.cfg`.  The 
LDAPSimpleBindChecker and LDAPRealm plugins take this approach, as the
LDAP settings are typically the same for these components.  However, you
*should* make an effort so that command line arguments override any config
file arguments, when applicable.

Credential Checker Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^
Current plugin architecture for cred checkers is based on providing an 
*instance* of a class that implements twisted.cred.strcred.ICheckerFactory.
This works with Twisted's :program:`twistd` program and lets you specify
an :option:`--auth` option directly on the command line.  :file:`cas.cfg`
can also specify a `cred_checker` option that should essentially be the same
as the command line argument.  Since this syntax can be somewhat clunky for
complex plugins, I'd recommend that you set up a separate section in the
config file to provide options.

User Realm Plugins
^^^^^^^^^^^^^^^^^^
User realm plugins are responsible for turning an authenticated avatar ID into
an object that implements txcas.inteface.ICASUSer.  This user object is used to 
provide attributes to a service during a /serviceValidate or /proxyValidate call.
Realm plugins should provide global instances that implement
txcas.interface.ICASRealmFactory.  The factory should generate an object that
implements the twisted...IRealm interface, similar to how credential checker 
plugin architecture works.

View Provider Plugins
^^^^^^^^^^^^^^^^^^^^^
A view provider is used to generate custom markup for the web pages the CAS
service generates in response to requests.  The most obvious page is the
login page, but there are other views that may warrant your attention for
theming purposes.  View providers that use templating solutions will
work best if you can serve static content from the service.  You can accomplish
this with the :option:`static_dir` option in under the `CAS` section of the
config file.

View providers don't *have* to implement every view.  If a view provider chooses
not to, it should return `None` from the `provideView()` method.  On the other hand,
if a view provider *does* provide a view, but some runtime condition prevents it 
from doing so, it can raise a `txcas.exceptions.ViewNotImplementedError`.

I am putting example "themes" (collections of templates and static resources) in
a separate repository at https://github.com/cwaldbieser/txcas_extras

Service Manager Plugins
^^^^^^^^^^^^^^^^^^^^^^^
Service manager plugins are used to determine whether a service is valid.
They also determine whether a service is able to participate in SSO or
whether primary credentials must be presented.  This latter function is similar
to the `renew` parameter of the CAS protocol, but it is enforced from the
CAS server rather than from the service.

Ticket Store Plugins
^^^^^^^^^^^^^^^^^^^^
Ticket store plugins manage tickets that CAS uses.  They can be persistant like
`txcas.couchdb_ticket_store.CouchDBTicketStore`, or they can be ephemeral like
`txcas.in_memory_ticket_store.InMemoryTicketStore`.  They also send out notifications
of ticket expirations.

Ticket store plugins should provide global instances that implement
txcas.interface.ITicketStoreFactory.  The factory should generate an object that
implements the txcas.interface.ITicketStore interface, similar to how credential checker 
plugin architecture works.




