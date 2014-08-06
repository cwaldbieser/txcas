A CAS server implemented with Twisted
+++++++++++++++++++++++++++++++++++++

.. highlight:: console

The protocol: http://www.jasig.org/cas/protocol


Examples
--------

Running the Server
------------------
Copy :file:`cas.tac.example` to :file:`cas.tac`.  Then
edit the settings in :file:`cas.tac` then run it with::

    $ twistd -n -y cas.tac

To run as a daemon (in the background even when you log out 
of the shell), omit the `-n` option.

You can also run the server and specify the endpoint options 
from the command line::

    $ twistd -n cas -p 9800


Running the Server Plus Example Services
----------------------------------------
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

The demonstration program does not use the cas.tac endpoint 
configuration.  The CAS server and the services run over HTTP (no SSL)
in the demonstration.  Running over HTTPS would require setting up
a self-signed cert at the minimum, and I really just wanted the
demo to run without any extra configuration.

Plugin options are honored, so if you want to try out the demo 
using a CouchDB ticket store or an LDAP realm, you can.

Point a browser to service 1 at http://127.0.0.1:9801/ .  You
will be redirected to the CAS server to log in.  Use 'foo' and
'password' as the credentials and you will be redirected back
to the service.  You will see you are now logged in as 'foo'.

The log being printed to the console will have printed out the
/proxyValidate XML response, including so (ficticious) attributes
that were added to the avatar by the DemoUserRealm.

If you point your browser to service 2, your SSO session (provided by
the CAS ticket granting cookie (TGC) will have transparently allowed
you to log into the second service without having to re-enter crdentials.

Service 2 will also allow you to proxy service 1, which will in turn
proxy service 4.  The result returned will show the complete proxy chain.

Service 3 requires you to use primary credentials to log in.

Plugins
-------
Various plugins exist for Credential Checkers, User Realms, and Ticket Stores.
These are configured in :file:`cas.cfg`.  Some plugins require additional
dependencies.  E.g. the LDAP-based plugins require ldaptor 
(https://github.com/twisted/ldaptor).

Configuration
-------------
The endpoint for the service (port, HTTP or HTTPS, cert files, SSL options, etc.) 
are configured in :file:`cas.tac`.  
The main configuration file is called :file:`cas.cfg` (:file:`.casrc` if located in your
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

- PLUGINS: Defines what components to use.
    - cred_checker: Component to use for checking credentials.
      For a full list of cred checkers, execute::

      $ twistd -n cas --help-auth

    - realm: User realm used to return a CAS user
        - DemoRealm (default): Creates a user based on the username and
          makes up some attributes for demonstration purposes.
        - LDAPRealm: Creates a user with attributes read from an LDAP
          account.

    - ticket_store: Storage for CAS tickets.
        - InMemoryTicketStore: Stores tickets in memory.
        - CouchDBTicketStore: Stores tickets in CouchDB

LDAP Configuration
==================
The LDAPSimpleBindChecker and LDAPUSerRealm plugins require a configuration
section called "LDAP" that supports the following options:

- host
- port
- basedn
- binddn
- bindpw

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
credentials.  The script will prompt you for the necessay information.

