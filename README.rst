A CAS server implemented with Twisted
+++++++++++++++++++++++++++++++++++++

.. highlight:: console

The protocol: http://www.jasig.org/cas/protocol


Examples
--------

Running the Server
------------------
Edit the settings in :file:`sample.tac` then run it with::

    $ twistd -n -y sample.tac

Running the Server Plus Example Services
----------------------------------------
Run the :program:`sample.py` script as follows::

    $ python sample.py

The CAS server will run on port 9800.
Service 1 runs on port 9801.
Service 2 runs on port 9802.
All services listen on localhost (127.0.0.1).

Point a browser to service 1 at http://127.0.0.1:9801/ .  You
will be redirected to the CAS server to log in.  Use 'foo' and
'password' as the credentials and you will be redirected back
to the service.  You will see you are now logged in as 'foo'.

The log being printed to the console will have printed out the
/serviceValidate XML response, including so (ficticious) attributes
that were added to the avatar by the UserRealm.

If you point your browser to service 2, your SSO session (provided by
the CAS ticket granting cookie (TGC) will have transparently allowed
you to log into the second service without having to re-enter crdentials.

Plugins
-------
Various plugins exist for Credential Checkers, User Realms, and Ticket Stores.
These are configured in :file:`cas.cfg`.  Some plugins require additional
dependencies.  E.g. the LDAP-based plugins require ldaptor 
(https://github.com/twisted/ldaptor).

Configuration
-------------
The configuration file is called 'cas.cfg' or '.casrc' if located in your
$HOME on UNIX-like systems.  The meanings of the sections are as follows:

- PLUGINS: Defines what components to use.
    - cred_checker: Component to use for checking credentials.
      Various checkers include:
        - DemoChecker (default): Simple in-memory checker that responds
          positively only to user 'foo' and password 'password'.
        - LDAPSimpleBindChecker: Attempts simple BIND to LDAP to check
          check account credentials.
    - realm: User realm used to return a CAS user
        - DemoRealm (default): Creates a user based on the username and
          makes up some attributes for demonstration purposes.
        - LDAPRealm: Creates a user with attributes read from an LDAP
          account.
    - ticket_store: Storage for CAS tickets.
        - InMemoryTicketStore: Stores tickets in memory.
        - CouchDBTicketStore: Stores tickets in CouchDB.

