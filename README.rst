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

