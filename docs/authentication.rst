==============
Authentication
==============

Authentication in txcas is implemented using a plugin system built into
the core Twisted library known as `Twisted Cred`_.  This system is actually
composed of 3 distinct parts: a credential checker, a portal, and a user realm.

The credential checker is the component that accepts primary credentials and
authenticates them.  If successful, it returns an avatarID that the user 
realm will use to produce an :term:`avatar`.

Currently, txcas supports accepting simple username/password credentials as
well as a client certificte checker.  

A number of credential checkers are available in `Twisted Cred`_  that support  
the username/password credential type.  |project| also includes support for the
ldap_simple_bind credential checker via the `ldaptor`_ library.

Trust-based client certificate authentication occurs during the SSL handshake
when a browser conects to the CAS service, so there is typically no reason
to present a login page.  Authentication either succeeds or fails, typically
with no intervention from the user.  This kind of credential checker deals
mostly with inspecting the certificate presented and extracting the avatar
ID from it.

Both trust-based and username/password checkers can be used simultaneously.
If both are specified on the command line, trust-based authentication will
occur first, and if successful the user s authenticated.  If trust-based 
authentication fails, then the login page is presented for username/password
authentication.

Configuration
-------------
An authentication method is selected via the :option:`cred_checker` option in the
`PLUGINS` section of the main configuration file.  Valid options are:

* :option:`memory`: An in-memory password database suitable for demonstrations 
  and development.  Do **not** use for production!
* :option:`file`: A file containing `username:password` entries, one per line.
  This option should be followed by a colon and the path to the file.  E.g.
  `file:/etc/cas/cas_users.passwd`.
* :option:`unix`: Attempts to authenticate against a user on the local 
  UNIX-like system.
* :option:`ldap_simple_bind`:  Attempts a simple BIND against an LDAP server.
  The LDAP options can be configured by appending a colon to this option and
  providing colon-separated key=value pairs *or* by configuring options in the
  LDAP section of the main config file (the latter method is preferred).

  Currently, the transport is encrypted after the initial connection is made
  using `STARTTLS`_.  A 2-stage BIND is used.  In stage 1, an service DN
  and password are used to BIND in order to serach for the target entry.
  If the target entry is located, this authenticator attempts to BIND using
  the password supplied at the CAS login.

  The LDAP options are:

  * :option:`host`
  * :option:`port`
  * :option:`basedn`
  * :option:`binddn`
  * :option:`bindpw`
  * :option:`query_template`: Defaults to `(uid=%(username)s)`.  The query 
    template is a filter that will be used by the LDAP service to identify
    the entry that it will attempt to BIND as using the supplied password.
    The `%(username)s` part of the filter will be substituted with the provided
    username in order to produce the final filter.  The username will be escaped
    according to LDAP filter rules.  The default template attempts to locate an 
    entry where the `uid` attribute matches the provided username.  If no 
    matching entry is located, or if multiple matching entries are located, 
    authentication will fail.
* :option:`client_cert`: This form of authentication is trust-based and happens
  during a SSL handshake.  In order for this checker to succeed, 
  the |project| service must run on a SSL/TLS endpoint, and the
  :option:`--verify-client-cert` option must be enabled.  At least one
  at least one CA that the server will trust for client certificates via the
  :option:`--addCA` option must be specified.  Multiple CAs can be specified, 
  but the user experience may be degraded if client certificates from multiple 
  CAs are specified.  A browser will typically ask the user to select the certificate
  that ought to be presented to the server if multiple valid options are available.

  The options for this plugin are:

  * :option:`subject_part`: The part of the subject to extract, e.g. "CN",
    or "emailAddress".
  * :option:`transform`: A comma-separated list of 'upper', 'lower',
    'strip_domain'.  One or more transforms are
    applied to the extracted subject part..

If you have added additional plugins to your :file:`$TXCAS/twisted/plugins` 
folder, additional option values may be available.  The plugin documentation 
should cover these.  You can also list the available plugins with the following
command::

    $ twistd -n cas --help-auth


.. _Twisted Cred: https://twistedmatrix.com/documents/14.0.0/core/howto/cred.html
.. _ldaptor: https://github.com/twisted/ldaptor
.. _STARTTLS: http://en.wikipedia.org/wiki/STARTTLS

.. include:: placeholders.rst
