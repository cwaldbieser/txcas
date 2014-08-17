==============
Authentication
==============

Authentication in txcas is implemented using a plugin system built into
the core Twisted library known as `Twisted Cred`_.  This system is actually
composed of 3 distinct parts: a credential checker, a portal, and a user realm.

The credential checker is the component that accepts primary credentials and
authenticates them.  If successful, it returns an avatarID that the user 
realm will use to produce an :term:`avatar`.

Currently, txcas supports accepting simple username/password credentials.  A
number of credential checkers are available in `Twisted Cred`_  that support this 
credential type.  txcas also includes support for the
ldap_simple_bind credential checker via the `ldaptor`_ library.

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

If you have added additional plugins to your :file:`$TXCAS/twisted/plugins` 
folder, additional option values may be available.  The plugin documentation 
should cover these.  You can also list the available plugins with the following
command::

    $ twistd -n cas --help-auth


.. _Twisted Cred: https://twistedmatrix.com/documents/14.0.0/core/howto/cred.html
.. _ldaptor: https://github.com/twisted/ldaptor
.. _STARTTLS: http://en.wikipedia.org/wiki/STARTTLS
