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
well as a client certificte checker (trust-based authentication).  

A number of credential checkers are available in `Twisted Cred`_  that support  
the username/password credential type.  |project| also includes support for the
ldap_simple_bind credential checker via the `ldaptor`_ library.

---------------------
Authentication Phases
---------------------
It is possible for authentication to happen in one of two distinct phases.
The phase that occurs first is the *credential requestor* (or *cred_requestor*)
phase.  This happens when the user browser makes an HTTP GET request to the
|project| service `/login` endpoint.  At this point, it is possible to attempt
trust-based authentication *before* the login page is rendered.  If successful,
a user will never see the login page.  Username/password based authentication
is not available in this phase as the user has not ye had a chance to enter 
credentials.

The second phase is the *credential acceptor* (or *cred_acceptor*) phase.
This phase happens when the user's browser makes an HTTP POST to the
|project| service `/login` endpoint with a username and password.  **Both**
trust-based authentication and username/password authentication may take
place in this phase.  If a trust-based credential checker is configured to
authenticate during this phase, it will attempt authentication first.  If
successful, the resulting :term:`avatar ID` is compared to the username
that was submitted.  If they do not match, authentication will fail.  
Otherwise, username/password authentication will take place.  Only if **both**
forms of authentication succeed will authentication be successful.

*********************************************
Typical Models For Trust-Based Authentication
*********************************************
Due to the fact that trsut-based authentication can be configure to occur
in either authentication phase, the user experience can vary.

In the **Trust-Only** model, trust based authentication is the only option.
Only a trust-based credential checker is configured.  There is no 
username/password credential checker.  The trust-based checker should be 
configured to occur in the cred_requestor phase.  A user will be authenticated
if her browser has a valid certificate.  If not, an error page would be 
presented.  The user would never see a login page.

The **Trust-or-Login** model, a trust-based checker is enabled in the cred_requestor
phase.  A username/password checker is also enabled (this can *only* occur in 
the cred_acceptor phase).  If the user's browser has a valid certificate, the
user is authenticated transparently as in the "Trust-Only" model.  If not, the
user will be presented with the |project| login view and be able to authenticate
with a username/password.

In the **Trust-and-Login** (a kind of :term:`two factor authentication`), the trust
checker is enabled in the cred_acceptor phase and a username/password checker is
also enabled.  In this case, authentication will *only* succeed if the user's
browser has a valid certificate *and* she enters a valid username/password *and*
the username she supplies matches the :term:`avatar ID` extracted from the
certificate.

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
  the |project| service must run on a SSL/TLS endpoint.  At least one CA 
  certificate that the server will trust for client certificates must be
  specified via the option :option:`--addCA`.  Multiple CAs can be specified, 
  but the user experience may be degraded.  A browser will typically ask the 
  user to select the certificate that ought to be presented to the server if 
  multiple valid options are available.

  The options for this plugin are:

  * :option:`subject_part`: The part of the subject to extract, e.g. "CN",
    or "emailAddress".
  * :option:`transform`: A comma-separated list of 'upper', 'lower',
    'strip_domain'.  One or more transforms are
    applied to the extracted subject part..
  * :option:`auth_when`: The authentication phase when this checker is active.
    Valid options are 'cred_requestor' (default) and 'cred_acceptor'.

If you have added additional plugins to your :file:`$TXCAS/twisted/plugins` 
folder, additional option values may be available.  The plugin documentation 
should cover these.  You can also list the available plugins with the following
command::

    $ twistd -n cas --help-auth


.. _Twisted Cred: https://twistedmatrix.com/documents/14.0.0/core/howto/cred.html
.. _ldaptor: https://github.com/twisted/ldaptor
.. _STARTTLS: http://en.wikipedia.org/wiki/STARTTLS

.. include:: placeholders.rst
