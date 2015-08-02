===========
User Realms
===========

In txcas, a user realm is a component that translates an authenticated
avatarID into an :term:`avatar` that implements the `ICASUSer` interface.  The CAS
service will use this object when determining the username and attributes
that should be sent to a service provider during a `/serviceValidate` or
`/proxyValidate` request.  A user realm object will implement the 
`Twisted Cred`_ `IRealm` interface.

The separation of authentication and :term:`avatar` generation allows avatars
to be populated with attributes that are not neccessarilly available via the
authentication provider.  For example, txcas could be configured to authenticate
against a file-based password database, but the avatar could be populated with
attributes retrieved from a web-based service or an LDAP directory.

A realm is enabled by setting the :option:`realm` option of the `PLUGINS` 
section in the main configuration file.
The realm options included in txcas are:

* :option:`demo_realm`: A realm created for demonstration purposes.  The
  avatar is constructed directly from the avatarID (username) provided and
  populated with phony attributes.

* :option:`basic_realm`: This realm is very basic and suitable for situations
  where attribute release is not needed.  In this case, CAS acts as a pure
  authenticator, and service providers must base access control decisions
  entirely on the avatar username.

* :option:`ldap_realm`: This realm constructs the avatar by BINDing to a LDAP
  directory and retrieving a set of possible attributes.

  The LDAP options can be configured by appending a colon to this option and
  providing colon-separated key=value pairs *or* by configuring options in the
  LDAP section of the main config file (the latter method is preferred).

  Currently, the transport is encrypted after the initial connection is made
  using `STARTTLS`_.

  The LDAP options are:

  * :option:`endpointstr`: A `Twisted endpoint`_ specification describing the
    client connection to the LDAP service.
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
    avatar generation will fail.  txcas will report this as an authentication
    failure to end users, though the logs should be helpful in determining the 
    reason.
  * :option:`attribs`: A comma separated list of attributes that the realm
    should attempt to populate during avatar generation.
  * :option:`aliases`: A comma separated list of aliases that is the same 
    length as the :option:`attribs` option.  Each attribute fetched will
    be mapped to the alias name indicated.
  * :option:`service_based_attribs`: 1 (Tue) or 0 (False).  Defaults to False.
    If this option is selected *and* a service manager plugin is used, the
    service entry for the current service will be used to look up a list
    of attributes or a mapping of attributes-to-aliases.  Whether a list or
    a mapping, the data should be located under the **attributes** key of the
    service registry entry.  If that key is not present for a particular entry
    the :option:`attribs` and :option:`aliases` options above will be used to
    compute the attributes to add to the realm.

If you have added additional plugins to your :file:`$TXCAS/twisted/plugins` 
folder, additional option values may be available.  The plugin documentation 
should cover these.  You can also list the available plugins with the following
command::

    $ twistd -n cas --help-realms


.. _Twisted Cred: https://twistedmatrix.com/documents/14.0.0/core/howto/cred.html
.. _Twisted endpoint: https://twistedmatrix.com/documents/current/core/howto/endpoints.html#clients
.. _STARTTLS: http://en.wikipedia.org/wiki/STARTTLS
