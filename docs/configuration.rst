=============
Configuration
=============

The txcas service is configured primarilly via a single configuration
file.  The service looks for this file at the following locations:

* :file:`/etc/cas/cas.cfg`
* :file:`$HOME/.casrc`
* :file:`$PWD/cas.cfg`

The configuration options will be loaded, in order, from each of the locations.
Options that appear in multiple locations will be overwritten by the values
that occur later in the search order, so system-wide options will be overridden
by user-specific options, which will be overridden by options specified in the
current woking folder.

This configuration is in a simple INI format.  Options are key-value pairs that
occur one per line.  Keys are separated from values by an equal sign (=).  
Options are grouped into sections, which are denoted by a symbol enclosed by square
brackets ([]).

Sections are:

* `CAS`_: This section contains general options for the service.
* `Plugins`_: This section conatins options used to enable various plugins.
* `Sections Specific to Plugins`_: Some plugins have unique or shared sections
  used for configuration.

CAS
---

This section is used for configuring basic CAS behavior.  Options are:

* :option:`lt_lifespan`: The length of time, in seconds, before a login 
  ticket expires.
* :option:`st_lifespan`: The length of time, in seconds, before a service 
  ticket expires.
* :option:`pt_lifespan`: The length of time, in seconds, before a proxy 
  ticket expires.
* :option:`pgt_lifespan`: The length of time, in seconds, before a proxy 
  granting ticket expires.
* :option:`tgt_lifespan`: The length of time, in seconds, before a ticket 
  granting ticket expires.
* :option:`validate_pgturl`: Validate a `pgtUrl` callback certificate, as per
  the CAS protocol.  Default is 1 (True).
* :option:`ticket_size`: The ticket size in characters.
* :option:`static_dir`: If this option is set to a folder, the cas service will
  serve static content out of this folder to the `/static` resource.

Plugins
-------

This section is used to enable the plugins used for various parts of the service.
The plugin options supported are:

* :option:`cred_checker`: The tag used to determine the mechanism that will
  be used for authenticating the credentials presented to the service.
* :option:`realm`: The tag used to determine the plugin that will create an
  avatar that will be exposed to a service, mainly via attribute release.  A
  realm receives an avatar ID that will have already been autheticated via a
  cred_checker.
* :option:`ticket_store`: The tag used to determine the plugin that will be
  used to manage tickets that CAS uses.
* :option:`service_manager`: The tag used to determine the plugin that will
  be used to determine whether a service is allowed to authenticate with this
  CAS service.  A service manager also determines if the service participates 
  in :term:`SSO`.  Extra information provided in the registry is also made
  available to the view_provider plugin.  If a service manager plugin is not 
  specified, CAS will run in *open* mode, and any service will be allowed to 
  authenticate with this CAS service.
* :option:`view_provider`: The tag used to determine the plugin that will be 
  used to provide customized views of CAS pages.

Sections Specific to Plugins
----------------------------

Some configuration sections are specific to certain plugins.  Some plugins may
also reference shared sections.  For example, the `json_service_manager` plugin
can be configured to use a particular service registry file via the section
`JSONServiceManager`.  The `ldap_simple_bind` cred_checker plugin and the 
`ldap_realm` realm plugin both reference the shared `LDAP` section to obtain
LDAP-specific options.

