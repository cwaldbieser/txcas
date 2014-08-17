================
Service Managers
================

Service managers are plugin components within txcas that determine whether CAS
will validate tickets for a particular service provider.  Service managers also
determine if services that CAS will validate will participate in CAS :term:`SSO`
sessions.  If a service manager determines that a given service will **not**
participate in :term:`SSO`, then primary credentials will *always* be requested
via the CAS login whenever authentication is requested for that service.

Service managers are free to provide additional information about services.  
This information may be consumed by a view provider plugin, if one is enabled.

Service managers are enabled by setting the :option:`service_manager` option
in the `PLUGINS` section of the main configuration file.
Valid settings for this option include:

* json_service_manager: This service manager stores information in JSON format
  in a file accessible to the txcas service.  The file is read, parsed, and
  represented in memory.  If the file is changed, the service manager will
  detect the change and reload the file contents.

  The options for this plugin can be configured by appending a colon to the 
  option name and providing colon-separated key=value pairs *or* by 
  configuring options in the JSONServiceManager section of the main config 
  file (the latter method is preferred).  

  The JSONServiceManager options are:

  * :option:`path`: The path to the service registry JSON file.

  The format of the the service registry is a list of entries, where each entry
  is a mapping of key-value pairs.  The following keys have special meanings to
  the service manager:

  * `name`: The name of the service.  Used mainly for identification during 
    logging.
  * `scheme`: One of `http`, `https`, or `*`.
  * `netloc`: A value composed of a host or domain pattern, and optionally 
    followed by a colon and a port number.  If the port number is omitted, it
    is inferred by the actual scheme of the service (443 for https, 80 for 
    http).  A host/domain pattern is in dotted notation.  Each component of
    the name may be replaced by an asterisk (*) indicating that component is
    a wildcard match.  If the first component is a double asterisk, that means
    that *any* hostname that ends with the same pattern will match.
  * `path`: The path part of the service URI.
  * `child_paths`: `true` or `false`.  whether to include child paths of
    the path component as matches.  False indicates an exact path match is 
    required.
  * `required_params`: A mapping of required parameters in key:list-of-values
    format or `null`.  If the required parameters and values are not present, 
    the service will not match.
  * `SSO`: `true` or `false`.  If false, CAS will authenticate the service, but
    it will request primary credentials each time.  The service will not 
    participate in :term:`SSO`.




