
=========
CHANGELOG
=========

* BUGFIX: URL encoding of service URL query string parameters was not handled 
  properly, resulting in mangled params that would notbe matched to the service
  during a /serviceValidate.

