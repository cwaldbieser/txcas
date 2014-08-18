==============
View Providers
==============

View provider plugins render the user facing web pages in txcas.
These include:

* The login page
* The successful login to SSO page
* The logout page
* The invalid service page
* The error page
* The resource not found page

If a service manager is enabled, a reference to it is given to a view provider
so that a service entry is made available to the *login page* and *invalid 
service* views.

A view provider does not have to provide every view.  If it does not provide
a particular view, the default txcas view will be presented.

A view provider is enabled by setting the :option:`view_provider` option
in the `PLUGINS` section of the main configuration file.
Valid options include:

* `jinja2_view_provider`: This view provider renders HTML pages from `Jinja2`_
  templates.  The `request` object is made available to all templates.  The 
  following names are made available to each view:

  * *login page*

    * `login_ticket`: A login ticket that must be POSTed when presenting 
      credentials.

    * `service`: The service requesting authentication.  May be an empty
      string, indicating the user is trying to log into a CAS :term:`SSO`
      session without logging into a service.

    * `service_entry`: The complete service entry from the service manager.

    * `failed`: True / False, indicates if previously submitted credentials 
      failed.

    * `request`

  * *successful login*

    * `avatar`: The avatar provided by the user realm.

    * `request`

  * *logout*

    * `request`

  * *invalid service*

    * `service`: The service requesting authentication.

    * `service_entry`: The complete service entry from the service manager.

    * `request`

  * *error*

    * `err`: The failure object.

    * `request`

  * *not found*

    * `request`

  The plugin options can be configured by appending a colon to this option and
  providing colon-separated key=value pairs *or* by configuring options in the
  *Jinja2ViewProvider* section of the main config file (the latter method is 
  preferred).

  The *Jinja2ViewProvider* options are:

  * :option:`template_folder`: The path to the folder that will contain the
    templates.  The templates should be named: 
    
    * :file:`login.jinja2`
    * :file:`login_success.jinja2` 
    * :file:`logout.jinja2`
    * :file:`invalid_service.jinja2` 
    * :file:`error_5xx.jinja2`
    * :file:`not_found.jinja2`


.. _Jinja2: http://jinja.pocoo.org/docs/
