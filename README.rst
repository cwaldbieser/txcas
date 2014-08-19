=====================================
A CAS server implemented with Twisted
=====================================

.. highlight:: console

The protocol: http://www.jasig.org/cas/protocol

Full documentation is hosted at http://txcas.readthedocs.org/

--------
Features
--------

* Implements the CAS Protocol required sections (1-3).
* Easy to start/stop service that listens and responds to incoming requests.
  No external web server or web application container required.
* Open source Python code making heavy use of the Twisted networking library.
* Flexible plugin architecture, allowing customization of major architectural
  components.
* Plugins for Authentication (file, unix, LDAP), User Realms (basic, LDAP), 
  Ticket Stores (in-memory, CouchDB), Service Managers (JSON), and
  View Providers (Jinja2 templates).
* Simple configuration.

-------------------------
Running the Demonstration
-------------------------

Run the :program:`sample.py` script as follows::

    $ python sample.py

The CAS server will run on port 9800.
Service 1 runs on port 9801.
Service 2 runs on port 9802.
Service 3 runs on port 9803.
Service 4 runs on port 9804.
All services listen on localhost (127.0.0.1).

-----------
Quick Start
-----------
Copy `cas.cfg.example` to `cas.cfg`.  
Copy `cas.tac.example` to `cas.tac`.  
Then edit the settings in both files.  Run the service with::

    $ twistd -n -y cas.tac

To run as a daemon (in the background even when you log out 
of the shell), omit the `-n` option.

You can also run the server and specify the options 
from the command line.  The following example runs the server
on port 9800.::

    $ twistd -n cas -p 9800

To get a list of all command line options::

    $ twistd -n cas --help

----------
Appearance
----------
The HTML pages presented by txcas are fully customizable via view provider
plugins.  The included Jinja2_ view provider allows you to design pages
using powerful yet easy to use Jinja2 templates (see 
http://jinja.pocoo.org/docs/templates/).

A sample theme using Bootstrap 3 is available at 
https://github.com/cwaldbieser/txcas_extras.
