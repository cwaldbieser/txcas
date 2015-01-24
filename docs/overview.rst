========
Overview
========

The `Central Authentication Service`_ (CAS) is a protocol that allows a single
web site to act as the authentication broker for service providers.
`Twisted`_ is an asyncronous networking library for the `Python`_ programming
language.  Since prefixing project names with "twisted" is somewhat long-ish, 
Twisted Python projects tend toward using the "tx" prefix.  So "txcas" is an
implementation of a CAS server using the Twisted Python library.

--------
Features
--------

* Implements the `CAS Protocol v3.0`_ required sections (1-3).
* Easy to start/stop service that listens and responds to incoming requests.
  No external web server or web application container required.
* Open source Python code making heavy use of the Twisted networking library.
* Flexible plugin architecture, allowing customization of major architectural
  components.
* Plugins for Authentication (file, unix, LDAP, client x509), User Realms 
  (basic, LDAP), Ticket Stores (in-memory, CouchDB), Service Managers (JSON), 
  and View Providers (Jinja2 templates).
* Simple configuration.
* Runs on a `Raspberry Pi`_!

-----------------------
Why Another CAS Server?
-----------------------

The `Apereo Foundation`_ already maintains the reference CAS server 
implementation.  It is robust, well tested, reliable, flexible 
software that has a vibrant community behind it.  So why another server 
implementation?

Ultimately, the reason this project exists is that  I unapologetically love 
programming in Python!  It has been said the Python "fits your brain", and 
in my case, I most certainly agree.  I am also a big fan of the Twisted 
networking library and asynchronous I/O.

I recognize many of the benefits of the `Java programming language`_ and
its associated tool chain, but it is not my software environment
of choice.  I found a basic CAS server written in Python on GitHub.  I 
forked it, and started this project.

Goals
-----
My goals for this project are as follows:

* Produce a working, production quality CAS server that implements all the required
  features of the CAS protocol.  
* Provide a flexible and customizable plugin architecture.  Don't try to include
  every option in the core server.
* Keep the code base simple to learn and understand.
* Keep the administration of the service simple to use.

.. _Central Authentication Service: http://jasig.github.io/cas/4.0.0/index.html
.. _CAS Protocol v3.0: http://jasig.github.io/cas/development/protocol/CAS-Protocol-Specification.html
.. _Python: https://www.python.org/
.. _Twisted: https://twistedmatrix.com/trac/
.. _Apereo Foundation: http://www.apereo.org/
.. _Java programming language: https://www.java.com
.. _Raspberry Pi: http://www.raspberrypi.org/

