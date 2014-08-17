Overview
++++++++

The `Central Authentication Server`_ (CAS) protocol allows a single
web site to act as the authentication broker for service providers.
`Twisted`_ is an asyncronous networking library for the `Python`_ programming
language.  Since prefixing project names with "twisted" is somewhat long-ish, 
Twisted Python projects tend toward using the "tx" prefix.  So "txcas" is an
implementation of a CAS server using the Twisted Python library.

Why Another CAS Server?
-----------------------
The `JASIG consortium`_ already maintains its own `CAS server 
implementation`_  It is robust, well tested, reliable, flexible 
software that has a vibrant community behind it.  So why another server 
implementation?

Ultimately, the reason this project exists is that  I unapologetically love 
programming in Python!  It has been said the Python "fits your brain", and 
in my case, I most certainly agree.  I am also a big fan of the Twisted 
networking library and asynchronous I/O.

I recognize many of the benefits of the `Java programming language`_ and
its associated tool chain, but for me, it is not my software environment
of choice.  I found a basic CAS server written in Python on GitHub.  I 
forked it, and started this project.

Goals
-----
My goals for this project are as follows:

* Produce a working, production quality CAS server that implements all the required
  features of the CAS protocol v2 and v3.  I am not implementing the old `/samlValidate`
  support, as the CAS protocol v3 now supports attribute release.
* Provide a flexible and customizable plugin architecture.  Don't try to include
  every option in the core server.
* Keep the code base simple to learn and understand.
* Keep the administration of the service simple to use.

.. _Central Authentication Server: http://www.jasig.org/cas/protocol
.. _Python: https://www.python.org/
.. _Twisted: https://twistedmatrix.com/trac/
.. _JASIG consortium: http://www.jasig.org/
.. _CAS server implementation: http://www.jasig.org/cas
.. _Java programming language: https://www.java.com

