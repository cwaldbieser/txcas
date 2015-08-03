
=========
Endpoints
=========

A `Twisted server endpoint`_ is the end of the connection on which a service 
listens for incoming requests.  For simple testing and development, the configured
endpoint may be a simple TCP socket.  In a production setting, an SSL endpoint
would be more appropriate.

Server endpoints can be described using a `simple string format`_.  Additionally,
|project| provides the *tls:* endpoint which extends the standard *ssl:* endpoint
with several additional options.

--------------------
TLS Endpoint Options
--------------------

* :option:`sslmethod` : This option is present in the *ssl:* endpoint and allows
  you to set the SSL method (e.g. `TLSv1_METHOD`).  The *tls:* endpoint allows
  you to specify multiple methods joined with '+'.
  E.g. `TLSv1_1_METHOD+TLSv1_2_METHOD`.  Other OpenSSL options may be specified.
  For a complete list, see the `PyOpenSSL documentation`_.
* :option:`authorities` : A path to a file that contains one or more trusted
  CA certificates in PEM format used to verify client certificates.  If this
  option is not specified, client certificates are not verified.
* :option:`revokedFile` : A path to a file that contains glob patterns,
  one per line.  Blank lines and lines starting with "#" are ignored.  The
  files referenced by each pattern should contain one or more revoked client
  certificates in PEM format.  These certificates are no longer trusted by the 
  service, and the SSL/TLS handshake will fail if a client presents one to
  the service.  The file is read once when the service is started.  If
  the file modification time is updated, all the patterns will be re-processed.
  (The \*NIX :command:`touch` command can cause the file to be re-processed
  even if no pattern has been changed).

.. note::

    By default, a TLS endpoint will negotiate one of of TLSv1.1, or TLSv1.2.


.. include:: placeholders.rst

.. _Twisted server endpoint: https://twistedmatrix.com/documents/current/core/howto/endpoints.html
.. _simple string format: https://twistedmatrix.com/documents/current/core/howto/endpoints.html#servers
.. _PyOpenSSL documentation: https://pyopenssl.readthedocs.org
