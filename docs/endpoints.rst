
=========
Endpoints
=========
An endpoint is the end of the connection on which the |project| service listens
and responds to requests.  For simple testing and development, the configured
endpoint may be a simple TCP socket.  In a production setting, an SSL endpoint
would be more appropriate.

------------------------------------------
SSL Endpoint Options for :command:`twistd`
------------------------------------------
A SSL endpoint has many more options that a simple TCP endpoint.  The
`cas` subcommand to :program:`twistd` exposes a number of these configuration
options on the command line.

* :option:`ssl` : Use SSL
* :option:`sslv3` : Use SSLv3 protocol (not recommended as this protocol is broken).
* :option:`no-tlsv1`: Do not use the TLSv1 protocol.
* :option:`no-tlsv1_1`: Do not use the TLSv1.1 protocol.
* :option:`no-tlsv1_2`: Do not use the TLSv1.2 protocol.
* :option:`cert-key` : The path to the server public certificate in PEM format.
* :option:`private-key` : The path to the server private key in PEM format.
* :option:`verify-client-cert` : Arrange for client certificates to be verified
  during the SSL handshake.
* :option:`addCA` : A path to a trusted CA certificate in PEM format used when 
  verifying client certificates.  Multiple CAs may be added by specifying this
  option multiple times.
* :option:`revoked-client-certs` : A path to a file that contains glob patterns,
  one per line.  Blank lines and lines starting with "#" are ignored.  The
  files referenced by each pattern should be PEM format client certificates that 
  have been revoked (are no longer to be trusted) during the SSL handshake client
  verification process.  The file is read once when the service is started.  If
  the file modification time is updated, all the patterns will be re-processed.
  (The \*NIX :command:`touch` command can cause the file to be re-processed
  even if no pattern has been changed).

.. note::

    By default, an SSL endpoint will negotiate one of of TLSv1, TLSv1.1, or TLSv1.2.

-----------------------------------
Endpoint Configuration in TAC files
-----------------------------------
Twisted Application Configuration (TAC) files are Python files that have a `.tac`
extension.  An example TAC file is included for |project|, :file:`cas.tac.example`.
Endpoints can either be configured using a string or by setting various options
in a dictionary.

When configuring an endpoint via a string, the `Twisted server endpoints`_ are used.
The connection string should be passed as the `endpoint_s` argument of the 
`txcas.service.CASService` class constructor.

When configuring an endpoint via dictionary options, a mapping of options should be
passed to the `endpoint_options` argument of the `txcas.service.CASService` class 
constructor.  The two methods of configuration are mutually exclusive.

The endpoint mapping keys are as follows:

* `ssl`: (boolean) Use SSL.
* `ssl_method_options`: (iterable) Strings representing OpenSSL method options (e.g. "OP_NO_SSLv3").
* `verify_client_cert`: (boolean) Verify client certificates during the SSL handshake.
* `port`: (int) The port on which to listen for incoming requests.
* `certKey`: (string) Path to the server certificate (PEM format).
* `privateKey`: (string) Path to the server private key (PEM format).
* `authorities`: (iterable) A list of paths to CA certificates (in PEM format) 
  used for verifying client certificates.  If a client certificate is not signed
  by one of these trusted CAs, the |project| service will not verify the client
  certificate and the SSL handshake will fail.
* `revoked_client_certs`: (iterable) The path to a text file that contains glob
  patterns, one per line.  Blank lines and lines starting with '#' are ignored.
  The files matched by each pattern should be PEM formatted certificates that 
  should no longer be trusted during client certificate verification.


.. include:: placeholders.rst

.. _Twisted server endpoints: https://twistedmatrix.com/documents/current/core/howto/endpoints.html

