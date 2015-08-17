=============
Demonstration
=============

The program :program:`sample.py` included in the txcas project root can spin up
a CAS service and 4 simple service providers to demonstrate various aspects
of the CAS protocol.  Once you have successfully installed the txcas software,
you can run the demonstration with the following command::

    $ python ./sample.py

You should see log entries that indicate the ports on which the services are listening.
The ports are:

* 9800: The CAS service.
* 9801: Service 1.  A basic service that will be used as the middle of a proxy chain.
* 9802: Service 2.  A more advanced service that can obtain a :term:`PGT` and 
  act as a proxy.
* 9803: Service 3.  A basic service that requires primary credentials and does 
  not participate in :term:`SSO`.
* 9804: Service 4.  A basic service.

The demonstration will run without any configuration files.  By default, the 
following plugins will be selected:

* Credential checker: In-memory database with user 'foo' and password 'password'.
* User realm: A demonstration realm that produces made-up attributes.
* Ticket store: An in-memory ticket store.

The demonstration also customizes the CAS views to some extent, but does not 
use a view provider or service manager.

-----------------
Take The CAS Tour
-----------------
Point a browser to service 1 at http://127.0.0.1:9801/ . You will be 
redirected to the CAS server to log in. Use 'foo' and 'password' as the 
credentials and you will be redirected back to the service. You will see you 
are now logged in as 'foo'.

The log being printed to the console will have printed out the /proxyValidate 
XML response, including some (ficticious) attributes that were added to the 
avatar by the demonstration user realm.

If you point your browser to service 2 at http://127.0.0.1:9802/, your SSO 
session provided by the CAS ticket granting cookie (TGC) will have 
transparently allowed you to log into 
the second service without having to re-enter crdentials.

Service 2 will also allow you to proxy service 1, which will in turn proxy 
service 4. The result returned will show the complete proxy chain.

Service 3 requires you to use primary credentials to log in.

------------------------------------
Experimenting With the Demonstration
------------------------------------

The demonstration program honors any plugin and option settings made in the main
txcas configuration file.  You can try out plugins and options with the demo 
services.  If you run :program:`sample.py` with the :option:`--no-cas` command line 
option, the services will be started *without* the CAS service.  You can run
the CAS service in another console and observe how the program interact.  The
:option:`--cas-base-url` option lets you specify the base CAS service URL.  This
is useful if you want to run the CAS service on a different host and/or port.


