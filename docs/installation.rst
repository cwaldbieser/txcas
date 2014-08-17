============
Installation
============

.. highlight:: console

--------------------------------------------
Running the Service as a Twisted Application
--------------------------------------------

#. `Clone the source from GitHub`_
#. `Create configuration files`_
#. `Start the service`_

Clone the source from GitHub
****************************
Use the standard :command:`git clone` command::

    $ git clone 'https://github.com/cwaldbieser/txcas.git'

Create configuration files
**************************
In the project directory copy :file:`cas.cfg.example` to :file:`cas.cfg`.
Edit the file and change the settings to suit your needs.
Copy :file:`cas.tac.example` to :file:`cas.tac`.  Edit the file to configure the
endpoint (host, port, SSL options) on which the service will run.::

    $ cd txcas
    $ cp cas.cfg.example txcas.cfg
    $ vim txcas.cfg
    $ cp cas.tac.example cas.tac
    $ vim cas.tac

.. note::

    The :file:`cas.tac` file is a Twisted Application Configuration (TAC) file.
    It is essentially a Python file used for configuring a Twisted Application.
    As such, it needs to conform to Python syntax.  The :file:`cas.tac` file has
    deliberately been kept very simple so configuration is not confusing for
    users who don't have a lot of familiarity with Python.  Python enthusiasts
    should feel free to experiment with adding settings to this file.
    See `Using the Twisted Application Framework`_ for more information.

Start the service
*****************

Start the service by invoking the :command:`twistd` command::

    $ twistd -n -y cas.tac

The above command runs the application in the foreground.  If you want to run the
service as a daemon (background service), omit the :option:`-n` option.

------------------------------------------
Running the Service as a twistd Subcommand
------------------------------------------

You can run the service using the `cas` subcommand to :command:`twistd`.
Running the service this way allows you to specify options on the command
line or inspet the online help.::

    $ twistd -n cas

Again, the :option:`-n` option runs the service in the foreground.  To run it as
a daemon process, omit that option.  If you specify the :option:`--help` option
after the `cas` subcommand, the program will output a list of options.


.. _Using the Twisted Application Framework: http://twistedmatrix.com/documents/current/core/howto/application.html


