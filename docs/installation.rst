============
Installation
============

.. highlight:: console


#. `Clone the source from GitHub`_
#. `Configure the Python environment`_
#. `Create configuration files`_
#. `Start the service`_

****************************
Clone the source from GitHub
****************************

Use the standard :command:`git clone` command::

    $ git clone 'https://github.com/cwaldbieser/txcas.git'

********************************
Configure the Python environment
********************************
If you are new to `Python`_, this will probably be the most difficult step.
txcas is tested and run on Python v2.7.  Older versions (e.g. v2.6) 
*may* work, but are not recommended.

You can `download Python`_ from the official web site.  If you are running
some flavor of Linux or BSD, your distribution's package manager may provide
a pre-packaged Python.  The official documentation has a helpful
`Setup and Usage`_ section.

.. note::

    Attention Windows users!  In addition to the Python installer available
    from the official web site, there are some alternative bundles.  The
    `ActivePython installer`_ is a great choice for Python on Windows!

----------------------
Fufilling Dependencies
----------------------

.. warning::

    Fufilling dependencies tends to be where the real pain points in any
    software installation are felt.  I apologize in advance.  The good
    news is that you probably only have to do this once to set up a 
    development environment.  If you set up production environments from
    source, make sure you take good notes if this step isn't a smooth
    ride.

The :file:`requirements.txt` file lists all the *Python* dependencies for txcas.
Some Python modules may require dependencies on external system libraries which
may vary depending on your platform.  Installing all the dependencies manually
is not a fun process.

While there is no silver bullet, a lot of work has been done to make satisfying 
dependencies a bit more civilized.  Your package manager may provide python
modules that you can :command:`yum install` or :command:`apt-get install`.

I recommend installing dependencies in a Python virtual environment.  This
keeps all your dependencies isolated from your system Python and any other
Python environments you have.  There is a handy `guide to virtual 
environments`_.

Once I have a virtual environment created and activated, I use `pip`_ to 
install the requirements listed in :file:`requirements.txt`. ::

    $ pip install -r ./requirements.txt

Ideally, you can sit back and relax while the packages are downloaded from 
the `Python Package Index`_ (PyPi) and installed as if by magic.  In practice,
sometimes there are unmet dependencies external to Python that pop up.  You
may not have the traditional build tools for your platform installed.  This
will cause issues if one of the dependencies needs to build a C-extension,
for example.  

Missing external libraries is another common issue.  Sometimes it will be
necessary to install the *devel* version of a library using your package
manager so the header files are available to compile against.

-------------------------
|project| on Raspberry Pi
-------------------------

Since you made it this far, here is an interesting tidbit.  Using the
above technique, I was able to install |project| on a `Raspberry Pi`_!
Using the `Raspbian image`_ I installed the following system packages
usinig :command:`apt-get install`:

* python-dev
* libffi-dev
* python-virtualenv
* virtualenvwrapper
* vim
* git
* htop

The first 2 were the only actual dependencies I needed to install.  The
`python-virtualenv` and `virtualenvwrapper` packages are just for working
with Python virtual environments (see above).  :program:`vim` is my editor
of choice when working on a Pi, :program:`git` is needed to clone the |project|
source, and :program:`htop` is just fun to watch once |project| is up and 
running!

**************************
Create configuration files
**************************

In the project directory, copy :file:`cas.cfg.example` to :file:`cas.cfg`.
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

You may need to make additional configuration changes depending on the plugins
you enable.  For example, if you use the JSON service registry plugin, you
will need to create a service registry file.  
:file:`serviceRegistry.json.example` is included in the project root as a
starting point.

*****************
Start the service
*****************

The service is started and stopped with the :program:`twistd` program included 
with the Twisted networking library.  This program is used run a 
`Twisted Application`_.  The simplest invocation of this command is to provide
the necessary application configuration in a :term:`TAC file`, which is a
regular Python code file.

The :program:`twistd` command can also to be used to configure services from
the command line.  In this case, the CAS service can be run as a 
:program:`twistd` sub-command, and options specified on the command line will 
override options specified in configuration files.

--------------------------------------------
Running the Service as a Twisted Application
--------------------------------------------

Start the service by invoking the :command:`twistd` command::

    $ twistd -n -y cas.tac

The above command runs the application in the foreground.  If you want to run the
service as a daemon (background service), omit the :option:`-n` option.

------------------------------------------
Running the Service as a twistd Subcommand
------------------------------------------

You can run the service using the `cas` subcommand to :command:`twistd`.
Running the service this way allows you to specify options on the command
line or inspect the online help.::

    $ twistd -n cas

Again, the :option:`-n` option runs the service in the foreground.  To run it as
a daemon process, omit that option.  If you specify the :option:`--help` option
after the `cas` subcommand, the program will output a list of options.


.. _Using the Twisted Application Framework: http://twistedmatrix.com/documents/current/core/howto/application.html
.. _Twisted Application: http://twistedmatrix.com/documents/current/core/howto/basics.html
.. _Python: https://www.python.org/
.. _download Python: https://www.python.org/downloads/
.. _Setup and Usage: https://docs.python.org/2/using/index.html
.. _ActivePython installer: http://www.activestate.com/activepython
.. _guide to virtual environments: http://docs.python-guide.org/en/latest/dev/virtualenvs/
.. _pip: http://pip.readthedocs.org/en/latest/index.html
.. _Python Package Index: https://pypi.python.org/pypi
.. _Raspberry Pi: http://www.raspberrypi.org/
.. _Raspbian image: http://www.raspberrypi.org/downloads/

.. include:: placeholders.rst

