# A CAS server implemented with Twisted #

The protocol: http://www.jasig.org/cas/protocol


## How to use it ##

Change `sample.tac` then run with:

    twistd -n -y sample.tac

It's Friday afternoon, and I need to leave, but here's a hacky way to use it:

 - Go to http://127.0.0.1:8080/login?service=https://www.google.com
 - After logging in (username: 'foo', password: 'password') you will be
   redirected to https://www.google.com  And if www.google.com was aware
   of the request, it would validate it and know that you're "foo".