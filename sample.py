SERVER_PATH='cas'

import cgi
from textwrap import dedent

# app
from klein import Klein
from twisted.web.client import getPage
from urllib import urlencode

def custom_login(ticket, service, request):
    """
    """
    service_lookup = {
        'http://127.0.0.1:9801/landing': 'Cool App #1',
        'http://127.0.0.1:9802/landing': 'Awesome App #2',
    }
    return dedent('''\
        <!DOCTYPE html>
        <html>
            <body>
                <h1>CAS Login - %(service_name)s</h1>
                <form method="post" action="">
                    Username: <input type="text" name="username" />
                    <br />Password: <input type="password" name="password" />
                    <input type="hidden" name="lt" value="%(lt)s" />
                    <input type="hidden" name="service" value="%(service)s" />
                    <input type="submit" value="Sign in" />
                </form>
            </body>
        </html>
        ''') % {
            'lt': cgi.escape(ticket),
            'service': cgi.escape(service),
            'service_name': cgi.escape(service_lookup.get(service, "SSO Login"))
        }

class MyApp(object):

    app = Klein()


    def __init__(self, color, cas_root):
        self.color = color
        self.cas_root = cas_root

    @app.route('/')
    def index(self, request):
        session = request.getSession()
        print request.sitepath
        me = request.URLPath().child('landing')
        service = request.URLPath().path
        return '''<html>
        <body style="background: %(color)s">
            Welcome to the app.
            <br />You are logged in as: %(user)s
            <br /><a href="%(cas_root)s/login?service=%(service)s">Click here to login</a>.
        </body>
        </html>''' % {
            'cas_root': self.cas_root,
            'service': str(request.URLPath().child('landing')),
            'user': getattr(request.getSession(), 'username', '(nobody)'),
            'color': self.color,
        }

    @app.route('/landing')
    def landing(self, request):
        try:
            ticket = request.args['ticket'][0]
        except (KeyError, IndexError):
            return 'Invalid login attempt'
        if not ticket:
            return 'Invalid login attempt'

        url = self.cas_root + '/serviceValidate'
        params = urlencode({
            'service': str(request.URLPath()),
            'ticket': ticket,
        })
        url += '?' + params
        print params

        d = getPage(url)
        def gotResponse(response):
            print response
            if response.find("<cas:authenticationSuccess>") != -1:
                valid = True
                for line in response.split("\n"):
                    line = line.strip()
                    if line.startswith("<cas:user>"):
                        username = line[10:-11]
                        break
            if not valid:
                raise Exception('Invalid login')
            session = request.getSession()
            session.username = username
            request.redirect(request.URLPath().sibling('').path)    

        def eb(err):
            log.msg('error: %s' % (err,))
            return 'Invalid login attempt'

        return d.addCallback(gotResponse).addErrback(eb)
        

# server
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from txcas.server import ServerApp, InMemoryTicketStore, UserRealm

checker = InMemoryUsernamePasswordDatabaseDontUse(foo='password')

page_views = {'login': custom_login}
#page_views = None
server_app = ServerApp(InMemoryTicketStore(), UserRealm(), [checker], lambda x:True,
                       requireSSL=False, page_views=page_views)


# combines server/app
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.python import log
import sys
log.startLogging(sys.stdout)

# cas server
reactor.listenTCP(9800, Site(server_app.app.resource()))

# app 1
app1 = MyApp('#acf', 'http://127.0.0.1:9800')
reactor.listenTCP(9801, Site(app1.app.resource()))

# app 2
app2 = MyApp('#cfc', 'http://127.0.0.1:9800')
reactor.listenTCP(9802, Site(app2.app.resource()))

reactor.run()

