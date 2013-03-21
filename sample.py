SERVER_PATH='cas'

# app
from klein import Klein
from twisted.web.client import getPage
from urllib import urlencode

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

        url = self.cas_root + '/validate'
        params = urlencode({
            'service': str(request.URLPath()),
            'ticket': ticket,
        })
        url += '?' + params
        print params

        d = getPage(url)
        def gotResponse(response):
            valid, username, _ = response.split('\n')
            if valid != 'yes':
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


server_app = ServerApp(InMemoryTicketStore(), UserRealm(), [checker], lambda x:True,
                       requireSSL=False)


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

