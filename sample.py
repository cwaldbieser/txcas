

SERVER_PATH='cas'

#Standard library
import cgi
from textwrap import dedent
from urllib import urlencode

#Application modules
from txcas.server import escape_html

# External modules
from klein import Klein
from twisted.web import microdom
from twisted.web.client import getPage


def custom_login(ticket, service, request):
    """
    """
    service_lookup = {
        'http://127.0.0.1:9801/landing': 'Cool App #1',
        'http://127.0.0.1:9802/landing': 'Awesome App #2',
        'http://127.0.0.1:9803/landing': 'Super Secure App #3',
    }
    top = dedent('''\
        <!DOCTYPE html>
        <html>
            <body>
                <h1>CAS Login - %(service_name)s</h1>
                <form method="post" action="">
                    Username: <input type="text" name="username" />
                    <br />Password: <input type="password" name="password" />
                    <input type="hidden" name="lt" value="%(lt)s" />
        ''')
    middle = '            <input type="hidden" name="service" value="%(service)s" />'
    bottom = dedent('''\
                    <input type="submit" value="Sign in" />
                </form>
            </body>
        </html>
        ''') 
    parts = [top]
    if service != "":
        parts.append(middle)
    parts.append(bottom)
    template = '\n'.join(parts)    
    return template % {
        'lt': cgi.escape(ticket),
        'service': cgi.escape(service),
        'service_name': cgi.escape(service_lookup.get(service, "SSO Login"))
    }

class MyApp(object):

    app = Klein()


    def __init__(self, color, cas_root, allow_sso=True, act_as_proxy=False):
        self.color = color
        self.cas_root = cas_root
        self.allow_sso = allow_sso
        self.act_as_proxy = act_as_proxy
        self._ious = {}

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

    @app.route('/landing', methods=['GET'])
    def landing_GET(self, request):
        log.msg("landing_GET()")
        try:
            ticket = request.args['ticket'][0]
        except (KeyError, IndexError):
            return 'Invalid login attempt'
        if not ticket:
            return 'Invalid login attempt'

        url = self.cas_root + '/serviceValidate'
        q = {
            'service': str(request.URLPath()),
            'ticket': ticket,
        }
        if not self.allow_sso:
            q['renew'] = True
        if self.act_as_proxy:
            if request.isSecure():
                scheme = "https://"
            else:
                scheme = "http://"
            host = request.getHost()
            netloc = "%s:%d" % (host.host, host.port)
            q['pgtUrl'] = scheme + netloc + '/proxycb'
        params = urlencode(q)
        url += '?' + params

        d = getPage(url)
        def gotResponse(response):
            log.msg("gotResponse()")
            log.msg(response)
            doc = microdom.parseString(response)
            elms = doc.getElementsByTagName("cas:authenticationSuccess")
            log.msg(elms)
            valid = False
            pgt = None
            if len(elms) > 0:
                valid = True
                elms = doc.getElementsByTagName("cas:user")
                if len(elms) > 0:
                    elm = elms[0]
                    username = elm.childNodes[0].value
                elms = doc.getElementsByTagName("cas:proxyGrantingTicket")
                if len(elms) > 0:
                    elm = elms[0]
                    iou = elm.childNodes[0].value
                    pgt = None
                    if iou in self._ious:
                        pgt = self._ious[iou]
                        del self._ious[iou] 
                    else:
                        log.error("Could not corrolate PGTIOU '%s'." % iou)
            if not valid:
                raise Exception('Invalid login')
            session = request.getSession()
            session.username = username
            if pgt is not None:
                session.pgt = pgt
                log.msg("PGT added to session '%s'." % pgt)
            request.redirect(request.URLPath().sibling('').path)    

        def eb(err):
            log.msg("eb()")
            log.msg('error: %s' % (err,))
            return 'Invalid login attempt'

        return d.addCallback(gotResponse).addErrback(eb)
        
    @app.route('/landing', methods=['POST'])
    def landing_POST(self, request):
        doc = microdom.parseString(request.content.read())
        elms = doc.getElementsByTagName("samlp:SessionIndex")
        if len(elms) > 0:
            elm = elms[0]
            st = elm.childNodes[0].value
            log.msg("Received POST SLO with Session Index '%s'." % st)

    @app.route('/proxycb', methods=['GET'])
    def proxycb_GET(self, request):
        pgtId = request.args.get('pgtId', [None])[0]
        pgtIou = request.args.get('pgtIou', [None])[0]
        if (pgtId is not None) and (pgtIou is not None):
            self._ious[pgtIou] = pgtId
        return "OK"

    @app.route('/pgtinfo', methods=['GET'])
    def pgtinfo_GET(self, request):
        session = request.getSession()
        if hasattr(session, 'pgt'):
            return "PGT == %s" % escape_html(session.pgt)
        else:
            return "No PGT"

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
app2 = MyApp('#cfc', 'http://127.0.0.1:9800', act_as_proxy=True)
reactor.listenTCP(9802, Site(app2.app.resource()))

# app 3
app3 = MyApp('#abc', 'http://127.0.0.1:9800', allow_sso=False)
reactor.listenTCP(9803, Site(app3.app.resource()))

reactor.run()

