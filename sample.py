#! /usr/bin/env python

from __future__ import print_function
import argparse
import cgi
from textwrap import dedent
from urllib import urlencode
import sys
from txcas.constants import (
    VIEW_LOGIN, 
    VIEW_LOGIN_SUCCESS, 
    VIEW_LOGOUT, 
    VIEW_INVALID_SERVICE,
    VIEW_ERROR_5XX,
    VIEW_NOT_FOUND)
from txcas.interface import (
    IRealmFactory,
    IServiceManagerFactory,
    ITicketStoreFactory)
from txcas.server import escape_html
import txcas.settings
from klein import Klein
from twisted.python import log
from twisted.web import microdom
from twisted.web.client import getPage

def custom_login(ticket, service, failed, request):
    service_lookup = {
        'http://127.0.0.1:9801/landing': 'Cool App #1',
        'http://127.0.0.1:9802/landing': 'Awesome App #2',
        'http://127.0.0.1:9803/landing': 'Super Secure App #3',
        'http://127.0.0.1:9804/landing': 'Just Another App #4',
    }
    top = dedent('''\
        <!DOCTYPE html>
        <html>
            <body>
                <h1>CAS Login - %(service_name)s</h1>
        ''')
    failblurb = dedent('''\
                <p>Login Failed.  Try again.</p>
        ''')
    formtop = dedent('''\
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
    if failed:
        parts.append(failblurb)
    parts.append(formtop)
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

    def __init__(
            self, color, cas_root, allow_sso=True, 
            act_as_proxy=None, act_as_link_in_proxy_chain=None):
        self.color = color
        self.cas_root = cas_root
        self.allow_sso = allow_sso
        self.act_as_proxy = act_as_proxy
        self._ious = {}
        self.act_as_link_in_proxy_chain = act_as_link_in_proxy_chain

    @app.route('/')
    def index(self, request):
        session = request.getSession()
        me = request.URLPath().child('landing')
        service = request.URLPath().path
        if self.act_as_proxy is not None:
            parts = ["""<li><a href="/pgtinfo">Click here to see your current PGT.</a>.</li>"""]
            parts.append("""<li><a href="/proxy-a-service">This service will proxy another service.</a>.</li>""")
            parts.append("""<li><a href="/proxy-a-service-mismatch">This service will proxy another, but the PT will be requested (erroneously) with a different URL than the service for which it is presented.</a>.</li>""")
            parts.append("""<li><a href="/badproxyticket">Make a bad request for a proxy ticket.</a>.</li>""")
            pgt_markup = '\n'.join(parts)
        else:
            pgt_markup = ""
        return '''<html>
        <body style="background: %(color)s">
            Welcome to the app.
            <br />You are logged in as: %(user)s
            <ul>
                <li><a href="%(cas_root)s/login?service=%(service)s">Click here to login</a>.</li>
                <li><a href="%(cas_root)s/login?service=%(service)s&renew=true">Click here to login, forcing the login page.</a>.</li>
                <li><a href="%(cas_root)s/login?service=%(service)s&gateway=true">Click here to login, using SSO or failing.</a>.</li>
                <li><a href="%(cas_root)s/login">Click here to login to an SSO session (no service)</a>.</li>
                %(pgt_markup)s
                <li><a href="%(cas_root)s/logout?service=%(logout_service)s">Click here to logout of your SSO session.</a>.</li>
            </ul>
        </body>
        </html>''' % {
            'cas_root': self.cas_root,
            'service': str(request.URLPath().child('landing')),
            'logout_service': request.URLPath().here(),
            'user': getattr(request.getSession(), 'username', '(nobody)'),
            'color': self.color,
            'pgt_markup': pgt_markup,
        }

    @app.route('/landing', methods=['GET'])
    def landing_GET(self, request):
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
        if self.act_as_proxy is not None:
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
            log.msg(response)
            doc = microdom.parseString(response)
            elms = doc.getElementsByTagName("cas:authenticationSuccess")
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
                        log.msg("[WARNING] Could not corrolate PGTIOU '%s'." % iou)
            if not valid:
                raise Exception('Invalid login')
            session = request.getSession()
            session.username = username
            if pgt is not None:
                session.pgt = pgt
                log.msg("PGT added to session '%s'." % pgt)
            request.redirect(request.URLPath().sibling('').path)    

        def eb(err):
            log.err(err)
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
        return "ACK"

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

    @app.route('/proxy-a-service', methods=['GET'])
    def proxy_a_service_GET(self, request):
        return self._proxy_a_service(request)

    @app.route('/proxy-a-service-mismatch', methods=['GET'])
    def proxy_a_service_mismatch_GET(self, request):
        return self._proxy_a_service(request, service_mismatch="http://fail.example.com/")

    def _proxy_a_service(self, request, service_mismatch=None):
        act_as_proxy = self.act_as_proxy
        proxied_service = act_as_proxy['service']
        request_service_endpoint = act_as_proxy['request_service_endpoint']
        if proxied_service is None:
            return dedent("""\
                <html>
                    <head><title>Not Configured to Proxy a Service</title></head>
                    <body style="background: %(color)s">
                        <h1>Not Configured to Proxy a Service</h1>
                        <p>
                        This service is not configured to proxy a service.
                        </p>
                        <p>
                        <a href="/">Back</a>
                        </p>
                    </body>
                </html>
                """) % {'color': self.color}
        session = request.getSession()
        if hasattr(session, 'pgt'):
            
            def parsePT(result):
                log.msg(result)
                doc = microdom.parseString(result)
                elms = doc.getElementsByTagName("cas:proxySuccess")
                if len(elms) == 0:
                    raise Exception("Error parsing PT")
                elms = doc.getElementsByTagName("cas:proxyTicket")
                if len(elms) == 0:
                    raise Exception("Error parsing PT")
                elm = elms[0]
                pt = elm.childNodes[0].value
                return pt
                
            def requestService(pt, proxied_service, request_service_endpoint):
                q = {
                    'ticket': pt,
                }
                url = request_service_endpoint + '?' + urlencode(q)
                d = getPage(url)
                return d
                
            def printResult(result):
                return dedent("""\
                    <html>
                        <head><title>Proxy a Service</title></head>
                        <body style="background: %(color)s">
                            <h1>Proxy a Service</h1>
                            <p>
                            Proxying service at: %(proxied_service)s
                            </p>
                            <pre>
                    %(result)s
                            </pre>
                            <p>
                            <a href="/">Back</a>
                            </p>
                        </body>
                    </html>
                    """) % {
                        'color': self.color,
                        'result': escape_html(result), 
                        'proxied_service': escape_html(proxied_service)}
                    
            def printError(err):
                log.err(err)
                return dedent("""\
                    <html>
                        <head><title>Proxy a Service - Error</title></head>
                        <body style="background: %(color)s">
                            <h1>Proxy a Service - Error</h1>
                            <p>
                            Errors occured while proxying service at: %(proxied_service)s
                            </p>
                            <pre>
                    %(result)s
                            </pre>
                            <p>
                            <a href="/">Back</a>
                            </p>
                        </body>
                    </html>
                    """) % {
                        'color': self.color,
                        'result': escape_html(str(err.getErrorMessage())), 
                        'proxied_service': escape_html(proxied_service)}
            url = self.cas_root + '/proxy'
            q = {
                'targetService': service_mismatch or proxied_service,
                'pgt': session.pgt,
            }
            url += '?' + urlencode(q)
            d = getPage(url)
            d.addCallback(parsePT)
            d.addCallback(
                    requestService, 
                    proxied_service, 
                    request_service_endpoint)
            d.addCallback(printResult) 
            d.addErrback(printError)
            return d
        else:
            return dedent("""\
                <html>
                    <head><title>No PGT</title></head>
                    <body style="background: %(color)s">
                        <h1>No PGT</h1>
                        <p>
                        <a href="/">Back</a>
                        </p>
                    </body>
                </html>
                """) % {
                    'color': self.color,}

    @app.route('/badproxyticket', methods=['GET'])
    def badproxyticket_GET(self, request):
        pgt = 'PGT-bogus'
        def printResult(result):
            return dedent("""\
                <html>
                    <head><title>/proxy Result</title></head>
                    <body style="background: %(color)s">
                        <h1>/proxy Result</h1>
                        <pre>
                %(result)s
                        </pre>
                        <p>
                        <a href="/">Back</a>
                        </p>
                    </body>
                </html>
                """) % {
                    'color': self.color,
                    'result': escape_html(result)}
        url = self.cas_root + '/proxy'
        q = {
            'targetService': 'foo',
            'pgt': pgt,
        }
        url += '?' + urlencode(q)
        d = getPage(url)
        d.addCallback(printResult) 
        return d

    @app.route('/acceptproxyticket', methods=['GET'])
    def acceptproxyticket_GET(self, request):
        act_as_link_in_proxy_chain = self.act_as_link_in_proxy_chain
        if act_as_link_in_proxy_chain is not None:
            proxied_service = act_as_link_in_proxy_chain['service']
            request_service_endpoint = act_as_link_in_proxy_chain['request_service_endpoint']
        try:
            ticket = request.args['ticket'][0]
        except (KeyError, IndexError):
            request.setResponseCode(400)
            return 'Bad request'
        if not ticket:
            request.setResponseCode(400)
            return 'Bad request'
        url = self.cas_root + '/proxyValidate'
        q = {
            'service': str(request.URLPath().sibling("landing")),
            'ticket': ticket,
        }
        if act_as_link_in_proxy_chain is not None:
            q['pgtUrl'] = str(request.URLPath().sibling("proxycb"))
        params = urlencode(q)
        url += '?' + params

        def requestPT(result, proxied_service):
            doc = microdom.parseString(result)
            elms = doc.getElementsByTagName("cas:authenticationSuccess")
            valid = False
            pgt = None
            if len(elms) == 0:
                log.msg("[WARNING] CAS authentication failed.  Result was:\n%s" % str(result))
                raise Exception("CAS authentication failed.")
            elms = doc.getElementsByTagName("cas:proxyGrantingTicket")
            if len(elms) == 0:
                log.msg("[WARNING] No PGT IOU was supplied.  Result was:\n%s" % str(result))
                raise Exception("No PGT IOU was supplied.")
            elm = elms[0]
            iou = elm.childNodes[0].value
            pgt = None
            if iou in self._ious:
                pgt = self._ious[iou]
                del self._ious[iou] 
            else:
                log.msg("[WARNING] Could not corrolate PGTIOU '%s'." % iou)
                raise Exception("Could not corrolate PGTIOU.")
            # Request the PT.
            url = self.cas_root + '/proxy'
            q = {
                'targetService': proxied_service,
                'pgt': pgt,
            }
            url += '?' + urlencode(q)
            d = getPage(url)
            return d
            
        def proxyService(result, request_service_endpoint, proxied_service):
            #Parse the PT.
            doc = microdom.parseString(result)
            elms = doc.getElementsByTagName("cas:proxySuccess")
            if len(elms) == 0:
                raise Exception("Error parsing PT")
            elms = doc.getElementsByTagName("cas:proxyTicket")
            if len(elms) == 0:
                raise Exception("Error parsing PT")
            elm = elms[0]
            pt = elm.childNodes[0].value
            # Make the request
            q = {
                'service': proxied_service,
                'ticket': pt,
            }
            url = request_service_endpoint + '?' + urlencode(q)
            d = getPage(url)
            return d

        d = getPage(url)
        if act_as_link_in_proxy_chain is not None:
            d.addCallback(requestPT, proxied_service)
            d.addCallback(proxyService, request_service_endpoint, proxied_service)
        return d


def main(args):
    run_cas_server = not args.no_cas
    cas_base_url = args.cas_base_url
    if run_cas_server:
        # server
        from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
        from twisted.cred.strcred import ICheckerFactory
        from txcas.server import ServerApp

        page_views = {VIEW_LOGIN: custom_login}
        # Load the config.
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas', defaults={
                'PLUGINS': {
                    'cred_checker': 'DemoChecker',
                    'realm': 'demo_realm',
                    'ticket_store': 'memory_ticket_store',}})
        # Choose plugin that implements IServiceManager.
        service_manager = None
        if scp.has_option('PLUGINS', 'service_manager'):
            tag_args = scp.get('PLUGINS', 'service_manager')
            parts = tag_args.split(':')
            tag = parts[0]
            args = ':'.join(parts[1:])
            factory = txcas.settings.get_plugin_factory(tag, IServiceManagerFactory)
            if factory is None:
                sys.stderr.write("[ERROR] Service manager type '%s' is not available.\n" % tag)
                sys.exit(1)
            service_manager = factory.generateServiceManager(args)
        # Choose plugin that implements ITicketStore.
        tag_args = scp.get('PLUGINS', 'ticket_store')
        parts = tag_args.split(':')
        tag = parts[0]
        args = ':'.join(parts[1:])
        factory = txcas.settings.get_plugin_factory(tag, ITicketStoreFactory)
        if factory is None:
            sys.stderr.write("[ERROR] Ticket store type '%s' is not available.\n" % tag)
            sys.exit(1)
        ticket_store = factory.generateTicketStore(args)
        if service_manager is not None:
            ticket_store.service_manager = service_manager
        # Choose the plugin that implements IRealm.
        tag_args = scp.get('PLUGINS', 'realm')
        parts = tag_args.split(':')
        tag = parts[0]
        args = ':'.join(parts[1:])
        factory = txcas.settings.get_plugin_factory(tag, IRealmFactory)
        if factory is None:
            sys.stderr.write("[ERROR] Realm type '%s' is not available.\n" % tag)
            sys.exit(1)
        realm = factory.generateRealm(args)
        assert realm is not None, "User Realm has not been configured!"
        # Choose plugin(s) that implement ICredentialChecker 
        try:
            tag_args =  scp.get('PLUGINS', 'cred_checker')
        except Exception:
            print("[ERROR] No valid credential checker was configured.")
            sys.exit(1)
        parts = tag_args.split(':')
        tag = parts[0]
        args = ':'.join(parts[1:])
        factories = txcas.settings.get_plugins_by_predicate(
                        ICheckerFactory, 
                        lambda x: x.authType == tag)
        if len(factories) == 0:
            checkers= [InMemoryUsernamePasswordDatabaseDontUse(foo='password')]
        else:
            checkers=[f.generateChecker(args) for f in factories]
        # Service validation func.
        if service_manager is None:
            validService = lambda x:True
        else:
            validService = service_manager.isValidService
        #Create the CAS server app.
        server_app = ServerApp(
            ticket_store, 
            realm, 
            checkers,
            validService,
            requireSSL=False,
            page_views=page_views,
            validate_pgturl=False)
    # combines server/app
    from twisted.web.resource import Resource
    from twisted.web.server import Site
    from twisted.internet import reactor
    from twisted.python import log
    import sys
    log.startLogging(sys.stdout)
    if run_cas_server:
        # cas server
        reactor.listenTCP(9800, Site(server_app.app.resource()))
    # app 1
    app1 = MyApp(
        '#acf', cas_base_url,
        act_as_link_in_proxy_chain={
            'request_service_endpoint': 'http://127.0.0.1:9804/acceptproxyticket',
            'service': 'http://127.0.0.1:9804/landing',})
    reactor.listenTCP(9801, Site(app1.app.resource()))
    # app 2
    app2 = MyApp(
        '#cfc', cas_base_url,
        act_as_proxy={
            'request_service_endpoint': 'http://127.0.0.1:9801/acceptproxyticket',
            'service': 'http://127.0.0.1:9801/landing'})
    reactor.listenTCP(9802, Site(app2.app.resource()))
    # app 3
    app3 = MyApp('#abc', cas_base_url, allow_sso=False)
    reactor.listenTCP(9803, Site(app3.app.resource()))
    # app 4
    app4 = MyApp('#9932CC', cas_base_url)
    reactor.listenTCP(9804, Site(app4.app.resource()))
    reactor.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-cas",
        action='store_true',
        help='Only run the service providers and *not* the CAS service.')
    parser.add_argument(
        "--cas-base-url",
        action="store",
        default='http://127.0.0.1:9800',
        help="The base CAS service URL (default http://127.0.0.1:9800).")
    args = parser.parse_args()
    main(args)
