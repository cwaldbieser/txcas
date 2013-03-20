from twisted.cred.portal import Portal, IRealm
from twisted.cred.credentials import UsernamePassword
from twisted.internet import defer, reactor
from zope.interface import implements

from klein import Klein

from txcas.interface import IUser

from urllib import urlencode

import uuid
import random
import string
import cgi


class InvalidTicket(Exception):
    pass



class ServerApp(object):

    app = Klein()

    
    def __init__(self, ticket_store, realm, checkers, validService=None):
        self.ticket_store = ticket_store
        self.portal = Portal(realm)
        map(self.portal.registerChecker, checkers)
        self.validService = validService or (lambda x: True)


    @app.route('/login', methods=['GET'])
    def login_GET(self, request):
        """
        Present a username/password login page to the browser.
        """
        service = request.args['service'][0]
        d = self.ticket_store.mkLoginTicket(None)
        def render(ticket, service):
            return '''
            <html>
                <body>
                    <form method="post" action="/login">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <input type="hidden" name="lt" value="%(lt)s" />
                        <input type="hidden" name="service" value="%(service)s" />
                    </form>
                </body>
            </html>
            ''' % {
                'lt': cgi.escape(ticket),
                'service': cgi.escape(service),
            }
        return d.addCallback(render, service)


    @app.route('/login', methods=['POST'])
    def login_POST(self, request):
        """
        Accept a username/password, verify the credentials and redirect them
        appropriately.
        """
        service = request.args['service'][0]
        username = request.args['username'][0]
        password = request.args['password'][0]

        def extractUsername(user):
            return user.username

        def mkServiceTicket(username, service):
            return self.ticket_store.mkServiceTicket(username, None)

        def redirect(ticket, service, request):
            query = urlencode({
                'ticket': ticket,
            })
            request.redirect(service + '?' + query)

        def eb(err, service, request):
            query = urlencode({
                'service': service,
            })
            request.redirect('/login?' + query)
            request.setResponseCode(403)

        # check credentials
        credentials = UsernamePassword(username, password)
        d = self.portal.login(credentials, None, IUser)
        d.addCallback(extractUsername)
        d.addCallback(mkServiceTicket, service)
        d.addCallback(redirect, service, request)
        d.addErrback(eb, service, request)
        return d


    @app.route('/validate', methods=['GET'])
    def validate_GET(self, request):
        """
        Validate a service ticket, consuming the ticket in the process.
        """
        ticket = request.args['ticket'][0]
        username = self.ticket_store.useServiceTicket(ticket, None)
        def gotUsername(username):
            return 'yes\n' + username + '\n'
        return username.addCallback(gotUsername)


        




class User(object):

    implements(IUser)

    username = None
    
    def __init__(self, username):
        self.username = username
    


class UserRealm(object):


    implements(IRealm)


    def requestAvatar(self, avatarId, mind, *interfaces):
        return User(avatarId)



class InMemoryTicketStore(object):
    """
    XXX
    """

    lifespan = 10
    charset = string.ascii_letters + string.digits + '-'


    def __init__(self, reactor=reactor):
        self.reactor = reactor
        self._tickets = {}


    def _generate(self, prefix):
        r = prefix
        while len(r) < 256:
            r += random.choice(self.charset)
        return r


    def _mkTicket(self, prefix, data):
        """
        Create a ticket prefixed with C{prefix}

        The ticket will expire after my class' C{lifespan} seconds.

        @param prefix: String prefix for the token.
        @param data: Data associated with this ticket (which will be returned
            when L{_useTicket} is called).
        """
        ticket = self._generate(prefix)
        self._tickets[ticket] = data
        self.reactor.callLater(self.lifespan, self._expireTicket, ticket)
        return defer.succeed(ticket)


    def _expireTicket(self, val):
        try:
            del self._tickets[val]
        except KeyError:
            pass


    def _useTicket(self, ticket):
        """
        Consume a ticket, producing the data that was associated with the ticket
        when it was created.

        @raise InvalidTicket: If the ticket doesn't exist or is no longer valid.
        """
        try:
            return defer.succeed(self._tickets.pop(ticket))
        except KeyError:
            return defer.fail(InvalidTicket())


    def mkLoginTicket(self, service):
        """
        Create a login ticket.

        XXX
        """
        return self._mkTicket('LT-', {
            'service': service,
        })


    def useLoginTicket(self, ticket, service):
        """
        Use a login ticket.

        XXX
        """
        data = self._useTicket(ticket)
        def cb(data):
            if data['service'] != service:
                raise InvalidTicket()
        return data.addCallback(cb)


    def mkServiceTicket(self, username, service):
        """
        Create a service ticket

        XXX
        """
        return self._mkTicket('ST-', {
            'username': username,
            'service': service,
        })


    def useServiceTicket(self, ticket, service):
        """
        Get the username associated with a service ticket.

        XXX
        """
        data = self._useTicket(ticket)
        def cb(data):
            if data['service'] != service:
                raise InvalidTicket()
            return data['username']
        return data.addCallback(cb)





