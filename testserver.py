from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse

from txcas.server import ServerApp, UserRealm


app = ServerApp(UserRealm(), InMemoryUsernamePasswordDatabaseDontUse(
                foo='password'), ['http://www.example.com'])
app.app.run('localhost', 9123)