#------------------------------------------------------------------------------
# REPLACE THIS STUFF WITH YOUR SPECIFICS
#------------------------------------------------------------------------------
def authorize(username, password):
    """
    Authorize the user "foo" for the password "password"
    """
    if username == 'foo' and password == 'password':
        return username
    raise Exception("Bad credentials")


def valid_service(url):
    """
    Authorize anything from localhost
    """
    if url.startswith('https://localhost'):
        return True
    return False


# How long do transient tickets last?
TICKET_TIMEOUT = 10

# How long do user sessions last?
AUTH_TIMEOUT = 60 * 60 * 24 * 2

# What endpoint to listen on
ENDPOINT = 'tcp:8080'

# Require cookies to be sent over SSL?
REQUIRE_SSL = True

#------------------------------------------------------------------------------



from twisted.application import service
from txcas.service import CASService

application = service.Application('txcas')
cas_service = CASService(ENDPOINT,
                         authorize=authorize,
                         ticket_timeout=TICKET_TIMEOUT,
                         auth_timeout=AUTH_TIMEOUT,
                         valid_service=valid_service,
                         requireSSL=REQUIRE_SSL)
cas_service.setServiceParent(application)
