
from twisted.cred.error import Unauthorized

#------------------------------------------------------------------------------
# REPLACE THIS STUFF WITH YOUR SPECIFICS
#------------------------------------------------------------------------------

def valid_service(url):
    """
    Authorize anything
    """
    return True


# How long do transient tickets last?
TICKET_TIMEOUT = 10

# How long do user sessions last?
AUTH_TIMEOUT = 60 * 60 * 24 * 2

# What endpoint to listen on
ENDPOINT = 'tcp:8080'

# Require cookies to be sent over SSL?
REQUIRE_SSL = True

# Customize page views (see txcas/server.py for details).
PAGE_VIEWS = None

# Validate the pgtUrl callback.  Only set to False for development.
VALIDATE_PGTURL = True
#------------------------------------------------------------------------------



from twisted.application import service
from txcas.service import CASService

application = service.Application('txcas')
cas_service = CASService(
                    ENDPOINT,
                    ticket_timeout=TICKET_TIMEOUT,
                    auth_timeout=AUTH_TIMEOUT,
                    valid_service=valid_service,
                    requireSSL=REQUIRE_SSL,
                    page_views=PAGE_VIEWS,
                    validate_pgturl=VALIDATE_PGTURL)
cas_service.setServiceParent(application)
