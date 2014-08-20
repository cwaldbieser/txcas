

#=======================================================================
# Exceptions
#=======================================================================

class CASError(Exception):
    pass

class InvalidTicket(CASError):
    pass

class InvalidTicketSpec(InvalidTicket):
    pass

class UnauthorizedServiceProxy(CASError):
    pass

class InvalidService(CASError):
    pass

class InvalidProxyCallback(CASError):
    pass

class CookieAuthFailed(CASError):
    pass

class NotSSOService(CASError):
    pass

class NotHTTPSError(CASError):
    pass

class ViewNotImplementedError(CASError):
    pass

class BadRequestError(CASError):
    pass
