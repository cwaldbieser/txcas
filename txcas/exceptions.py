

#=======================================================================
# Exceptions
#=======================================================================

class CASError(Exception):
    pass

class InvalidTicket(CASError):
    pass


class InvalidService(CASError):
    pass


class CookieAuthFailed(CASError):
    pass

class NotSSOService(CASError):
    pass

class NotHTTPSError(CASError):
    pass
