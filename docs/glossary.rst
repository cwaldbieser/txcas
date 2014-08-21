Glossary
********

.. glossary::

    AVATAR
        A representation of an authenticated user.  In txcas, an avatar must
        implement the interface ICASUSer.  The avatar will have a username
        and possibly one or more attributes associated with it.

    PGT
        Proxy Granting Ticket.  A ticket obtained by a service provider that
        allows it to request proxt tickets from CAS.  The proxy tickets can
        later be used to request services from other service providers that
        participate in the CAS session.

    SLO
        Single Log-out.  When a user is logged out of a CAS :term:`SSO` 
        session, all CAS clients that authenticated via the session are
        notified of the session termination.

        See https://github.com/Jasig/cas/blob/master/cas-server-protocol/3.0/cas_protocol_3_0.md#233-single-logout 
        for details.

    SSO
        Single Sign-On.  The ability to login once to a service authentication 
        broker and not have to present primary credentials to log into same
        or different participating services, often for a specific period of
        time.

    TAC FILE
        A Twisted Application Configuration file.  A regular Python file used
        to configure a Twisted Application.  Endpoint settings (interface, 
        port, SSL settings) are commonly configured in this type of file.

    TGT
        Ticket Granting Ticket.  A ticket issued when a CAS session is started
        by providing primary credentials.  The TGT is then used to request
        service tickets that a service provider can validate with CAS to prove
        that the ticket presenter has been authenticated by CAS.

