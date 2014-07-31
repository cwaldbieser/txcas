
import txcas.settings

_scp = txcas.settings.load_settings('cas', syspath='/etc/cas')

from txcas.in_memory_ticket_store import InMemoryTicketStore
ticket_store = InMemoryTicketStore()

if txcas.settings.has_options(_scp, {'CouchDB': ['host', 'port', 'db', 'user', 'passwd']}):
    from txcas.couchdb_ticket_store import CouchDBTicketStore
    use_https = True
    if _scp.has_option('CouchDB', 'https'):
        use_https = bool(_scp.getint('CouchDB', 'https'))
    couchdb_ticket_store = CouchDBTicketStore(
                            couch_host=_scp.get('CouchDB', 'host'), 
                            couch_port=_scp.getint('CouchDB', 'port'), 
                            couch_db=_scp.get('CouchDB', 'db'),
                            couch_user=_scp.get('CouchDB', 'user'), 
                            couch_passwd=_scp.get('CouchDB', 'passwd'),
                            use_https=use_https)


