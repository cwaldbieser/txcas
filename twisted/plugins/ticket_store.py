

from txcas.in_memory_ticket_store import InMemoryTicketStoreFactory
memory_factory = InMemoryTicketStoreFactory()

from txcas.couchdb_ticket_store import CouchDBTicketStoreFactory
couchdb_factory = CouchDBTicketStoreFactory()


