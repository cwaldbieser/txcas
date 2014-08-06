#! /usr/bin/env python

# Standard library
import getpass
import json
import sys

# App modules
import txcas.http as http

# External modules
from twisted.internet import reactor

def run():
    """
    """
    is_https = ""
    while is_https.strip().lower() not in ('y', 'n'):
        is_https = raw_input("Use HTTPS [Yn]? ")
        if is_https.strip() == "":
            is_https = "y"
    host = raw_input("CouchDB Server: ")
    port = ""
    while True:
        port = raw_input("CouchDB Port: ")
        try:
            port = int(port)
        except ValueError:
            continue
        break
    db = ""
    while db.strip() == "":
        db = raw_input("Database Name: ") 
    admin = ""
    while admin.strip() == "":
        admin = raw_input("Admin User: ")
    passwd = ""
    confirm = None
    while passwd != confirm:
        passwd = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password: ")
    
    print "Create Database"
    print "Server: %s:%d" % (host, port)
    print "Database: '%s'" % db
    yesno = raw_input("Continue [yN]? ")
    if yesno.strip().lower() != "y":
        sys.exit(1)

    if is_https:
        scheme = "https"
    else:
        scheme = "http"
    url = "%s://%s:%d/%s" % (scheme, host, port, db)
   
    def check_created(resp):
        def report_error(resp_text):
            raise Exception("Could not create database.\n%s" % resp_text)
        if resp.code not in (201, 412):
            return http.content(resp).adCallback(report_error)
        return resp

    def create_design_doc(_, scheme, host, port, db, admin, passwd):
        url = "%s://%s:%d/%s/_design/views" % (scheme, host, port, db)
        doc = {
                'language': 'javascript',
                'views': {
                    "get_ticket": {
                        "map": "function(doc) {\n  emit(doc['ticket_id'], doc);\n}"
                    },
                    "get_by_expires": {
                        "map": """function(doc) {\n    emit(doc['expires'], doc['ticket_id']);\n}"""
                    },
                },
            }
        doc = json.dumps(doc)
        d = http.put(url,  auth=(admin, passwd), data=doc)
        return d

    #201 - create ddoc, 409 - exists
    def report_status(resp):
        if resp.code == 409:
            print "Design document 'views' already exists."
        elif resp.code != 201:
            print "Could not create design document 'views'."
        return resp

    def print_result(result):
        print result
        return result

    def stop(_, reactor):
        print "Stopping ..."
        reactor.stop()
 
    d = http.put(url, auth=(admin, passwd))
    d.addCallback(check_created) 
    d.addCallback(http.json_content)
    d.addCallback(create_design_doc, scheme, host, port, db, admin, passwd)
    d.addCallback(report_status) 
    d.addCallback(http.json_content)
    #d.addCallback(print_result)
    d.addBoth(stop, reactor)

    reactor.run()

if __name__ == "__main__":
    run()

