
import txcas.settings

_scp = txcas.settings.load_settings('cas', syspath='/etc/cas')


from txcas.demo_realm import DemoRealm
demo_realm = DemoRealm()

if txcas.settings.has_options(_scp, {'LDAP': ['host', 'port', 'basedn', 'binddn', 'bindpw']}):
    from txcas.ldap_realm import LDAPRealm
    ldap_realm = LDAPRealm(host=_scp.get('LDAP', 'host'),
                                    port=_scp.getint('LDAP', 'port'),
                                    basedn=_scp.get('LDAP', 'basedn'),
                                    binddn=_scp.get('LDAP', 'binddn'),
                                    bindpw=_scp.get('LDAP', 'bindpw'),
                                    attribs=['uid', 'givenName', 'sn', 'mail', 'memberOf'])

                                    
                                    
