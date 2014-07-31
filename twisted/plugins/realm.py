
import txcas.settings

_scp = txcas.settings.load_settings('cas', syspath='/etc/cas', defaults={
    'PLUGINS':{'realm': 'DemoRealm'}})

if _scp.get('PLUGINS', 'realm') == 'DemoRealm':
    from txcas.demo_realm import DemoRealm
    realm = DemoRealm()

elif _scp.get('PLUGINS', 'realm') == 'LDAPRealm':
    from txcas.ldap_realm import LDAPRealm
    realm = LDAPRealm(host=_scp.get('LDAP', 'host'),
                                    port=_scp.getint('LDAP', 'port'),
                                    basedn=_scp.get('LDAP', 'basedn'),
                                    binddn=_scp.get('LDAP', 'binddn'),
                                    bindpw=_scp.get('LDAP', 'bindpw'),
                                    attribs=['uid', 'givenName', 'sn', 'mail', 'memberOf'])
                                    
                                    
