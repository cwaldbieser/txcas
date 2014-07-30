
# Standard library
import ConfigParser
import StringIO
import os.path
import textwrap

# Application modules
from txcas.ldap_cred_checker import LDAPSimpleBindChecker

def load_defaults():
    """
    Load default settings.
    """
    settings = textwrap.dedent("""\
        [LDAP]
        host = 127.0.0.1
        port = 389
        """)
    scp = ConfigParser.SafeConfigParser()
    buf = StringIO.StringIO(settings)
    scp.readfp(buf)
    return scp
    
def load_settings():
    scp = load_defaults()
    thisdir = os.path.dirname(__file__)
    config_file_basename = "cred_checker"
    local_path = os.path.join(thisdir, "%s.cfg" % config_file_basename)
    user_path = os.path.expanduser("~/%src" % config_file_basename)
    system_path = "/etc/cas/%s.cfg" % config_file_basename
    scp.read([system_path, user_path, local_path])
    return scp
    
_scp = load_settings()

ldap_simple_bind_cred_checker = LDAPSimpleBindChecker(
                                    host=_scp.get('LDAP', 'host'),
                                    port=_scp.getint('LDAP', 'port'),
                                    basedn=_scp.get('LDAP', 'basedn'),
                                    binddn=_scp.get('LDAP', 'binddn'),
                                    bindpw=_scp.get('LDAP', 'bindpw'))

