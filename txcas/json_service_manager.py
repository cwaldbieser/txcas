
# Standard library
import cgi
import itertools
import json
import sys
from textwrap import dedent
import urlparse

# Application modules
from txcas.interface import IServiceManager, IServiceManagerFactory
import txcas.settings

# External modules
from twisted.internet import reactor
from twisted.plugin import IPlugin
from twisted.python import log
from twisted.python.filepath import FilePath
from zope.interface import implements

def normalize_netloc(scheme, netloc):
    """
    """
    if ':' not in netloc:
        if scheme == 'https':
            netloc = '%s:443' % netloc
        elif scheme == 'http':  
            netloc = '%s:80' % netloc
    return netloc

def compare_paths(allowed_path, path, allow_child_paths=False):
    """
    """
    if allowed_path == path:
        return True

    if not allow_child_paths:
        return False
    
    allowed_parts = allowed_path.split('/')[1:]
    parts = path.split('/')[1:]
    for allowed, presented in itertools.izip(allowed_parts, parts):
        if allowed == '':
            return True
        if allowed != presented:
            return False
    
    return True


class JSONServiceManagerFactory(object):
    """
    """
    implements(IPlugin, IServiceManagerFactory)

    tag = "json_service_manager"

    opt_help = dedent('''\
            A service manager configured in an external JSON file.
            ''')

    opt_usage = '''A colon-separated key=value list.'''

    def generateServiceManager(self, argstring=""):
        """
        """
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        config = settings.get('JSONServiceManager', {})
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            config.update(argdict)
        missing = txcas.utils.get_missing_args(
                    JSONServiceManager.__init__, config, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][JSONServiceManager] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n')
            sys.exit(1)

        txcas.utils.filter_args(JSONServiceManager.__init__, config, ['self'])
        buf = ["[CONFIG][JSONServiceManager] Settings:"]
        for k in sorted(config.keys()):
            v = config[k]
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf))
        sys.stderr.write('\n')
        return JSONServiceManager(config["path"])

class JSONServiceManager(object):
    """
    [
        {
            'name': 'Service Name',
            'scheme': 'http|https(default)|*',
            'netloc': 'host[:port]',
            'path': '/some/resource',
            'child_paths': true|false(default),
            'required_params': None(default) or {param: [value, value, ...]},
            'SSO': true(default)|false
        },
        ...
    ]
    """
    implements(IServiceManager)

    poll_interval = 60

    def __init__(self, path):
        self._path = path
        self._modtime = None
        self._reload()
        reactor.callLater(self.poll_interval, self._reload)
        
        #self._debug = True
        self._debug = False

    def debug(self, msg):
        if self._debug:
            log.msg("[DEBUG][JSONServiceRegistry] %s" % msg)

    def _reload(self):
        """
        """
        path = self._path
        filepath = FilePath(path)
        modtime = filepath.getModificationTime()
        if modtime != self._modtime:
            log.msg("[INFO][JSONServiceRegistry] Reloading service registry '%s' ..." % self._path)    
            self._modtime = modtime
            with open(path, 'r') as f:
                self._registry = json.load(f)
            self._apply_defaults()
            self._cache = {}

        reactor.callLater(self.poll_interval, self._reload)

    def _apply_defaults(self):
        registry = self._registry
        for service in registry:
            scheme = service.setdefault('scheme', 'https')
            child_paths = service.setdefault('child_paths', False)
            required_params = service.setdefault('required_params', None)
            sso = service.setdefault('SSO', True)

    def _getMatchingService(self, service):
        """
        Get matching service or None.
        """
        cache = self._cache
        if service in cache:
            self.debug("_getMatchingService(), cached ...")
            return cache[service]

        p = urlparse.urlparse(service)
        scheme = p.scheme
        netloc = normalize_netloc(scheme, p.netloc)
        path = p.path
        query = p.query
        params = cgi.parse_qs(query)

        self.debug("_getMatchingService(), parsed scheme: %s, netloc: %s, path: %s, query: %s" % (
            scheme, netloc, path, query))

        registry = self._registry
        match = None
        for entry in registry:
            self.debug("_getMatchingService(), entry: %s" % str(entry))

            entry_scheme = entry['scheme']
            if entry_scheme != '*' and entry_scheme != scheme:
                self.debug("schemes don't match.")
                continue
            entry_netloc = normalize_netloc(scheme, entry['netloc'])
            if netloc != entry_netloc:
                self.debug("netlocs don't match.")
                continue
            entry_path = entry['path']
            if not compare_paths(entry_path, path, allow_child_paths=entry['child_paths']):
                self.debug("paths don't match.")
                continue
            required_params = entry['required_params']
            if required_params is not None:
                for param, values in required_params.iteritems():
                    if not param in params:
                        self.debug("params don't match.")
                        continue
                    vset = set(values)
                    if vset != set(params[param]):
                        self.debug("params don't match.")
                        continue
            match = entry 
            break
        self.debug("_getMatchingService(), match == %s" % str(entry))
        cache[service] = match
        return match

    def isValidService(self, service):
        if service == "":
            return True
        result = (self._getMatchingService(service) is not None)
        self.debug("service: '%s', result: %s" % (service, result))
        return result

    def isSSOService(self, service):
        """
        Returns True if the service participates in SSO.
        Returns False if the service will only accept primary credentials.
        """
        if service == "":
            return True
        entry = self._getMatchingService(service)
        if entry is None:
            self.debug("isSSOService(), service: '%s', returning False." % service)
            return False
        else:
            self.debug("isSSOService(), service: '%s', returning %s." % (service, entry['SSO']))
            return entry['SSO'] 

