
# Standard library
import cgi
import itertools
import json
import sys
from textwrap import dedent
import urlparse

# Application modules
from txcas.constants import VIEW_LOGIN, VIEW_LOGIN_SUCCESS, VIEW_LOGOUT, \
                        VIEW_INVALID_SERVICE, VIEW_ERROR_5XX, VIEW_NOT_FOUND
from txcas.exceptions import ViewNotImplementedError
from txcas.interface import IViewProvider, IViewProviderFactory
import txcas.settings

# External modules
from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound

from twisted.internet import reactor
from twisted.plugin import IPlugin
from twisted.python import log
from twisted.python.filepath import FilePath
from zope.interface import implements



class Jinja2ViewProviderFactory(object):
    """
    """
    implements(IPlugin, IViewProviderFactory)

    tag = "jinja2_view_provider"

    opt_help = dedent('''\
            A view provider based on jinja2 templates.
            ''')

    opt_usage = '''A colon-separated key=value list.'''

    def generateViewProvider(self, argstring=""):
        """
        """
        scp = txcas.settings.load_settings('cas', syspath='/etc/cas')
        settings = txcas.settings.export_settings_to_dict(scp)
        config = settings.get('Jinja2ViewProvider', {})
        if argstring.strip() != "":
            argdict = dict((x.split('=') for x in argstring.split(':')))
            config.update(argdict)
        buf = ["[CONFIG][Jinja2ViewProvider] Settings:"]
        for k in sorted(config.keys()):
            v = config[k]
            buf.append(" - %s: %s" % (k, v))
        sys.stderr.write('\n'.join(buf))
        sys.stderr.write('\n')
        missing = txcas.utils.get_missing_args(
                    Jinja2ViewProvider.__init__, config, ['self'])
        if len(missing) > 0:
            sys.stderr.write(
                "[ERROR][Jinja2ViewProvider] "
                "Missing the following settings: %s" % ', '.join(missing))
            sys.stderr.write('\n')
            sys.exit(1)

        txcas.utils.filter_args(Jinja2ViewProvider.__init__, config, ['self'])
        return Jinja2ViewProvider(**config)

class Jinja2ViewProvider(object):
    """
    A view provider based on Jinja2 templates.
    """
    implements(IViewProvider)

    template_map = {
        VIEW_LOGIN: 'login.jinja2',
        VIEW_LOGIN_SUCCESS: 'login_success.jinja2',
        VIEW_LOGOUT: 'logout.jinja2',
        VIEW_INVALID_SERVICE: 'invalid_service.jinja2',
        VIEW_ERROR_5XX: 'error5xx.jinja2',
        VIEW_NOT_FOUND: 'not_found.jinja2',
        }

    def __init__(self, template_folder):
        self._template_folder = template_folder
        self._loader = FileSystemLoader(template_folder)
        self._env = Environment()
        
        #self._debug = True
        self._debug = False

    def debug(self, msg):
        if self._debug:
            log.msg("[DEBUG][Jinja2ViewProvider] %s" % msg)

    def _renderTemplate(self, view_type, **kwds):
        """
        """
        env = self._env
        loader = self._loader
        name = self.template_map[view_type]
        try:
            templ = loader.load(env, name)
        except TemplateNotFound:
            raise ViewNotImplementedError("The template '%s' was not found." % name)
        return templ.render(**kwds).encode('utf-8')

    def renderLogin(self, login_ticket, service, failed, request):
        """
        """
        return self._renderTemplate(
                        VIEW_LOGIN, 
                        login_ticket=login_ticket, 
                        service=service, 
                        failed=failed,
                        request=request)

    def renderLoginSuccess(self, avatar, request):
        """
        """
        return self._renderTemplate(
                        VIEW_LOGIN_SUCCESS, 
                        avatar=avatar, 
                        request=request)

    def renderLogout(self, request):
        """
        """
        return self._renderTemplate(
                        VIEW_LOGOUT, 
                        request=request)

    def renderInvalidService(self, service, request):
        """
        """
        return self._renderTemplate(
                        VIEW_INVALID_SERVICE, 
                        service=service, 
                        request=request)

    def renderError5xx(self, err, request):
        """
        """
        return self._renderTemplate(
                        VIEW_ERROR_5XX, 
                        err=err, 
                        request=request)
                        
    def renderNotFound(self, request):
        """
        """
        return self._renderTemplate(
                        VIEW_NOT_FOUND, 
                        request=request)

    def provideView(self, view_type):
        """
        """
        if view_type == VIEW_LOGIN:
            return self.renderLogin
        elif view_type == VIEW_LOGIN_SUCCESS:
            return self.renderLoginSuccess
        elif view_type == VIEW_LOGOUT:
            return self.renderLogout
        elif view_type == VIEW_INVALID_SERVICE:
            return self.renderInvalidService
        elif view_type == VIEW_ERROR_5XX:
            return self.renderError5xx
        elif view_type == VIEW_NOT_FOUND:
            return self.renderNotFound
        else:
            return None

