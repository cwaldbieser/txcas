
# Standard library
import ConfigParser
import StringIO
import os.path

# External modules
from twisted.plugin import getPlugins

def load_defaults(defaults):
    """
    Load default settings.
    """
    lines = []
    for section, opts in defaults.iteritems():
        lines.append("[%s]" % section)
        for opt, value in opts.iteritems():
            lines.append("%s = %s" % (opt, value))
    settings = '\n'.join(lines)
    del lines
    scp = ConfigParser.SafeConfigParser()
    buf = StringIO.StringIO(settings)
    scp.readfp(buf)
    return scp
    
def load_settings(config_basename, defaults=None, syspath=None):
    """
    Load settings.
    """
    if defaults is None:
        defaults = {}
    scp = load_defaults(defaults)
    appdir = os.path.dirname(os.path.dirname(__file__))
    paths = []
    if syspath is not None:
        paths.append(os.path.join(syspath, "%s.cfg" % config_basename))
    paths.append(os.path.expanduser("~/%src" % config_basename))
    paths.append(os.path.join(appdir, "%s.cfg" % config_basename))
    scp.read(paths)
    return scp

def has_options(scp, opts):
    """
    Check if a config parser has the indicated options.
    """
    for section, options in opts.iteritems():
        if not scp.has_section(section):
            return False
        for opt in options:
            if not scp.has_option(section, opt):
                return False
    return True

def get_plugin(tagname, iface, all_matches=False):
    """
    Get plugins for interface `iface` with class names
    matching `tagname`.
    Retunrs the first match or None if no matches.
    If `all_matches` is set to True, return a list of matches or
    an empty list on no matches.
    """
    results = []
    for plugin in getPlugins(iface):
        if plugin.__class__.__name__ == tagname:
            results.append(plugin)
            if not all_matches:
                break
            
    if not all_matches:
        if len(results) == 0:
            return None
        else:
            return results[0]
    else:
        return results

def dump_settings(scp):
    """
    """
    for section in scp.sections():
        for option in scp.options(section):
            print "%s, %s: %s" % (section, option, scp.get(section, option))

