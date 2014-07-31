
# Standard library
import ConfigParser
import StringIO
import os.path

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
    scp = load_defaults(defaults)
    appdir = os.path.dirname(os.path.dirname(__file__))
    paths = []
    if syspath is not None:
        paths.append(os.path.join(syspath, "%s.cfg" % config_basename))
    paths.append(os.path.expanduser("~/%src" % config_basename))
    paths.append(os.path.join(appdir, "%s.cfg" % config_basename))
    scp.read(paths)
    return scp

