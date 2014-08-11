
# Standard library
import inspect

# External modules.
import treq

def http_status_filter(response, allowed, ex, msg=None, include_resp_text=True):
    """
    Checks the response status and determines if it is in one of the
    allowed ranges.  If not, it raises `ex()`.

    `ex` is a callable that results in an Exception to be raised,
        (typically an exception class).
    `allowed` is a sequence of (start, end) valid status ranges.
    """
    code = response.code
    in_range = False
    for start_range, end_range in allowed:
        if code >= start_range and code <= end_range:
            in_range = True
            break
    if not in_range:
        def raise_error(body, ex):
            ex_msg = []
            if msg is not None:
                ex_msg.append(msg)
            if include_resp_text:
                ex_msg.append(body)
            text = '\n'.join(ex_msg)
            if text != "":
                raise ex(text)
            else:
                raise ex()
        # Need to still deliver the response body or Twisted make
        # hang.
        d = treq.content(response)
        d.addCallback(raise_error, ex)
        return d
    return response

def unwrap_failures(err):
    """
    Takes nested failures and flattens the nodes into a list.
    The branches are discarded.
    """
    errs = []
    check_unwrap = [err]
    while len(check_unwrap) > 0:
        err = check_unwrap.pop()
        if hasattr(err.value, 'reasons'):
            errs.extend(err.value.reasons)
            check_unwrap.extend(err.value.reasons)
        else:
            errs.append(err)
    return errs
    
def get_missing_args(func, provided, exclude=None):
    """
    """
    if exclude is None:
        exclude = set([])
    argspec = inspect.getargspec(func)
    defaults = argspec.defaults or []
    defaults_count = len(defaults)
    if defaults_count > 0:
        required = argspec.args[:-defaults_count]
    else:
        required = argspec.args
    missing = [arg for arg in required if not arg in provided and arg not in exclude]        
    return missing

def filter_args(func, provided, exclude=None):
    """
    Removes keys from mapping `provided` that are not included in the
    arglist for `func`.
    """
    if exclude is None:
        exclude = set([])
    arg_set = set([x for x in inspect.getargspec(func).args if x not in exclude])
    keys = provided.keys()
    for k in keys:
        if not k in arg_set:
            del provided[k]

def format_plugin_help_list(factories, stm):
     """
     Show plugin list with brief usage..
     """
     # Figure out the right width for our columns
     firstLength = 0
     for factory in factories:
         if len(factory.tag) > firstLength:
             firstLength = len(factory.tag)
     formatString = '  %%-%is\t%%s\n' % firstLength
     stm.write(formatString % ('Plugin', 'ArgString format'))
     stm.write(formatString % ('======', '================'))
     for factory in factories:
         stm.write(
             formatString % (factory.tag, factory.opt_usage))
     stm.write('\n')

