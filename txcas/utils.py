

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

