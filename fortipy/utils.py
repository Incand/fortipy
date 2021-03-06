def is_iterable_no_str(obj):
    if isinstance(obj, str):
        return False
    try:
        iter(obj)
    except TypeError:
        return False
    return True


def kwargs_to_json_handler(kwargs):
    '''
    Necessary for python args and API params name conflict resolution.
    e.g. for table "get_used" -> "get used" or "filter_" -> "filter".
    '''
    return {k.strip('_'): v for k, v in kwargs.items()}
