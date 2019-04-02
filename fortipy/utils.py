def is_iterable(obj):
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
    return {k.strip('_').replace('_', ' '): v for k, v in kwargs.items()}
