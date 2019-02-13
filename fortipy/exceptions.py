class Error(Exception):
    def __init__(self, prefix, message):
        self._prefix = prefix
        self._message = message

    @property
    def message(self):
        return '{}: {}'.format(self._prefix, self._message)


class LoginError(Error):
    def __init__(self, message):
        self._prefix = 'Login failed'
        self._message = message


class ConnectionError(Error):
    def __init__(self, message):
        self._prefix = 'Connection failed'
        self._message = message
