'''
FortiManager
Author: Armin Schaare <armin-scha@hotmail.de>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''


class Error(Exception):
    def __init__(self, errcode, message=''):
        self.errcode = errcode
        self.message = message or 'Unknown error.'


class LockException(Exception):
    pass


class CommitException(Exception):
    pass


class LoginError(Error):
    def __init__(self, message):
        self._prefix = 'Login failed'
        self._message = message


class ConnectionError(Error):
    def __init__(self, message):
        self._prefix = 'Connection failed'
        self._message = message
