class LoginError(Exception):
    def __init__(self, message):
        self.message = message or 'Login failed'


class ConnectionError(Exception):
    def __init__(self, message):
        self.message = message or \
            'No FortiManager instance found at the provided host & port'
