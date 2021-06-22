from .sessions import MoverSession

class BaseMover:
    def __init__(self, creds, url, rest_endpoint):
        self.creds = creds
        self.old = MoverSession(self.creds.old, url, rest_endpoint)
        self.new = MoverSession(self.creds.new, url, rest_endpoint)


