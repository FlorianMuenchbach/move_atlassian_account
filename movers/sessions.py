import logging
import requests

logger = logging.getLogger('User move')
logger.setLevel(logging.DEBUG)

class MoverSession:
    def __init__(self, auth, base, rest_endpoint):
        self.base = base
        self.rest_endpoint = rest_endpoint
        self.auth = auth
        self.session = requests.Session()
        self.session.auth = (auth.user, auth.password)

    def _url(self, url, rest_call):
        return f'{self.base}{("/" + self.rest_endpoint) if rest_call else ""}/{url}' \
                if url \
                else self.base

    def _exec(self, url, method, rest_call, *args, **kwargs):
        if not self.auth.valid():
            raise RuntimeError("No session credentials...")

        full = self._url(url, rest_call)
        function = self.session.__getattribute__(method)
        result = function(full, *args, **kwargs)
        logger.debug('%s: %s: %d', method.upper(), full, result.status_code)
        return result

    def get(self, url, *args, rest_call=True, **kwargs):
        return self._exec(url, 'get', rest_call, *args, **kwargs)

    def put(self, url, *args, rest_call=True, **kwargs):
        return self._exec(url, 'put', rest_call, *args, **kwargs)

    def post(self, url, *args, rest_call=True, **kwargs):
        return self._exec(url, 'post', rest_call, *args, **kwargs)

    def delete(self, url, *args, rest_call=True, **kwargs):
        return self._exec(url, 'delete', rest_call, *args, **kwargs)
