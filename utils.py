from exceptions import AuthBadRequestException, AuthForbiddenException, AuthUnreachableProvider
import functools
import requests


def handle_http_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.HTTPError as err:
            if err.response.status_code == 400:
                raise AuthBadRequestException(args[0])
            elif err.response.status_code == 401:
                raise AuthForbiddenException(args[0])
            elif err.response.status_code == 503:
                raise AuthUnreachableProvider(args[0])
            else:
                raise
    return wrapper