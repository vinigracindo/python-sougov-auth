class AuthBadRequestException(ValueError):
    "Auth process bad request"
    def __str__(self):
        return 'Authentication process canceled. Bad request.'

class AuthForbiddenException(ValueError):
    "Auth process forbidden"
    def __str__(self):
        return 'Your credentials aren\'t allowed.'

class AuthUnreachableProvider(ValueError):
    "Auth process cannot reach the provider"
    def __str__(self):
        return 'The authentication provider could not be reached'