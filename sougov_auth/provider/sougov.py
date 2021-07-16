import jwt
import requests
from utils import handle_http_errors


class SougovAuth:
    """A authentication provider that autheticates the user 
    based on the sougov response"""
    RESPONSE_TYPE = 'code'
    AUTHORIZATION_URL = 'https://sso.staging.acesso.gov.br'
    HTTP_METHOD = 'GET'
    DEFAULT_SCOPE = ['openid', 'email', 'phone', 'profile']
    
    client_id = ''
    callback_url = ''
    response = ''
    user_info_access = ''
    user_info_id = ''

    def __init__(self, client_id, callback_url):
        self.client_id = client_id
        self.callback_url = callback_url
        self.response = self.__auth()
        keys = self.__process_to_claims()
        self.user_info_access = self.__decode_access_token(keys, self.response['access_token'])
        self.user_info_id = self.__decode_access_token(keys, self.response['id_token'])


    @handle_http_errors
    def __auth(self):
        uri = '{url}{path}?response_type={code}&client_id={client_id}&scope={scope}&redirect_uri={callback_url}&nonce={nonce}&state={state}'.format(
            url=self.AUTHORIZATION_URL,
            path='/authorize',
            code=self.RESPONSE_TYPE,
            client_id=self.client_id,
            scope='+'.join(self.DEFAULT_SCOPE),
            callback_url=self.callback_url,
            nonce='unsecure_nonce',
            state='unsecure_state'
        )

        response = requests(uri)
        return response.json()

    @handle_http_errors
    def __process_to_claims(self):
        uri = '{url}{path}'.format(url=self.AUTHORIZATION_URL, path='/jwt')
        response = requests(uri)
        result = response.json()
        return result['keys'][0]

    def __decode_access_token(self, keys, access_token):
        keys = self.__process_to_claims()
        result = jwt.decode(
            jwt=access_token, 
            key=keys['n'], 
            algorithms=[keys['alg']],
            headers={"kid": keys["kid"], "kty": keys["kty"], "e": keys["e"]}
        )
        return result

    def __decode_id_token(self, keys, id_token):
        keys = self.__process_to_claims()
        result = jwt.decode(
            jwt=id_token, 
            key=keys['n'], 
            algorithms=[keys['alg']],
            headers={"kid": keys["kid"], "kty": keys["kty"], "e": keys["e"]}
        )
        return result
