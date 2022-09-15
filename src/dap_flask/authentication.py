import json, requests
from pprint import pprint
from flask import request
from flask_restx import Resource, Namespace, fields
from base64 import b64decode
from .app import oidc, oidc_client, header_parser

api = Namespace('auth', description='Authentication APIs')

# JSON model for a login response
login_success_response_model = api.model('LoginResponse', {
    'access_token': fields.String(description='api access token'),
    'session': fields.String(description='login session'),
    'oidc_id_token': fields.String(description='oidc id token')
})

# JSON model for a logout response
logout_response_model = api.model('LogoutResponse', {
    'msg': fields.String(description='logout message')
})

# JSON model for a login-fail response
login_fail_response_model = api.model('LoginFailResponse', {
    'msg': fields.String(description='error message')
})

@api.route("/login")
class Login(Resource):

    @api.response(code=200, description='Success', model=login_success_response_model) # Response
    @api.response(code=400, description='Fail', model=login_fail_response_model) # Response
    @api.doc(description='A user obtains a bearer token through Red Hat Single Sign-On.')
    @oidc.require_login
    def get(self):
        info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])

        username = info.get('preferred_username')
        user_id = info.get('sub')

        access_token = None
        session = None
        oidc_id_token = None
        if user_id in oidc.credentials_store:
            from oauth2client.client import OAuth2Credentials
            access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
            session = request.cookies.get('session')
            oidc_id_token = request.cookies.get('oidc_id_token')
            print('access_token={}'.format(access_token))
            print('session={}'.format(session))
            print('oidc_id_token={}'.format(oidc_id_token))
            return {'access_token': access_token,
                    'session': session,
                    'oidc_id_token': oidc_id_token}, 200
        else:
            return {'msg': 'Login failed'}, 400

@api.route("/logout")
@api.expect(header_parser) # Header
class Logout(Resource):

    @api.response(code=200, description='Success', model=logout_response_model) # Response
    @oidc.accept_token(require_token=True, scopes_required=['openid'])
    def get(self):
        refresh_token = oidc.get_refresh_token()
        data = {
            'refresh_token': refresh_token,
            'client_id': 'flask',
            'client_secret': oidc_client['client_secret']
        }
        pprint(data)
        r = requests.post(oidc_client['logout_uri'], data, verify=False)
        oidc.logout()
        return {'msg': 'Logged out'}, 200

# @api.route("/user")
# class UserRole(Resource):
#     @oidc.accept_token(require_token=True, scopes_required=['openid'])
#     @oidc.require_keycloak_role(role='end-user')
#     def post(self):
#         pre, tkn, post = oidc.get_access_token().split('.')
#         access_token = json.loads(b64decode(tkn + '==='))
#         print('access_token')
#         print(access_token)

#         info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
#         username = info.get('preferred_username')
#         userid = info.get('sub')
#         print('username={} userid={}'.format(username, userid))
#         return {'Status': 'Your role is user'}, 200

# @api.route("/approver")
# class ApproverRole(Resource):
#     @oidc.accept_token(require_token=True, scopes_required=['openid'])
#     @oidc.require_keycloak_role(role='approver')
#     def post(self):
#         return {'Status': 'Your role is approver'}, 200
