# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

from dap_util.dap_resource import DAPDBaaSResource
import os, json, socket, dap_crypto, dap_cos, time
from pprint import pprint
from flask import Flask, abort, jsonify, Response
from flask_restx import Api, fields
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flask_oidc import OpenIDConnect
import dap_consts
from dap_resource import DAPCommonResource

app = Flask(dap_consts.service, root_path=dap_consts.flask_root_path)
app.config["JWT_SECRET_KEY"] = "secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = True

api = Api(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
if dap_consts.service == dap_consts.AUTHORIZATION_POLICY_APPROVAL_SERVER:
    # Use the same resource as an authorization policy service
    resource = DAPDBaaSResource(dap_consts.AUTHORIZATION_POLICY_SERVICE)
else:
    resource = DAPCommonResource(dap_consts.reboot, dap_consts.service)

if 'MAIL_USERNAME' not in os.environ:
    raise Exception('An environment variable MAIL_USER is not set.')

if 'MAIL_PASSWORD' not in os.environ:
    raise Exception('An environment variable MAIL_PASSWORD is not set.')

mail_settings = {
    "MAIL_SERVER": 'smtp.mailtrap.io',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": False,
    "MAIL_USERNAME": os.environ['MAIL_USERNAME'],
    "MAIL_PASSWORD": os.environ['MAIL_PASSWORD']
}
app.config.update(mail_settings)
mail = Mail(app)

CORS(app)

##### Authorization model #####
header_parser = api.parser()
header_parser.add_argument('Authorization', type=str, required=True, location='headers', help='bearer token for api access') # Note: help == description
header_parser.add_argument('Cookie', type=str, required=True, location='headers', help='rhsso session and oidc_id_token') # Note: help == description
authorization_failure_response_model = api.model('AuthorizationFailureResponse', {
    'error': fields.String(description='error type'),
    'error_description': fields.String(description='error description'),
})

##### OIDC set up #####
key1, key2 = dap_crypto.derive_common_keys()
cos_client = dap_cos.create_cos_client('CLI')
oidc_host = 'rhsso-host'
oidc_secret = None
while True:
    try:
        oidc_secret = dap_cos.get_and_decrypt_backup_from_cos('rhsso-oidc-secret', key1, key2, cos_client)
        break
    except Exception as e:
        print('Failed to get OIDC secret and host')
        print('Try after 10-sec sleeping')
        time.sleep(10)
print('oidc_host={}'.format(oidc_host))
print('oidc_secret={}'.format(oidc_secret))

oidc_client = {}

# SSL
oidc_client['issuer'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam'
oidc_client['auth_uri'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam/protocol/openid-connect/auth'
oidc_client['logout_uri'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam/protocol/openid-connect/logout'
oidc_client['client_id'] = "flask"
oidc_client['client_secret'] = oidc_secret
oidc_client['userinfo_uri'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam/protocol/openid-connect/userinfo'
oidc_client['token_uri'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam/protocol/openid-connect/token'
oidc_client['token_introspection_uri'] = 'https://' + oidc_host + ':8543/auth/realms/rhpam/protocol/openid-connect/token/introspect'

# w/o SSL
# oidc_client['issuer'] = 'http://' + oidc_host + ':8180/auth/realms/rhpam'
# oidc_client['auth_uri'] = 'http://' + oidc_host + ':8180/auth/realms/rhpam/protocol/openid-connect/auth'
# oidc_client['client_id'] = "flask"
# oidc_client['client_secret'] = oidc_secret
# oidc_client['userinfo_uri'] = 'http://' + oidc_host + ':8180/auth/realms/rhpam/protocol/openid-connect/userinfo'
# oidc_client['token_uri'] = 'http://' + oidc_host + ':8180/auth/realms/rhpam/protocol/openid-connect/token'
# oidc_client['token_introspection_uri'] = 'http://' + oidc_host + ':8180/auth/realms/rhpam/protocol/openid-connect/token/introspect'

pprint('oidc_client')
pprint(oidc_client)

web = {}
web['web'] = oidc_client

with open('oidc_client.json', mode='w') as file:
    file.write(json.dumps(web, indent=4))
    file.close()

# ip = socket.gethostbyname(socket.gethostname())
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'oidc_client.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'rhpam',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    # 'OVERWRITE_REDIRECT_URI': 'https://' + ip + ':5000/oidc_callback',
})

oidc = OpenIDConnect(app)

##### Check administrator #####
def check_admin(userid):
    if userid != 'admin':
        abort(423, 'Authorization failure (only admin can do this action)')


