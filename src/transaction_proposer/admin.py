from pprint import pprint
from dap_client import cleanup_txqueue
from flask import request, abort
from flask_restx import Resource, Namespace, fields
from dap_util import txqueue, dap_consts
from dap_flask.app import oidc, header_parser, authorization_failure_response_model, resource

api = Namespace('admin', description='Admin APIs')

##### Query status model #####
query_status_response_model = api.model('QueryStatusResponse', {
    'status': fields.String(description='status of a service'),
    'pubkey': fields.String(description='public key in hex from a service'),
    'pubkey_hmac': fields.String(description='hmac for public key')
})
update_ss_keys_response_model = api.model('UpdateSSKeysResponse', {
    'status': fields.String(description='ok or fail')
})
update_ps_keys_response_model = api.model('UpdatePSKeysResponse', {
    'status': fields.String(description='ok or fail')
})
update_pubkeys_response_model = api.model('UpdatePubkeysResponse', {
    'status': fields.String(description='ok or fail')
})
update_db_password_response_model = api.model('UpdateDBPasswordResponse', {
    'status': fields.String(description='ok or fail')
})

##### Create seed model (only for testing) #####
admin_create_seed_request_model = api.model('AdminCreateSeedRequest', {
    'seed': fields.String(description='seed'),
    'userid': fields.String(description='user id')
})
admin_create_seed_response_model = api.model('AdminCreateSeedResponse', {
    'seedid': fields.String(description='seed id'),
    'status': fields.String(description='status message')
})

##### Clean up txqueue #####
cleanup_txqueue_response_model = api.model('CleanupTxqueue', {
    'status': fields.String(description='ok or fail')
})

@api.route('/service/<string:serviceid>')
@api.expect(header_parser) # Header
class QueryServiceStatus(Resource):

    @api.response(code=200, description='Success', model=query_status_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Query service status (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def get(self, serviceid):
        res = {
            'status': None,
            'serviceid': None,
            'pubkey': None,
            'pubkey_hmac': None
        }

        query = {
            'type': {'$eq': dap_consts.SERVICE_STATUS},
            'serviceid': {'$eq': serviceid}
        }
        doc, code, res['status'] = txqueue.poll(resource.txqueue_client, query, wait_infinitely=False)

        if code == 500:
            abort(500, res['status'])

        res['serviceid'] = doc['serviceid']
        if 'pubkey' in doc:
            res['pubkey'] = doc['pubkey']
        if 'pubkey_hmac' in doc:
            res['pubkey_hmac'] = doc['pubkey_hmac']
        return res, code

@api.route('/updatesskeys')
@api.expect(header_parser) # Header
class UpdateSSKeys(Resource):

    @api.response(code=200, description='Success', model=update_ss_keys_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Update encryption keys in signing service (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self):
        res = {'status': None}

        doc = txqueue.create_request_document(type=dap_consts.ADMIN_OPERATION, 
                                              method=dap_consts.UPDATE_SS_KEYS_METHOD,
                                              params={})
        query = txqueue.create_response_query(type=dap_consts.ADMIN_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['status'] = doc['result']
        return res, code

@api.route('/updatepskeys/<string:serviceid>')
@api.expect(header_parser) # Header
class UpdatePSKeys(Resource):

    @api.response(code=200, description='Success', model=update_ps_keys_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Update a  signing keypair in a policy service (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self, serviceid):
        ### Generate a RSA key pair and store it as a backup to COS in a signing service ###
        res = {'status': None}

        doc = txqueue.create_request_document(type=dap_consts.ADMIN_OPERATION, 
                                              method=dap_consts.GENERATE_PS_KEYS_METHOD,
                                              params={'serviceid': serviceid})
        query = txqueue.create_response_query(type=dap_consts.ADMIN_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        ### Retrieve a RSA key pair from COS and update it in a policy service ###
        res = {'status': None}

        doc = txqueue.create_request_document(type=dap_consts.ADMIN_OPERATION, 
                                              method=dap_consts.UPDATE_PS_KEYS_METHOD)
        for s in dap_consts.POLICY_SERVICES:
            if s != serviceid:
                # Force only the target policy service to retrieve this request
                doc[s] = 'dummy'
        query = txqueue.create_response_query(type=dap_consts.ADMIN_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['status'] = doc['result']
        return res, code

@api.route('/dbs/<string:name>')
@api.expect(header_parser) # Header
class UpdateDBPassword(Resource):

    @api.response(code=200, description='Success', model=update_db_password_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Update the password for a DBaaS instance (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self, name):
        res = {'status': None}

        params = {}
        if name == 'txqueue':
            params['backup_name'] = dap_consts.BACKUP_TXQUEUE_INFO
        elif name == 'walletdb':
            params['backup_name'] = dap_consts.BACKUP_WALLETDB_INFO
        else:
            abort(500, 'Unknown db name ' + name)
        doc = txqueue.create_request_document(
            type=dap_consts.ADMIN_OPERATION,
            method=dap_consts.UPDATE_DBAAS_PASSWORD_METHOD,
            params=params)
        query = txqueue.create_response_query(type=dap_consts.ADMIN_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        # Update my txqueue client
        resource.update_txqueue_client()

        # Update txqueue clients in other services
        txqueue.kill_all_sessions(resource.txqueue_client)

        res['status'] = doc['result']
        return res, code

@api.route('/createseed')
@api.expect(header_parser) # Header
class AdminCreateSeed(Resource):

    @api.expect(admin_create_seed_request_model)
    @api.response(code=200, description='Success', model=admin_create_seed_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API requests the blueprint to create a new master seed, which is generated using HPCS and is stored internally in such a way that admins cannot extract or use to make blockchain transactions. The API returns a seed id, which is unique in the blueprint instance.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        json_data = request.json

        res = {
            'status': None,
            'seedid': None
        }

        params = json_data

        doc = txqueue.create_request_document(type=dap_consts.ADMIN_OPERATION, 
                                              method=dap_consts.ADMIN_CREATE_SEED, 
                                              params=params)
        query = txqueue.create_response_query(type=dap_consts.ADMIN_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['seedid'] = doc['result']
        return res, code

@api.route('/dbs/txqueue/cleanup')
@api.expect(header_parser) # Header
class CleanupTxqueue(Resource):

    @api.response(code=200, description='Success', model=cleanup_txqueue_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='Update the password for a DBaaS instance (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self):
        res = {'status': None}

        txqueue.cleanup(resource.txqueue_client)

        res['status'] = 'ok'

        return res, 200
