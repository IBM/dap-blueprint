# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import json
from urllib.parse import unquote
from pprint import pprint
from flask import request, abort
from flask_restx import Resource, Namespace, fields
from dap_util import txqueue, dap_consts
from dap_flask.app import oidc, header_parser, authorization_failure_response_model, resource
from electrum import commands as electrum

api = Namespace('seeds', description='Signing key management APIs')

##### Create seed model #####
policy_service_pubkey_model = api.model('PolicyServicePubkey', {
    '<serviceid>': fields.String(description='public key')
})
policy_service_hmac_model = api.model('PolicyServiceHMAC', {
    '<serviceid>': fields.String(description='HMAC of a public key')
})
create_seed_request_model = api.model('CreateSeedRequest', {
    'pubkeys': fields.List(fields.Nested(policy_service_pubkey_model)),
    'hmacs': fields.List(fields.Nested(policy_service_hmac_model)),
})
create_seed_response_model = api.model('CreateSeedResponse', {
    'seedid': fields.String(description='seed id'),
    'status': fields.String(description='status message')
})

##### Query seed model #####
query_seed_response_model = api.model('QuerySeedResponse', {
    'status': fields.String(description='status message')
})

##### Delete seed model #####
delete_seed_response_model = api.model('DeleteSeedResponse', {
    'status': fields.String(description='status message')
})

##### Derive pubkey model #####
derive_pubkey_response_model = api.model('DerivePubkeyResponse', {
    'pubkey': fields.String(description='public key'),
    'chaincode': fields.String(description='chain code'),
    'status': fields.String(description='status message')
})

##### Sign request model #####
transaction_input_model = api.model('TransactionInput', {
    # 'seedid': fields.String(description='seed id'),
    'bip32path': fields.String(description='bip32 derivation path (e.g., m/0/0/0)'),
    'hash': fields.String(description='hash')
})
sign_request_model = api.model('SingRequest', {
    'transaction or invoice': fields.String(description='pre-sign raw transaction or invoice in hexadecimal'),
    'inputs': fields.List(fields.Nested(transaction_input_model), description='hash value to be signed and corresponding derivation path')
})
sign_response_model = api.model('SignResponse', {
    'status': fields.String(description='status message')
})

##### Sign result model #####
sign_result_request_model = api.model('SingResultRequest', {
    'transaction': fields.String(description='raw pre-sign transaction string in hexadecimal')
})
sign_result_response_model = api.model('SignResultResponse', {
    'signatures': fields.List(fields.String(), description='signatures for transaction inputs'),
    'status': fields.String(description='status message')
})

@api.route('/create')
@api.expect(header_parser) # Header
class TransactionProposerSeedsCreate(Resource):

    @api.expect(create_seed_request_model)
    @api.response(code=200, description='Success', model=create_seed_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API requests the blueprint to create a new master seed, which is generated using HPCS and is stored internally in such a way that admins cannot extract or use to make blockchain transactions. The API returns a seed id, which is unique in the blueprint instance.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def post(self):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        json_data = request.json

        res = {
            'status': None,
            'seedid': None
        }

        params = json_data
        params['userid'] = userid

        doc = txqueue.create_request_document(type=dap_consts.SEED_OPERATION, 
                                              method=dap_consts.CREATE_SEED_METHOD, 
                                              params=params)
        query = txqueue.create_response_query(type=dap_consts.SEED_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['seedid'] = doc['result']
        return res, code

@api.route('/<string:seedid>')
@api.expect(header_parser) # Header
class TransactionProposerSeeds(Resource):

    @api.response(code=200, description='Success', model=query_seed_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API queries if a seed exists in the blueprint instance or not.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def get(self, seedid):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        res = {
            'status': None,
        }

        doc = txqueue.create_request_document(
            type=dap_consts.SEED_OPERATION, 
            method=dap_consts.QUERY_SEED_METHOD, 
            params={'userid': userid, 'seedid': seedid})
        query = txqueue.create_response_query(type=dap_consts.SEED_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['status'] = doc['result']
        return res, code

    @api.response(code=200, description='Success', model=delete_seed_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API requests the blueprint to delete a seed.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def delete(self, seedid):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        res = {
            'status': None,
        }

        doc = txqueue.create_request_document(
            type=dap_consts.SEED_OPERATION, 
            method=dap_consts.DELETE_SEED_METHOD, 
            params={'userid': userid, 'seedid': seedid})
        query = txqueue.create_response_query(type=dap_consts.SEED_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])
        
        res['status'] = doc['result']
        return res, code

@api.route('/<string:seedid>/pubkeys/<path:bip32path>')
@api.expect(header_parser) # Header
class TransactionProposerSeedsDerive(Resource):

    @api.response(code=200, description='Success', model=derive_pubkey_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API requests the blueprint to derive a public key for a seed and a bip32 derivation path. bip32path is a URL-encoded string from a path string like m/0/0/0.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def post(self, seedid, bip32path):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        res = {
            'status': None,
            'pubkey': None,
            'chaincode': None,
            'raw_pubkey': 'raw_pubkey',
        }

        try:
            bip32path = unquote(bip32path)
        except Exception as e:
            abort(500, 'Failed to decode bip32path={}'.format(bip32path))

        if not bip32path.startswith('m/'):
            abort(500, 'bip32path ({}) does not start with \'m/\''.format(bip32path))

        doc = txqueue.create_request_document(
            type=dap_consts.SEED_OPERATION, 
            method=dap_consts.DERIVE_PUBKEY_METHOD, 
            params={'userid': userid, 
                    'seedid': seedid, 
                    'bip32path': bip32path}
        )
        query = txqueue.create_response_query(type=dap_consts.SEED_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['pubkey'] = doc['result']['pubkey']
        res['chaincode'] = doc['result']['chaincode']
        res['raw_pubkey'] = doc['result']['raw_pubkey']
        return res, code

@api.route('/<string:seedid>/sign/request')
@api.expect(header_parser) # Header
class TransactionProposerSignRequest(Resource):

    @api.expect(sign_request_model)
    @api.response(code=200, description='Success', model=sign_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API sends a request to sign a set of hash values to be added in a blockchain transaction. It takes an array of inputs, where each element has a bip32 path and a hash value to be signed. For each element in the inputs, the signing service in this blueprint derives a private key from the seed specified by the seed id using the bip32 path, and signs the hash value. This API also takes a raw pre-sign transaction string. The blueprint parses the string to extract transaction parameters (a set of destination and source addresses, and an amount for each address), which a policy service uses to approve or reject the transaction. The blueprint also computes each hash value from the string to validate the ones in the API parameter. If the hash value computed from the string doesn\'t match, the transaction is rejected. Since the signing process can take a long time (e.g., a few days) with human approvals, another API (/seeds/<seedid>/sign/result) needs to be called to retrieve signatures.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def post(self, seedid):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        json_data = request.json

        res = {
            'status': None,
        }

        '''
        valid = electrum.validatetx(json_data['transaction'], json_data['inputs'])
        if not valid:
            abort(500, 'Your transaction is invalid')
        '''

        params = {
            'userid': userid,
            'seedid': seedid,
            'inputs': json_data['inputs']
        }
        if 'transaction' in json_data:
            params['transaction'] = json_data['transaction']
        elif 'invoice' in json_data:
            params['invoice'] = json_data['invoice']
        else:
            abort(500, 'transaction or invoice must be included in a request body')

        doc = txqueue.create_request_document(
            type=dap_consts.TRANSACTION_OPERATION, 
            method=dap_consts.SIGN_METHOD, 
            params=params
        )
        # query = txqueue.create_response_query(type=dap_consts.TRANSACTION_OPERATION, id=doc['request']['id'])
        # doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)
        doc, code, res['status'] = txqueue.enqueue(resource.txqueue_client, doc)

        return res, code

@api.route('/<string:seedid>/sign/result')
@api.expect(header_parser) # Header
class TransactionProposerSignResult(Resource):

    @api.expect(sign_result_request_model)
    @api.response(code=200, description='Success', model=sign_result_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API retrives a signing result, which includes an array of signatures from the signing service, for a signing request made by a signing request API (/seeds/<seedid>/sign/request). The frontend (a caller of this API) is supposed to add signatures from this API response to a raw pre-sign transaction string before broadcasting it to a blockchain network (e.g. bitcoin network).')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def post(self, seedid):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        json_data = request.json

        res = {
            'status': None,
            'signs': None
        }

        query = {
            'request.type': {'$eq': dap_consts.TRANSACTION_OPERATION},
            'request.params.userid': {'$eq': userid},
            'request.params.seedid': {'$eq': seedid},
            'request.params.transaction': {'$eq': json_data['transaction']},
            'result': {'$ne': None}
        }
        print('SignResult query')
        pprint(json.dumps(query))
        doc, code, res['status'] = txqueue.dequeue(resource.txqueue_client, query)

        if code == 500:
            if res['status'].startswith('No response'):
                return res, 200
            abort(500, res['status'])

        res['signs'] = doc['result']
        return res, code

@api.route('/<string:seedid>/sign')
@api.expect(header_parser) # Header
class TransactionProposerSign(Resource):

    @api.expect(sign_request_model)
    @api.response(code=200, description='Success', model=sign_result_response_model)
    @api.response(code=401, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='This API combines signing request and result APIs.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='end-user')
    def post(self, seedid):
        userid = oidc.user_getinfo(['preferred_username', 'email', 'sub']).get('preferred_username')

        json_data = request.json

        res = {
            'status': None,
            'signs': None
        }

        '''
        valid = electrum.validatetx(json_data['transaction'], json_data['inputs'])
        if not valid:
            abort(500, 'Your transaction is invalid')
        '''

        params = {
            'userid': userid,
            'seedid': seedid,
            'inputs': json_data['inputs']
        }
        if 'transaction' in json_data:
            params['transaction'] = json_data['transaction']
        elif 'invoice' in json_data:
            params['invoice'] = json_data['invoice']
        else:
            abort(500, 'transaction or invoice must be included in a request body')

        doc = txqueue.create_request_document(
            type=dap_consts.TRANSACTION_OPERATION, 
            method=dap_consts.SIGN_METHOD, 
            params=params
        )
        query = txqueue.create_response_query(type=dap_consts.TRANSACTION_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(resource.txqueue_client, doc, query)

        if code == 500:
            abort(500, res['status'])

        res['signs'] = doc['result']
        return res, code


