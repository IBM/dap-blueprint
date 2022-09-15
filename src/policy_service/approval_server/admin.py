import json
from os import abort
from pprint import pprint
from dap_client import update_db_password
from flask import request
from flask_restx import Resource, Namespace, fields
from dap_util import txqueue, dap_consts
from dap_flask.app import oidc, header_parser, authorization_failure_response_model, check_admin, resource, mail
from . import approval_table

api = Namespace('admin', description='Admin APIs')

create_approval_request_model = api.model('CreateApprovalRequest', {
    'userid': fields.String(descripttion='A user who initiates this transaction'),
    'seedid': fields.String(descripttion='Seed ID'),
    'psbt': fields.String(description='PSBT transaction'),
    'amount': fields.Float(description='Total amount to be sent'),
    'daily_amount': fields.Float(description='Total amount sent and to be sent in 24 hours'),
    'doc': fields.String(description='Original document to be approved as a JSON string')
})

create_approval_response_model = api.model('CreateApprovalResponse', {
    'status': fields.String(description='ok or fail'),
    'psbt': fields.String(description='PSBT transaction'),
    'process_instance_id': fields.String(description='RHPAM process instance id')
})

end_approval_response_model = api.model('CreateApprovalResponse', {
    'status': fields.String(description='ok or fail'),
    'approved': fields.Boolean(description='true or false')
})

update_db_password_response_model = api.model('UpdateDBPasswordResponse', {
    'status': fields.String(description='ok or fail')
})

def _send_approval_result(record, approval):
    doc = {
        'request': {'type': dap_consts.APPROVAL_RESULT},
        'result': approval,
        'doc': record.doc
    }
    for serviceid in dap_consts.POLICY_SERVICES:
        if serviceid == dap_consts.AUTHORIZATION_POLICY_SERVICE:
            doc[serviceid] = None
        else:
            doc[serviceid] = 'dummy'
    txqueue.enqueue(resource.txqueue_client, doc)

@api.route('/approval')
@api.expect(header_parser) # Header
class CreateApproval(Resource):

    @api.expect(create_approval_request_model)
    @api.response(code=200, description='Success', model=create_approval_response_model)
    @api.response(code=422, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Create an approval request (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self):
        print('CreateApproval')
        json_data = request.json

        res = {
            'status': None,
            'psbt': None,
            'process_instance_id': None
        }
        record = approval_table.create_transaction_record(
            json_data['psbt'],
            json_data['userid'],
            json_data['seedid'],
            json_data['amount'],
            json_data['daily_amount'],
            json_data['doc'])
        print('Transaction record created')

        res['status'] = 'ok'
        res['psbt'] = json_data['psbt']
        res['process_instance_id'] = record.process_instance_id

        if record.processed:
            _send_approval_result(record, True)

        return res, 200

@api.route('/approval/<string:process_instance_id>/<string:approved>')
@api.expect(header_parser) # Header
class EndApproval(Resource):

    @api.response(code=200, description='Success', model=end_approval_response_model)
    @api.response(code=422, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='End an approval process (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def patch(self, process_instance_id, approved):
        print('EndApproval')
        res = {
            'status': None,
            'approved': None
        }

        record = approval_table.get_record(process_instance_id)
        if not record:
            res['status'] = 'fail'
            res['approved'] = 'Approval record not found'
            return res, 500

        if approved == 'true':
            approved = True
        elif approved == 'false':
            approved = False
        else:
            res['status'] = 'fail'
            res['approved'] = 'Unknown approved value ' + approved
            return res, 500

        if record.processed:
            res['status'] = 'ok'
            res['approved'] = 'Already processed'
            return res, 200

        record.processed = True
        _send_approval_result(record, approved)
        res['status'] = 'ok'
        res['approved'] = approved
        print('returning ' + str(res))
        return res, 200

@api.route('/dbs/<string:name>')
@api.expect(header_parser) # Header
class UpdateDBPassword(Resource):

    @api.response(code=200, description='Success', model=update_db_password_response_model)
    @api.response(code=422, description='API token authorization faulure', model=authorization_failure_response_model) 
    @api.doc(description='Update the password for a DBaaS instance (admin-only API)')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='admin')
    def post(self, name):
        if name != 'txqueue':
            abort(500, 'Unknown db name ' + name)
        resource.update_txqueue_client()

        return {'status': 'ok'}, 200
