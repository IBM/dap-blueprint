import json, uuid
from pprint import pprint
from flask_restx import Resource, Namespace, fields
from dap_util import electrum_client
from dap_flask.app import oidc, header_parser, authorization_failure_response_model, resource
from . import approval_table

api = Namespace('transactions', description='Approver APIs to obtain the transaction information')
users_api = Namespace('users', description='Approver APIs to obtain the user information')

##### Model for transactions of a specified user #####
user_transactions_response_model = users_api.model('UserTransactionsResponse', {
    'transactions': fields.List(fields.String, description='list of transactions'),
    'status': fields.String(description='status message')
})

##### Transaction details model #####
transaction_details_response_model = api.model('TransactionDetailResponse', {
    'userid': fields.String(description='User ID initiating this transaction'),
    'amount': fields.Float(description='Amount to be sent'),
    'daily_amount': fields.Float(description='Total amount sent and to be sent with 24 hours'),
    'psbt': fields.String(description='Deserialized transaction'),
    'status': fields.String(description='status message')
})

@api.route('/<string:process_instance_id>')
@api.expect(header_parser) # Header
class TransactionDetails(Resource):

    @api.response(code=200, description='Success', model=transaction_details_response_model)
    @api.response(code=422, description='API token authorization faulure', model=authorization_failure_response_model)
    @api.doc(description='An approver obtains the user id of the owner of the master seed for transaction inputs and the psbt in a json format. The policy service will return an error if the transaction is not being assigned to the approver.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='approver')
    def get(self, process_instance_id):
        res = {
            'userid': None,
            'rules': None,
            'amount': None,
            'daily_amount': None,
            'psbt': None,
            'status': None
        }

        record = approval_table.get_record(process_instance_id)

        if not record:
            res['status'] = 'No approval process for process_instance_id=' + process_instance_id
        elif record and record.processed == False:
            res['userid']       = record.userid
            res['amount']       = record.amount
            res['daily_amount'] = record.daily_amount
            res['psbt']         = electrum_client.desrialize(record.psbt)['result']

            res['status'] = 'Waiting for approval'
        else:
            res['status'] = 'Already processed'
        return res, 200

@users_api.route('/<string:userid>/transactions/hours/<int:hours>')
@users_api.expect(header_parser) # Header
class UserTransactions(Resource):

    @users_api.response(code=200, description='Success', model=user_transactions_response_model)
    @users_api.response(code=422, description='API token authorization faulure', model=authorization_failure_response_model)
    @users_api.doc(description='An approver obtains a list of all transactions within a specified hours with inputs from a seed owned by a specified user. An approver can check the recent history of transactions from the user.')
    @oidc.accept_token(render_errors=False, require_token=True, scopes_required=['openid'])
    @oidc.require_keycloak_role(role='approver')
    def get(self, userid, hours):
        psbts, transactions = approval_table.get_user_transactions(userid, hours)
        if not transactions:
            status = 'You have no transactions to be approved for this user.'
        else:
            status = 'The first {} transactions are waiting for your signs.'.format(len(psbts))

        return {
            'transactions': psbts + transactions,
            'status': '{} has {} transactions'.format(userid, len(psbts) + len(transactions))
        }, 200
