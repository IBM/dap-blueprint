# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import json, os
from pprint import pprint
import re
from ssl import ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE
import dbaas, dap_hpcs, dap_crypto, dap_consts
from dap_resource import DAPCommonResource, DAPSSResource
from pymongo.errors import PyMongoError

class PollingService:

    def __init__(self, serviceid, query, response, reboot=False):
        if serviceid == dap_consts.SIGNING_SERVICE:
            self.resource = DAPSSResource(reboot=reboot, serviceid=serviceid)
        else:
            self.resource = DAPCommonResource(reboot=reboot, serviceid=serviceid)
        self.serviceid = serviceid
        self.query = query
        self.response = response
        print('query={}'.format(self.query))

        self.skip_verification = False
        if 'SKIP_VERIFICATION' in os.environ and os.environ['SKIP_VERIFICATION']:
            self.skip_verification = True

        self.__skip_hpcs_verify = False
        if 'SKIP_HPCS_VERIFY' in os.environ and os.environ['SKIP_HPCS_VERIFY']:
            self.__skip_hpcs_verify = True

    def _post_ready_status(self, with_pubkey=False):
        doc = {
            'type': 'ServiceStatus',
            'serviceid': self.serviceid,
            'status': 'ok'
        }
        if with_pubkey:
            doc['pubkey'] = self.resource.pubkey.hex()
            doc['pubkey_hmac'] = dap_crypto.gen_hmac(self.resource.pubkey.hex(), self.resource.common_key1)
        dbaas.enqueue(self.resource.txqueue_client, self.resource.queue_name, doc)

    def _get_request(self, doc):
        if 'request' not in doc:
            return None
        return doc['request']

    def _get_type(self, doc):
        request = self._get_request(doc)
        if request is None or 'type' not in request:
            return None
        return request['type']

    def _get_method(self, doc):
        request = self._get_request(doc)
        if request is None or 'method' not in request:
            return None
        return request['method']

    def _get_params(self, doc):
        request = self._get_request(doc)
        if request is None or 'params' not in request:
            return None
        return request['params']

    def verify(self, doc):
        raise NotImplementedError('This function must be implemented in each inheriting service.')

    def execute(self, doc):
        method = self._get_method(doc)
        if method is not None and method == dap_consts.UPDATE_PS_KEYS_METHOD:
            self.resource.update_rsa_keys(self.serviceid)
            doc['result'] = 'RSA keys were updated in ' + self.serviceid
            doc['status'] = 'ok'
            doc[self.response] = 'done'
            doc[dap_consts.SIGNING_SERVICE] = 'dummy'
        elif self.resource.privkey:
            if self.__skip_hpcs_verify:
                doc[self.response] = 'ok'
            else:
                doc[self.response] = dap_hpcs.sign(self.resource.privkey,
                                                json.dumps(doc['request']),
                                                hpcs_credentials=self.resource.hpcs_credentials,
                                                hpcs_address=self.resource.hpcs_address).hex()
        else:
            raise Exception('No signing key')

    def enqueue(self, doc):
        dbaas.enqueue(self.resource.txqueue_client, self.resource.queue_name, doc)

    def process(self, doc):
        try:
            print('\n-------------------------------------------------')

            print('Verifying ...')
            status, msg, doc = self.verify(doc)
            if status == dap_consts.DAP_VERIFICATION_FAIL:
                # Verification failure
                doc['status'] = 'fail'
                doc['result'] = msg
                doc[self.response] = msg
                if not doc[dap_consts.SIGNING_SERVICE]:
                    doc[dap_consts.SIGNING_SERVICE] = msg
            elif status == dap_consts.DAP_VERIFICATION_WAIT:
                print('Waiting for human verification ...')
                return
            elif status == dap_consts.DAP_VERIFICATION_SUCCEED:
                print('Signing ...')
                self.execute(doc)
            else:
                raise Exception('Unknown status {}'.format(status))
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            doc['status'] = str(e)
            doc['result'] = str(e)
            doc[self.response] = str(e)
            if not doc[dap_consts.SIGNING_SERVICE]:
                doc[dap_consts.SIGNING_SERVICE] = str(e)

        print('Enqueueing')
        pprint(doc)
        self.enqueue(doc)

    # This function needs to be overriden if there are any other resources that have txqueue clients (e.g., approval server)
    def update_txqueue_client(self):
        self.resource.update_txqueue_client()

    def run(self):
        while True:
            try:
                docs = dbaas.poll(self.resource.txqueue_client, self.resource.queue_name, self.query)
                for doc in docs:
                    self.process(doc)
            except PyMongoError:
                # Update my mongo client because we caught an exception caused by killAllSessions.
                self.update_txqueue_client()
