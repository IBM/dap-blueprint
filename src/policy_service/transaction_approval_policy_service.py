# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

from polling_service import PollingService
import dap_consts

class TransactionApprovalPolicyService(PollingService):

    def __init__(self, reboot = False):
        super().__init__(
            serviceid=dap_consts.TRANSACTION_APPROVAL_POLICY_SERVICE,
            query={
                '$or': [{'request.type': {'$eq': x}} for x in dap_consts.REQUEST_TYPES],
                dap_consts.TRANSACTION_APPROVAL_POLICY_SERVICE: {'$eq': None}
            },
            response=dap_consts.TRANSACTION_APPROVAL_POLICY_SERVICE,
            reboot=reboot
        )

        self.malicious_users = ['eve', 'mallory']

        self._post_ready_status(with_pubkey=True)

    def verify(self, doc):
        if self.skip_verification:
            return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

        params = self._get_params(doc)
        if 'userid' in params and params['userid'] in self.malicious_users:
            return dap_consts.DAP_VERIFICATION_FAIL, 'Your request is rejected in {}. Please contact an administrator.'.format(self.serviceid), doc

        return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

def run(reboot=False):
    TransactionApprovalPolicyService(reboot=reboot).run()
