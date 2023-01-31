#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import json, os
from dap_flask.app import app, api
from .signing_service_api import api as ss_api

api.add_namespace(ss_api)

def run(dump=False):
    if dump:
        with app.test_request_context():
            print(json.dumps(api.__schema__, indent=4))
    else:
        port = 5002
        if 'SIGNING_SERVICE_PORT' in os.environ:
            port = int(os.environ['SIGNING_SERVICE_PORT'])
        # app.run(ssl_context='adhoc', debug=False, host='0.0.0.0', port=port)
        app.run(debug=False, host='0.0.0.0', port=port)
