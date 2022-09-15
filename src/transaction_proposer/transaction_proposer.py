#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import json, os
from dap_flask.app import app, db, api
from dap_flask.user import User
from dap_flask.authentication import api as auth_api
from .seed import api as seed_api
from .admin import api as admin_api

api.add_namespace(auth_api)
api.add_namespace(seed_api)
api.add_namespace(admin_api)

def run(dump=False):
    if dump:
        with app.test_request_context():
            print(json.dumps(api.__schema__, indent=4))
    else:
        db.create_all()
        db.session.add(User(username='admin', email='admin@ibm.com', password='passw0rd'))
        db.session.add(User(username='alice', email='alice@ibm.com', password='passw0rd'))
        db.session.add(User(username='bob', email='bob@ibm.com', password='passw0rd'))
        db.session.add(User(username='charlie', email='charlie@ibm.com', password='passw0rd'))
        db.session.add(User(username='eve', email='eve@ibm.com', password='passw0rd'))
        db.session.add(User(username='mallory', email='mallory@ibm.com', password='passw0rd'))
        db.session.commit()

        port = 5000
        if 'TRANSACTION_PROPOSER_PORT' in os.environ:
            port = int(os.environ['TRANSACTION_PROPOSER_PORT'])
        app.run(ssl_context='adhoc', debug=False, host='0.0.0.0', port=port)
