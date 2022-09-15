#!/usr/bin/env python3

import json, os
from dap_flask.app import app, db, api
from dap_flask.user import User
from dap_flask.authentication import api as auth_api
from .approval import api as transactions_api, users_api
from .admin import api as admin_api

api.add_namespace(auth_api)
api.add_namespace(transactions_api)
api.add_namespace(users_api)
api.add_namespace(admin_api)

def run(dump=False):
    if dump:
        with app.test_request_context():
            print(json.dumps(api.__schema__, indent=4))
    else:
        db.create_all()
        db.session.add(User(username='admin', email='admin@ibm.com', password='passw0rd'))
        db.session.add(User(username='chris', email='chris@ibm.com', password='passw0rd'))
        db.session.add(User(username='jon', email='jon@ibm.com', password='passw0rd'))
        db.session.add(User(username='vlad', email='vlad@ibm.com', password='passw0rd'))
        db.session.commit()

        port = 5001
        if 'APPROVAL_SERVER_PORT' in os.environ:
            port = int(os.environ['APPROVAL_SERVER_PORT'])
        app.run(ssl_context='adhoc', debug=False, host='0.0.0.0', port=port)
