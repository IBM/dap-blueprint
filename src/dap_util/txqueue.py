# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import uuid
import dbaas, dap_consts

def _check_documents(docs):
    doc = None
    if docs is None or len(docs) == 0:
        status = 'No response from backend services'
        code = 500
    elif len(docs) > 1:
        status = 'Multiple responses from backend services'
        code = 500
    else:
        doc = docs[0]
        status = doc['status']
        if status != 'ok' and status != 'fail':
            code = 500
        else:
            code = 200
    return doc, code, status

def _check_document(doc):
    if doc is None:
        status = 'No response from backend services'
        code = 500
    else:
        status = doc['status']
        if status != 'ok' and status != 'fail':
            code = 500
        else:
            code = 200
    return doc, code, status

def send_request(txqueue_client, doc, query):
    dbaas.enqueue(txqueue_client, 'txqueue', doc)
    return _check_documents(dbaas.poll(txqueue_client, 'txqueue', query))

def enqueue(txqueue_client, doc):
    dbaas.enqueue(txqueue_client, 'txqueue', doc)
    return doc, 200, 'ok'

def dequeue(txqueue_client, query):
    return _check_document(dbaas.dequeue(txqueue_client, 'txqueue', query))

def poll(txqueue_client, query, wait_infinitely=True):
    return _check_documents(dbaas.poll(txqueue_client, 'txqueue', query, wait_infinitely=wait_infinitely))

def kill_all_sessions(txqueue_client):
    dbaas.kill_all_sessions(txqueue_client)

def cleanup(txqueue_client):
    dbaas.delete_docs(txqueue_client, 'txqueue')

def create_request_document(type, method, params={}):
    doc = {
        'request': {
            'type': type,
            'id': str(uuid.uuid1()),
            'method': method,
            'params': params
        },
        'result': None,
        'status': None,
        dap_consts.SIGNING_SERVICE: None
    }
    for serviceid in dap_consts.POLICY_SERVICES:
        doc[serviceid] = None
    return doc

def create_response_query(type, id):
    return {
        'request.id': {'$eq': id},
        'result': {'$ne': None}
    }
