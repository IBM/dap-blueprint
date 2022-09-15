#!/usr/bin/env python3

from pymongo import MongoClient
from pymongo.errors import PyMongoError
import os, argparse, json
from pprint import pprint

def get_client(hosts, cafile, replicaset, user, password):
    if not os.path.exists(cafile):
        print('CA file ' + str(cafile) + ' does not exist')
        return None, None

    url = 'mongodb://' + hosts
    return MongoClient(url,
                       tls = True,
                       tlsCAFile=cafile,
                       replicaset=replicaset,
                       username=user,
                       password=password,
                       authSource='admin',
                       authMechanism='SCRAM-SHA-256')

def get_client_from_info(dbaas_info):
    return get_client(
        hosts=dbaas_info['HOSTS'],
        cafile=dbaas_info['CA_FILE'],
        replicaset=dbaas_info['REPLICA_SET'],
        user=dbaas_info['USER'],
        password=dbaas_info['PASSWORD']
    )

def get_client_from_envs(instance):
    if instance == 'walletdb':
        hosts = os.environ['WALLETDB_HOSTS']
        password = os.environ['WALLETDB_PASSWORD']
        replicaset = 'walletdb'
    elif instance == 'txqueue':
        hosts = os.environ['TXQUEUE_HOSTS']
        password = os.environ['TXQUEUE_PASSWORD']
        replicaset = 'txqueue'
    elif instance == 'test':
        hosts = os.environ['DBAAS_HOSTS']
        password = os.environ['DBAAS_PASSWORD']
        replicaset = 'test'
    else:
        raise Exception('Unknown instance ' + instance)
    return get_client(
        hosts=hosts,
        cafile=os.environ['DBAAS_CA_FILE'],
        replicaset=replicaset,
        user='admin',
        password=password)

def get_db(client, name):
    return client[name]

def delete_db(client, name):
    client.drop_database(name)

def list_dbs(client):
    return client.list_databases()

def get_col(client, name):
    return get_db(client, name)[name]

def list_cols(client, name):
    return get_db(client, name).list_collections()

def enqueue(client, name, doc):
    queue = get_col(client, name)
    queue.insert(doc)
    return doc

def dequeue(client, name, query):
    queue = get_col(client, name)
    doc = queue.find_one_and_delete(filter=query, sort=[('_id', 1)], projection={'_id': False})
    return doc

def store(client, name, query, doc):
    col = get_col(client, name)
    col.update_one(filter=query, update={'$set': doc}, upsert=True)

def update_all(client, name, update):
    col = get_col(client, name)
    return col.update_many(filter={}, update=update)

def get(client, name, query):
    col = get_col(client, name)
    return col.find_one(query)

def delete(client, name, query):
    col = get_col(client, name)
    return col.delete_one(query)

def dequeue_all(client, name, query):
    docs = []
    while True:
        doc = dequeue(client, name, query)
        if doc is None:
            break
        else:
            docs.append(doc)
    return docs

def poll(client, name, query, max_await_time_ms=1000, wait_infinitely=True):
    queue = get_col(client, name)
    pipeline = [{'$match': {'operationType': 'insert'}}]

    while True:
        try:
            with queue.watch(pipeline=pipeline, max_await_time_ms=max_await_time_ms) as stream:
                docs = dequeue_all(client, name, query)
                if docs:
                    return docs
                print('Watching ' + name + ' queue ...')
                if wait_infinitely:
                    for _ in stream:
                        break
                else:
                    while stream.alive:
                        s = stream.try_next()
                        if not s:
                            return None
                        break
        except PyMongoError as e:
            print(type(e))
            print(str(e))
            print(e.code)
            if e.code == 11601:
                print('Throwing an exception to update a mongo client')
                raise e
            print('Queue watching error. Restarting ...')

def process_request(client, name, doc, query):
    print('\n-------------------------------------------------')
    print('Enqueueing')
    pprint(doc)
    enqueue(client, name, doc)
        
    print('\n-------------------------------------------------')
    print('Waiting for ' + str(query))
    doc = poll(client, name, query)[0]

    print('\n-------------------------------------------------')
    print('Received a signed document')
    pprint(doc)
    return doc

def update_password(client, name, user, password):
    db = get_db(client, name)
    db.command('updateUser', user, pwd=password)

def kill_all_sessions(client):
    db = get_db(client, 'admin')
    db.command({'killAllSessions': []})

### Wrapper for CLI ###

def enqueue_(client, args):
    enqueue(client, args.name, json.loads(args.doc))

def dequeue_(client, args):
    doc = dequeue(client, args.name, json.loads(args.query))
    pprint(doc)

def poll_(client, args):
    doc = poll(client, args.name, json.loads(args.query))
    pprint(doc)

def delete_db_(client, args):
    delete_db(client, args.name)

def list_dbs_(client, args):
    dbs = list_dbs(client)
    for db in dbs:
        print(db)

def list_cols_(client, args):
    cols = list_cols(client, args.name)
    for col in cols:
        print(col)

def list_docs(client, name):
    return get_col(client, name).find({})

def list_docs_(client, args):
    docs = list_docs(client, args.name)
    for doc in docs:
        print(doc)

def delete_docs(client, name):
    get_col(client, name).delete_many({})

def delete_docs_(client, args):
    delete_docs(client, args.name)

def store_(client, args):
    store(client, args.name, args.query, args.doc)

def get_(client, args):
    doc = get(client, args.name, json.loads(args.query))
    pprint(doc)

def delete_(client, args):
    delete(client, args.name, json.loads(args.query))

def update_password_(client, args):
    update_password(client, args.name, args.user, args.password)

def kill_all_sessions_(client, args):
    kill_all_sessions(client)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--instance', default='txqueue')
    parser.add_argument('--name', default='txqueue')
    subparsers = parser.add_subparsers(title='commands')

    enqueue_parser = subparsers.add_parser('enqueue', help='Enqueue a document')
    enqueue_parser.add_argument('doc')
    enqueue_parser.set_defaults(func=enqueue_)

    dequeue_parser = subparsers.add_parser('dequeue', help='Dequeue a document')
    dequeue_parser.add_argument('query')
    dequeue_parser.set_defaults(func=dequeue_)

    poll_parser = subparsers.add_parser('poll', help='Poll a document')
    poll_parser.add_argument('query')
    poll_parser.set_defaults(func=poll_)

    delete_db_parser = subparsers.add_parser('delete-db', help='Delete a DB')
    delete_db_parser.set_defaults(func=delete_db_)

    list_dbs_parser = subparsers.add_parser('list-dbs', help='List DBs')
    list_dbs_parser.set_defaults(func=list_dbs_)

    list_cols_parser = subparsers.add_parser('list-cols', help='List collections')
    list_cols_parser.set_defaults(func=list_cols_)

    list_docs_parser = subparsers.add_parser('list-docs', help='List documents')
    list_docs_parser.set_defaults(func=list_docs_)

    delete_docs_parser = subparsers.add_parser('delete-docs', help='Delete documents')
    delete_docs_parser.set_defaults(func=delete_docs_)

    store_parser = subparsers.add_parser('store', help='Store a document')
    store_parser.add_argument('query')
    store_parser.add_argument('doc')
    store_parser.set_defaults(func=store_)

    get_parser = subparsers.add_parser('get', help='Get a document')
    get_parser.add_argument('query')
    get_parser.set_defaults(func=get_)

    delete_parser = subparsers.add_parser('delete', help='Delete a document')
    delete_parser.add_argument('query')
    delete_parser.set_defaults(func=delete_)

    update_password_parser = subparsers.add_parser('update_password', help='Update a password for a DB')
    update_password_parser.add_argument('user')
    update_password_parser.add_argument('password')
    update_password_parser.set_defaults(func=update_password_)

    kill_all_sessions_parser = subparsers.add_parser('kill_all_sessions', help='Kill all sessions')
    kill_all_sessions_parser.set_defaults(func=kill_all_sessions_)

    args = parser.parse_args()
    client = get_client_from_envs(args.instance)
    if hasattr(args, 'func'):
        args.func(client, args)
    else:
        parser.parse_args('-h')
