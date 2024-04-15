from pymongo import MongoClient
from pymongo.errors import CollectionInvalid
from pymongo.server_api import ServerApi


def get_database(db_uri: str, db_keyfile_path: str):
    client = MongoClient(db_uri,
                         tls=True,
                         tlsCertificateKeyFile=db_keyfile_path,
                         server_api=ServerApi('1'))

    db = client['users']
    return db


def cred_db_connect(db_uri, db_keyfile_path):
    try:
        database = get_database(db_uri, db_keyfile_path)
        collection = database["cred"]
        print("Database['cred'] connected")
        return collection
    except CollectionInvalid:
        print("Getting collection failed, please make sure the collection is named 'cred'")


def nonce_db_connect(db_uri, db_keyfile_path):
    try:
        database = get_database(db_uri, db_keyfile_path)
        collection = database["nonce"]
        print("Database['nonce'] connected")
        return collection
    except CollectionInvalid:
        print("Getting collection failed, please make sure the collection is named 'cred'")
