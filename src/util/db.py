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


def db_connect(db_uri, db_keyfile_path, collection_name):
    try:
        database = get_database(db_uri, db_keyfile_path)
        collection = database[collection_name]
        print(f"Database['{collection_name}'] connected")
        return collection
    except CollectionInvalid:
        print(f"Getting collection failed with name {collection_name}")
