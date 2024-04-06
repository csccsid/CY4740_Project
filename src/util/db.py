from pymongo import MongoClient
from pymongo.server_api import ServerApi


def get_database():
    uri = (
        "mongodb+srv://server-users.5lef1kv.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites"
        "=true&w=majority&appName=server-users")
    client = MongoClient(uri,
                         tls=True,
                         tlsCertificateKeyFile='<path to cert>',
                         server_api=ServerApi('1'))

    db = client['users']
    return db


# This is added so that many files can reuse the function get_database()
if __name__ == "__main__":
    # Get the database
    dbname = get_database()
