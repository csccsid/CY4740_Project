from argon2 import PasswordHasher
from db import get_database

ph = PasswordHasher()

# modify the credentials.txt for a list of pre-registered user.
credentials = {}
with open('credentials.txt', 'r') as file:
    for line in file:
        username, password = line.strip().split(':')
        credentials[username] = password

hashed_passwords = {username: ph.hash(password) for username, password in credentials.items()}

# Replace the following params with your own database credentials
db = get_database("DB_URI", "DB_KEYFILE_PATH")
collection = db['cred']

for username, hashed_password in hashed_passwords.items():
    collection.insert_one({
        'username': username,
        'hashed_password': hashed_password
    })

