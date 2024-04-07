from argon2 import PasswordHasher
from db import get_database

# Initialize the PasswordHasher
ph = PasswordHasher()

# Step 1: Read the credentials.txt file
credentials = {}
with open('credentials.txt', 'r') as file:
    for line in file:
        username, password = line.strip().split(':')
        credentials[username] = password

# Step 2: Hash passwords
hashed_passwords = {username: ph.hash(password) for username, password in credentials.items()}

# Connect to MongoDB
db = get_database()
collection = db['cred']

# Step 3: Insert into MongoDB
for username, hashed_password in hashed_passwords.items():
    collection.insert_one({
        'username': username,
        'hashed_password': hashed_password
    })

