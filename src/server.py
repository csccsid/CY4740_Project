import argparse
import asyncio
import base64
import hashlib
import json
import logging
import math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

from util.db import db_connect
from util.crypto import (
    load_key,
    decrypt_with_private_key,
    decrypt_with_dh_key,
    generate_dh_private_key,
    generate_nonce,
    fetch_argon2_params,
    sign_data
)

from asyncio import Lock


OP_ERROR = 0
OP_LOGIN = 1
OP_LOGOUT = 2
OP_AUTH = 3
OP_CMD = 4
OP_MSG = 5
PRIME = (2 ** 1024) - (2 ** 960) - 1 + (2 ** 64) * (int(2 ** 894 * math.pi) + 129093)
GENERATOR = 2

logger = logging.getLogger(__name__)
logging.basicConfig(filename='server.log', encoding='utf-8', level=logging.DEBUG)

DB = None
Server_Private_Key = None
AuthenticatedUsers = {}


def parse_arguments():
    """
    Parse command line arguments for the server.
    """
    parser = argparse.ArgumentParser(description="Instant message exchange app, server side")
    parser.add_argument('-sp', type=int, help='Server port to bind', required=True)
    parser.add_argument('-priv_key_path', type=str, help="Server's private key", required=True)
    parser.add_argument('-db_uri', type=str, help='The uri for mongodb database which stores user credentials')
    parser.add_argument('-db_key_path', type=str, help='Path to the key file for the mongodb database authentication')

    return parser.parse_args()


class TCPAuthServerProtocol(asyncio.Protocol):
    authenticated_users = {}
    lock = asyncio.Lock()

    def __init__(self):
        super().__init__()
        self.transport = None
        self.login_state = "AWAITING_AUTH_REQ"
        self.username = ""
        self.argon2_hash = ""
        self.auth_user_nonce = ""
        self.server_nonce = generate_nonce()
        self.client_modulo = ""
        self.dh_key = ""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        print(f"Connection from {peername}")

    def data_received(self, data):
        message = json.loads(data.decode())
        addr = self.transport.get_extra_info('peername')
        print(f"Received message from {addr}: {message}")
        asyncio.create_task(self.process_message(message, addr))

    async def process_message(self, message, addr):
        try:
            if message.get("op_code") == OP_LOGIN:
                await self.on_login(message, addr)
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.transport.close()

    async def modify_users(self, username, addr):
        async with self.lock:
            self.authenticated_users[username] = addr

    async def on_login(self, message, addr):
        """
        Handles login attempts and responses during the authentication process.

        This method processes two main types of messages based on the current state of login:
        1. 'auth_request': Decrypts the received encrypted credentials, fetches user data from the database,
           generates a Diffie-Hellman key, and sends an authentication challenge encrypted with AES.
        2. 'challenge_response': Verifies the response to the authentication challenge, updates login state,
           and notifies the client of the authentication status.

        Depending on the login_state and the message event type, it performs the necessary cryptographic
        operations and state transitions.

        Parameters:
        - message (dict): A dictionary containing the incoming message with potential keys like 'event' and 'payload'.
        - addr (tuple): The client's address from which the message was received.

        The function updates internal state and prepares responses which involve cryptographic operations
        like decryption using private keys, AES encryption, and signature verification. The results of these
        operations are used to determine the legitimacy of login attempts and to craft appropriate responses.

        Raises:
        - KeyError: If necessary keys are missing in the message.
        - ValueError: If decoding or cryptographic operations fail.
        """
        global OP_LOGIN

        # handling the initial auth request message
        if self.login_state == "AWAITING_AUTH_REQ" and message.get("event") == "auth_request":
            # expecting the first message that is encrypted with the public key
            encrypted_payload_base64 = message["payload"]
            encrypted_payload = base64.b64decode(encrypted_payload_base64)
            decrypted_payload_bytes = decrypt_with_private_key(Server_Private_Key, encrypted_payload)
            decrypted_payload = json.loads(decrypted_payload_bytes.decode('ascii'))

            # fetch user credentials from DB and construct challenge.
            username = decrypted_payload["username"]
            self.username = username
            user_doc = DB.find_one({"username": username})
            if user_doc:
                password_hash = user_doc.get("hashed_password")
                self.argon2_hash = password_hash
                argon2_params = fetch_argon2_params(password_hash)
                self.auth_user_nonce = decrypted_payload["nonce"]
                self.client_modulo = decrypted_payload["modulo"]

                # sign the argon2 params
                argon2_params_signature = sign_data(Server_Private_Key, json.dumps(argon2_params).encode('ascii'))
                argon2_params_signature_encoded = base64.b64encode(argon2_params_signature).decode(
                    'ascii')  # Convert to base64 string for JSON

                secret = generate_dh_private_key()
                self.dh_key = pow(self.client_modulo, secret, PRIME)
                server_modulo = pow(GENERATOR, secret, PRIME)

                # generate the initial key
                key_prime_content = {"nonce": self.auth_user_nonce,
                                     "password_hash": self.argon2_hash}

                # Convert the dictionary to a JSON string to ensure consistent ordering
                content_string = json.dumps(key_prime_content, sort_keys=True)

                # Encode the string to bytes
                content_bytes = content_string.encode('ascii')
                hash_object = hashlib.sha256(content_bytes)
                key_prime = hash_object.digest()

                iv = os.urandom(16)

                challenge_content = {"client_nonce": self.auth_user_nonce,
                                     "server_nonce": self.server_nonce,
                                     "server_modulo": server_modulo}

                cipher = Cipher(algorithms.AES(key_prime), modes.CFB(iv), backend=default_backend())

                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(json.dumps(challenge_content).encode()) + encryptor.finalize()

                ciphertext_encoded = base64.b64encode(ciphertext).decode('ascii')
                iv_encoded = base64.b64encode(iv).decode('ascii')

                payload = {"argon2_params": argon2_params,
                           "argon2_params_signature": argon2_params_signature_encoded,
                           "challenge": ciphertext_encoded,
                           "iv": iv_encoded}

                auth_req_response = {
                    "op_code": OP_LOGIN,
                    "event": "auth_request_challenge",
                    "payload": json.dumps(payload)  # This stays as a string
                }

                print(f"Sent: {auth_req_response}")
                print(f"Server nonce is: {self.server_nonce}")
                self.transport.write(json.dumps(auth_req_response).encode())
                self.login_state = "AWAITING_CHALLENGE_RESP"
            else:
                print(f"User not found {self.username}")
                user_not_found = {"op_code": OP_LOGIN, "event": "user not found", "payload": ""}
                self.transport.write(json.dumps(user_not_found).encode())

        # this is the second client message received, server expecting the server_nonce encrypted with dh_key
        elif self.login_state == "AWAITING_CHALLENGE_RESP" and message.get("event") == "challenge_response":
            # Verify the challenge response
            # Message should be encrypted with the sha256 hash of dh_key
            chal_resp_payload = json.loads(message['payload'])
            decrypted_json = decrypt_with_dh_key(dh_key=self.dh_key,
                                                 cipher_text=chal_resp_payload["ciphertext"],
                                                 iv=chal_resp_payload["iv"])

            # client should be able to use the password derived key to decrypt payload
            # and obtain server_nonce
            if decrypted_json.get("server_nonce") == self.server_nonce:
                response = {"op_code": OP_LOGIN, "event": "auth successful", "payload": ""}
            else:
                response = {"op_code": OP_LOGIN, "event": "auth failed", "payload": ""}

            # notify client status of login
            self.transport.write(json.dumps(response).encode())
            self.login_state = "AUTHENTICATED"  # Or reset to "AWAITING_AUTH_REQ" if failed
            await self.modify_users(self.username, addr)
            print(self.authenticated_users)

        # wrong event during states or unexpected event
        else:
            # Unexpected message type or sequence
            error_msg = {"event": "error", "message": "Unexpected message or state."}
            self.transport.write(json.dumps(error_msg).encode())

    def connection_lost(self, exc):
        if exc:
            print(f"Error on connection: {exc}")
        else:
            print("Connection closed by client.")
        super().connection_lost(exc)


async def main(sp):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(TCPAuthServerProtocol, '127.0.0.1', sp)
    print("Starting TCP server...")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    args = parse_arguments()
    DB = db_connect(args.db_uri, args.db_key_path)
    Server_Private_Key = load_key(args.priv_key_path, public=False)
    try:
        if DB is not None and Server_Private_Key is not None:
            asyncio.run(main(args.sp))
        else:
            print(f"Database not connected or missing private key")
    except KeyboardInterrupt:
        print("Server stopped manually.")
