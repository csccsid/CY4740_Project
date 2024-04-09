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
    encrypt_with_public_key,
    generate_dh_private_key,
    generate_nonce,
    fetch_argon2_params,
    sign_data
)

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
        self.process_message(message, addr)

    def process_message(self, message, addr):
        global OP_LOGIN
        # Process authentication based on message and current state
        # Placeholder for authentication logic
        match message.get("op_code"):
            case OP_LOGIN:
                return self.on_login(message, addr)
        # response = json.dumps({"status": "ok"})
        # self.transport.write(response.encode())

    def on_login(self, message, addr):
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
            # Process the initial authentication request

        elif self.login_state == "AWAITING_CHALLENGE_RESP" and message.get("event") == "challenge_response":
            # Verify the challenge response

            bytes_length = (self.dh_key.bit_length() + 7) // 8  # Calculate the number of bytes needed
            dh_key_bytes = self.dh_key.to_bytes(bytes_length, byteorder='big')
            hash_object = hashlib.sha256(dh_key_bytes)
            dh_key_sha = hash_object.digest()

            chal_resp_payload = json.loads(message['payload'])
            print(chal_resp_payload)
            cipher_text = base64.b64decode(chal_resp_payload["ciphertext"])
            chal_iv = base64.b64decode(chal_resp_payload["iv"])
            cipher = Cipher(algorithms.AES(dh_key_sha), modes.CFB(chal_iv), backend=default_backend())

            # Decrypt the data
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

            # Convert the decrypted data back to a string (assuming it was originally a JSON string)
            decrypted_string = decrypted_data.decode('ascii')
            decrypted_json = json.loads(decrypted_string)
            if decrypted_json.get("server_nonce") == self.server_nonce:
                response = {"event": "auth_status", "status": "success"}
            else:
                response = {"event": "auth_status", "status": "failure"}
            self.transport.write(json.dumps(response).encode())
            self.login_state = "AUTHENTICATED"  # Or reset to "AWAITING_AUTH_REQ" if failed
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
