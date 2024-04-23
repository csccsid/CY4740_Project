import argparse
import asyncio
import base64
import datetime
import json
import logging
import math

from KeyManager import AuthenticationKeyManager
from util.crypto import (
    load_key,
    decrypt_with_private_key,
    decrypt_with_dh_key,
    generate_dh_private_key,
    generate_nonce,
    fetch_argon2_params,
    encrypt_with_dh_key,
    encrypt_with_key_prime,
    sign_data,
)
from util.db import db_connect

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

cred_db = None
nonce_db = None
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


def verify_timestamp(message_timestamp, validity_period=120):
    # Current time in UTC
    now = datetime.datetime.now(datetime.timezone.utc)
    current_timestamp = int(now.timestamp())

    # Check if the current timestamp is within the valid time period
    if current_timestamp - message_timestamp <= validity_period:
        return True
    else:
        return False


class TCPAuthServerProtocol(asyncio.Protocol):
    key_manager = AuthenticationKeyManager()
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
            # Using int rather than OP_XXX because of some python match case issue.
            match message.get("op_code"):
                case 1:
                    await self.on_login(message, addr)
                case 2:
                    self.on_logout(message, addr)
                case 3:
                    self.on_auth(message, addr)
                case 4:
                    self.on_cmd(message, addr)
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.transport.close()

    def on_logout(self, message, addr):
        """
        Handles client log out request, the login state will be terminated under the following conditions:
        1. The session has been established for more than 30 minutes.
        2. The client manually send the logout request to server.
        In both cases, the server will delete client's shared key from key manager.

        The logout request payload should be encrypted with the shared session key, with content:
        {
            "timestamp": <timestamp>
            "username": <username>
        }

        """
        if message["event"] == "logout":
            logout_payload = json.loads(message["payload"])

            logout_request_cipher = logout_payload['ciphertext']
            logout_request_gcm_nonce = logout_payload['gcm_nonce']
            logout_request_gcm_tag = logout_payload['gcm_tag']
            logout_request_user = logout_payload['username']

            if (logout_request_cipher is None
                    or logout_request_gcm_nonce is None
                    or logout_request_user is None):
                self.reset_connection(f"Invalid logout request: {message['payload']}")
                return

            logout_request_user_dh_key = self.key_manager.get_dh_key_by_username(logout_request_user)
            logout_request = decrypt_with_dh_key(logout_request_user_dh_key,
                                                 logout_request_cipher,
                                                 logout_request_gcm_nonce,
                                                 logout_request_gcm_tag)

            if logout_request is None:
                self.reset_connection(f"Invalid logout request: {message['payload']}")
                return

            if (verify_timestamp(logout_request['timestamp'])
                    and logout_request['username'] == logout_request_user):
                self.key_manager.remove_user(logout_request_user)
                print(f'Logged out user: {logout_request_user} with addr {addr}')
            else:
                self.reset_connection(f"Invalid timestamp: {logout_request['timestamp']}")
                return

    def on_auth(self, message, addr):
        """
        Handle message forwarded by client to client authentication by the receiver end client.
        Assuming two clients A and B, and A is trying to communicate with B, this function should receive from B
        and sends back N_c, K_a{N_a, K_ab}, K_b{N_b, K_ab} to B

        :param message: auth message from receiver client
        :param addr: address of that receiver client
        """

        if message["event"] == "auth_forward_request":
            client_auth_payload = json.loads(message["payload"])

            sender_info = json.loads(client_auth_payload['sender_info'])
            receiver_info = json.loads(client_auth_payload['receiver_info'])

            client_send_dh_key = self.key_manager.get_dh_key_by_username(sender_info['username'])
            client_recv_dh_key = self.key_manager.get_dh_key_by_username(receiver_info['username'])

            client_source_cipher = client_auth_payload["sender_ciphertext"]
            client_source_gcm_nonce = client_auth_payload["sender_gcm_nonce"]
            client_source_gcm_tag = client_auth_payload["sender_gcm_tag"]

            client_recv_cipher = client_auth_payload["receiver_ciphertext"]
            client_recv_gcm_nonce = client_auth_payload["receiver_gcm_nonce"]
            client_recv_gcm_tag = client_auth_payload["receiver_gcm_tag"]

            if any(v is None for v in [
                client_source_cipher,
                client_source_gcm_nonce,
                client_recv_cipher,
                client_source_gcm_tag,
                client_recv_gcm_nonce,
                client_send_dh_key,
                client_recv_dh_key,
                client_recv_gcm_tag
            ]):
                self.reset_connection(f"Bad request for on_auth between {sender_info} and {receiver_info}")
            else:

                client_source_payload = decrypt_with_dh_key(client_send_dh_key,
                                                            client_source_cipher,
                                                            client_source_gcm_nonce,
                                                            client_source_gcm_tag)

                client_recv_payload = decrypt_with_dh_key(client_recv_dh_key,
                                                          client_recv_cipher,
                                                          client_recv_gcm_nonce,
                                                          client_recv_gcm_tag)

                # entering a series of checking,
                # check if the session identifier match or has been replayed
                if (client_recv_payload['session_identifier'] != client_source_payload['session_identifier']
                        or nonce_db.find_one({'nonce': client_recv_payload['session_identifier']})):
                    self.reset_connection(f"Invalid nonce, possible replay attack")

                # check if the sender, receiver addr matches
                elif (client_recv_payload['sender_info'] != client_source_payload['sender_info']
                      or client_recv_payload['receiver_info'] != client_source_payload['receiver_info']):
                    self.reset_connection(f"Receiver or Sender mismatch")

                else:
                    nonce_db.insert_one({'nonce': client_recv_payload['session_identifier']})

                    client_shared_key = generate_dh_private_key()
                    M_nonce = client_recv_payload['session_identifier']

                    client_recv_payload = {
                        'receiver_nonce': client_recv_payload['receiver_nonce'],
                        'channel_key': client_shared_key
                    }

                    client_source_payload = {
                        'sender_nonce': client_source_payload['sender_nonce'],
                        'channel_key': client_shared_key
                    }

                    (client_recv_payload_cipher,
                     client_recv_payload_gcm_nonce,
                     client_recv_payload_gcm_tag) = encrypt_with_dh_key(
                        client_recv_dh_key,
                        client_recv_payload
                    )

                    (client_source_payload_cipher,
                     client_source_payload_gcm_nonce,
                     client_source_payload_gcm_tag) = encrypt_with_dh_key(
                        client_send_dh_key,
                        client_source_payload
                    )

                    payload_json = {
                        'session_identifier': M_nonce,
                        'sender_ciphertext': client_source_payload_cipher,
                        'sender_gcm_nonce': client_source_payload_gcm_nonce,
                        'sender_gcm_tag': client_source_payload_gcm_tag,
                        'receiver_ciphertext': client_recv_payload_cipher,
                        'receiver_gcm_nonce': client_recv_payload_gcm_nonce,
                        'receiver_gcm_tag': client_recv_payload_gcm_tag
                    }

                    auth_request_response = {
                        "op_code": OP_AUTH,
                        "event": "auth_KDC_response",
                        "payload": json.dumps(payload_json)
                    }

                    self.transport.write(json.dumps(auth_request_response).encode('ascii'))
                    print(f"Send KDC response: {auth_request_response}")
                    print(f"Auth request response sent to {addr}")

        else:
            self.reset_connection(f"Invalid auth event for KDC: {message['event']}")

    def reset_connection(self, error_message):
        print(error_message)
        self.transport.close()
        self.__init__()

    def on_cmd(self, message, addr):
        """
        Handle all the commands sent from client, and delegate them to specific handlers

        Currently supported commands:
        - LIST (get all authenticated/logged-in users)

        :param message: request message from client
        :param addr: address of the client
        """

        match message["event"]:
            case "LIST":
                asyncio.create_task(self.on_list(message, addr))

    async def on_list(self, message, addr):
        """
        Process a client's list request to retrieve all usernames. Decrypts the client's message,
        verifies the username, and sends back an encrypted list of usernames.

        Args:
            message (dict): The received message containing 'payload' with encrypted data and an 'iv'.
            addr (tuple): Client's address used to identify the user and their encryption key.

        Returns:
            None: Sends an encrypted response to the client and handles errors internally.
        """

        list_request_payload_json = json.loads(message['payload'])

        username = list_request_payload_json['username']
        dh_key = self.key_manager.get_dh_key_by_username(username)

        # if no session key found for username, send an error response with the original request.
        if dh_key is None:
            print(f"No key found for {username}, user never logged in or key expired")

            key_not_found_resp = {
                "op_code": OP_ERROR,
                "event": "key_not_found",
                "payload": json.dumps(message)
            }

            self.transport.write(json.dumps(key_not_found_resp).encode('ascii'))
            return

        list_request_payload_content = decrypt_with_dh_key(dh_key,
                                                           list_request_payload_json['ciphertext'],
                                                           list_request_payload_json['gcm_nonce'],
                                                           list_request_payload_json['gcm_tag'])
        print(username)
        if username != list_request_payload_content["username"]:
            print(f"Request username mismatch, addr: {addr}")
            self.transport.close()
            self.__init__()
        else:
            user_json_list = self.key_manager.get_all_users()
            (user_list_cipher,
             user_list_gcm_nonce,
             user_list_gcm_tag) = encrypt_with_dh_key(dh_key=dh_key, data=user_json_list)

            user_list_payload = {
                "ciphertext": user_list_cipher,
                "gcm_nonce": user_list_gcm_nonce,
                "gcm_tag": user_list_gcm_tag
            }

            user_list_response = {
                "op_code": OP_CMD,
                "event": "LIST_RESP",
                "payload": json.dumps(user_list_payload)
            }

            print(f"Sent: {user_list_response} to {addr} with username: {username}")
            self.transport.write(json.dumps(user_list_response).encode('ascii'))

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
            user_doc = cred_db.find_one({"username": username})
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

                challenge_content = {"client_nonce": self.auth_user_nonce,
                                     "server_nonce": self.server_nonce,
                                     "server_modulo": server_modulo}

                (ciphertext_encoded,
                 gcm_nonce_encoded,
                 gcm_tag_encoded) = encrypt_with_key_prime(key_content=key_prime_content,
                                                           data=challenge_content)

                payload = {"argon2_params": argon2_params,
                           "argon2_params_signature": argon2_params_signature_encoded,
                           "challenge": ciphertext_encoded,
                           "gcm_nonce": gcm_nonce_encoded,
                           "gcm_tag": gcm_tag_encoded
                           }

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
                                                 nonce=chal_resp_payload["gcm_nonce"],
                                                 tag=chal_resp_payload["gcm_tag"])

            print(f"Received challenge response: {decrypted_json}")
            # client should be able to use the password derived key to decrypt payload
            # and obtain server_nonce
            if decrypted_json.get("server_nonce") == self.server_nonce and decrypted_json.get("client_service_port"):
                try:
                    self.key_manager.add_user(self.username,
                                              self.dh_key, addr[0],
                                              decrypted_json.get("client_service_port"))
                    print(self.key_manager.get_all_usernames())
                finally:
                    response = {"op_code": OP_LOGIN, "event": "auth successful", "payload": ""}
                    print(f"sent response {response} to {addr}")
                    self.transport.write(json.dumps(response).encode())
                    self.login_state = "AUTHENTICATED"  # Or reset to "AWAITING_AUTH_REQ" if failed

            else:
                response = {"op_code": OP_LOGIN, "event": "auth failed", "payload": ""}
                self.transport.write(json.dumps(response).encode())
                print(f"Authentication failed, closing connection with {addr}")
                self.transport.close()

        # wrong event during states or unexpected event
        else:
            # Unexpected message type or sequence
            error_msg = {"event": "error", "message": "Unexpected message or state."}
            self.transport.write(json.dumps(error_msg).encode())
            self.transport.close()

    def connection_lost(self, exc):
        if exc:
            print(f"Error on connection: {exc}")
        else:
            print("Connection closed by client.")

        self.__init__()
        print("Client info reset completed")
        super().connection_lost(exc)


async def main(sp):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(TCPAuthServerProtocol, '127.0.0.1', sp)
    print("Starting TCP server...")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    args = parse_arguments()
    cred_db = db_connect(args.db_uri, args.db_key_path, "cred")
    nonce_db = db_connect(args.db_uri, args.db_key_path, "nonce")

    Server_Private_Key = load_key(args.priv_key_path, public=False)
    try:
        if (cred_db is not None
                and Server_Private_Key is not None
                and nonce_db is not None):
            asyncio.run(main(args.sp))
        else:
            print(f"Database not connected or missing private key")
    except KeyboardInterrupt:
        print("Server stopped manually.")
