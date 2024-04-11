import argparse
import base64
import hashlib
import json
import logging
import secrets
import socket
import sys
import time
from datetime import datetime, timedelta
from math import pi

import argon2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from util import util_funcs, msg_processing, crypto

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12345
SERVER_PUBLIC_KEY_PATH = "../server_public_key.pem"
LOGIN_P = 2 ** 768 - 2 ** 704 - 1 + 2 ** 64 * (int(2 ** 638 * pi) + 149686)
LOGIN_G = 2

OP_ERROR = 0
OP_LOGIN = 1
OP_LOGOUT = 2
OP_AUTH = 3
OP_CMD = 4
OP_MSG = 5

logger = logging.getLogger(__name__)
logging.basicConfig(filename='client.log', encoding='utf-8', level=logging.DEBUG)


class Client:
    """
    Client class for security messaging
    """

    def init(self):
        """
        Init client class
        """
        self.active_time = datetime.now()
        self.connect_list = []
        self.session_key = ""
        self.login_status = False
        self.server_dh_key = ""
        self.server_dh_iv = ""

    def login(self, uname, pswd):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_ADDRESS, SERVER_PORT))
                logger.debug(f"Connect to server for {uname} login")

                server_public_key = util_funcs.load_key(SERVER_PUBLIC_KEY_PATH, True)
                nonce = secrets.token_bytes(2)
                exponent = secrets.token_bytes(2)

                """
                Generate login message and encrypt with server public key
                """
                payload_json = {
                    "username": uname,
                    "nonce": nonce,
                    "dh_mod": pow(LOGIN_G, exponent, LOGIN_P)
                }
                payload_string = json.dumps(payload_json)
                payload_bytes = payload_string.encode('ascii')
                encrypted_payload = crypto.encrypt_with_public_key(public_key=server_public_key, data=payload_bytes)
                payload_base64 = base64.b64encode(encrypted_payload).decode('ascii')
                message_json = {
                    "op_code": OP_LOGIN,
                    "event": "auth_request",
                    "payload": payload_base64
                }
                s.sendall(util_funcs.pack_message(message_json, OP_LOGIN))

                """
                Receive response and verify sign
                """
                response_json, _ = msg_processing.recv_msg(s)
                if response_json.get("op_code") != OP_LOGIN or response_json.get("event") != "auth_request_challenge":
                    # invalid message
                    logger.debug(f"Invalid format response from server {response_json} in login process")
                    raise ValueError("Server error")                
                response_payload_json = json.loads(response_json[payload_json])
                argons_params_json = response_payload_json["argon2_params"]
                encry_challenge_encoded = response_payload_json["challenge"]
                server_sign_encoded = response_payload_json["argon2_params_signature"]
                iv_encoded = response_payload_json["iv"]

                server_sign = base64.b64decode(server_sign_encoded)
                if not util_funcs.check_signature(server_public_key, server_sign, json.dumps(argons_params_json).encode('ascii')):
                    # sign is wrong
                    logger.debug("Verification of Sign from server fail")
                    raise ValueError("Server error")
                # sign is correct
                logger.debug(f"Verification of Sign from server success")

                """
                Decrypt response and handle login result
                """
                hash_pswd = argon2.low_level.hash_secret_raw(
                    secret=pswd,
                    salt=argons_params_json["Salt"],
                    time_cost=argons_params_json["Time_cost"],
                    memory_cost=argons_params_json["Memory_cost"],
                    parallelism=argons_params_json["Parallelism"],
                    version=argons_params_json["Version"]
                )
                key_json = {
                    "nonce": nonce,
                    "password_hash": hash_pswd
                }

                challenge_string = crypto.decrypt_with_key_prime(key_json, encry_challenge_encoded, iv_encoded)
                challenge = json.loads(challenge_string)

                if challenge["client_nonce"] != nonce:
                    # wrong password
                    logger.debug("Wrong password")
                    raise ValueError("Wrong password")
                # login success
                logger.debug(f"Login of {uname} success")
                print(f"Login success {uname}!")

                server_mod = challenge["server_modulo"]
                nonce2 = challenge["server_nonce"]

                """
                Send the third step of login
                """
                self.server_dh_key = pow(server_mod, exponent, LOGIN_P)
                server_nonce_json = {
                    "server_nonce": nonce2
                }
                encrypted_nonce_encoded, dh_iv_encoded = crypto.encrypt_with_dh_key(dh_key=self.server_dh_key, data=server_nonce_json)
                self.server_dh_iv = dh_iv_encoded
                chal_resp_payload = {
                    "ciphertext": encrypted_nonce_encoded,
                    "iv": dh_iv_encoded
                }
                message_json = {
                    "op_code": OP_LOGIN,
                    "event": "challenge_response",
                    "payload": chal_resp_payload
                }
                s.sendall(util_funcs.pack_message(message_json))




        except (socket.error, ConnectionError, ConnectionResetError) as e:
            print(f"Exception login: {e}")
            return False, None

        return True, session_key

    """
    Connect to another user
    """

    def connect(self, usname):
        pass

    """
    Communicate with connected user
    """

    def communicate(self, usname, message):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Messaging")
    parser.add_argument("-u", type=str, help="login username")
    parser.add_argument("-p", type=str, help="login password")
    args = parser.parse_args()

    client = Client()

    """
    Login Server
    """
    client.login_status, client.session_key = client.login(args.u, args.p)
    if not client.login_status:
        # login fail
        print(f"Init login fail")
        sys.exit(1)
    # login success
    client.active_time = datetime.now()

    while True:

        """
        Check active time
        """
        if datetime.now() - client.active_time > timedelta(minutes=10):
            # login time out
            client.login_status = False
            while True:
                uname = input("Login time out, please login again\nUsername:")
                pswd = input("Password: ")
                client.login_status, client.session_key = client.login(uname, pswd)
                if client.login_status:
                    break

                # pause a second to avoid consuming to much resource
                time.sleep(1)

        """
        Exchange message asynchronously
        """
        user_input = input("Connect to: ")
