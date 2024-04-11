import argparse
import base64
import json
import logging
import socket
import sys
import time
from datetime import datetime, timedelta
import argon2
import constant

from util import util_funcs, crypto


SERVER_PUBLIC_KEY_PATH = "../server_public_key.pem"

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
        self.login_status = False
        self.server_dh_key = ""
        self.server_dh_iv = ""

    def login(self, uname, pswd):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((constant.SERVER_ADDRESS, constant.SERVER_PORT))
                logger.debug(f"Connect to server for {uname} login")

                server_public_key = util_funcs.load_key(SERVER_PUBLIC_KEY_PATH, True)
                nonce = crypto.generate_nonce()
                exponent = crypto.generate_dh_private_key()

                """
                Generate login message and encrypt with server public key
                """
                payload_json = {
                    "username": uname,
                    "nonce": nonce,
                    "modulo": pow(constant.G, exponent, constant.P)
                }
                payload_string = json.dumps(payload_json)
                payload_bytes = payload_string.encode('ascii')
                encrypted_payload = crypto.encrypt_with_public_key(public_key=server_public_key, data=payload_bytes)
                payload_base64 = base64.b64encode(encrypted_payload).decode('ascii')
                message_json = {
                    "op_code": constant.OP_LOGIN,
                    "event": "auth_request",
                    "payload": payload_base64
                }
                s.sendall(util_funcs.pack_message(message_json))
                logger.debug(f"Send login request to server for {uname}")

                """
                Receive response and verify sign
                """
                msg = s.recv(4096)
                response_json =json.loads(msg.decode())
                print(f"Receive message {response_json}")
                logger.debug(f"Receive challenge from server for {uname}")
                if response_json.get("op_code") != constant.OP_LOGIN or response_json.get("event") != "auth_request_challenge":
                    # invalid message
                    logger.debug(f"Invalid format response from server {response_json} in login process")
                    raise ValueError("Server error")
                logger.debug(f"Format of challenge from server is correct for {uname}")                
                response_payload_json = json.loads(response_json["payload"])
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
                hper = argon2.PasswordHasher(
                    time_cost=argons_params_json["Time Cost"],
                    memory_cost=argons_params_json["Memory Cost"],
                    parallelism=argons_params_json["Parallelism"],
                    salt_len=len(argons_params_json["Salt"])
                )
                decode_salt = base64.b64decode((argons_params_json["Salt"] + "==").encode('utf-8'))
                hash_pswd = hper.hash(
                    password=pswd, salt=decode_salt
                )
                """
                hash_pswd = argon2.low_level.hash_secret_raw(
                    secret=pswd,
                    salt=argons_params_json["Salt"],
                    time_cost=argons_params_json["Time Cost"],
                    memory_cost=argons_params_json["Memory Cost"],
                    parallelism=argons_params_json["Parallelism"],
                    version=argons_params_json["Version"]
                )
                """
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
                self.server_dh_key = pow(server_mod, exponent, constant.P)
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
                    "op_code": constant.OP_LOGIN,
                    "event": "challenge_response",
                    "payload": chal_resp_payload
                }
                s.sendall(util_funcs.pack_message(message_json))




        except (socket.error, ConnectionError, ConnectionResetError) as e:
            print(f"Exception login: {e}")
            logger.debug(f"Exception login: {e}")
            return False

        return True

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
    client.login_status = client.login(args.u, args.p)
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
                client.login_status = client.login(uname, pswd)
                if client.login_status:
                    break


                # pause a second to avoid consuming to much resource
                time.sleep(1)

        """
        Exchange message asynchronously
        """
        user_input = input("Connect to: ")

