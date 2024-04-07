import hashlib
import json
import logging
import secrets
import struct
import sys
import argon2
import argparse
import time
import socket
from util import util_funcs, msg_processing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from math import pi

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 10001
SERVER_PUBLIC_KEY_PATH = "../server_public_key.pem"
LOGIN_P = 2**768 - 2**704 - 1 + 2**64 * (int(2**638 * pi) + 149686)
LOGIN_G = 2

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
                message_json = {
                    "username": uname,
                    "nonce": nonce,
                    "dh_mod": pow(LOGIN_G, exponent, LOGIN_P)
                }
                message_string = json.dumps(message_json)
                encrypted_message = server_public_key.encrypt(
                    message_string,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                message_size = struct.pack('!l', len(encrypted_message))
                s.sendall(message_size + encrypted_message.encode())


                """
                Receive response and verify sign
                """
                response, _ = msg_processing.recv_msg(s)
                response_json = json.loads(response)
                argon_params_string = response_json["argon_params"]
                encry_challenge = response_json["challenge"]
                server_sign = response_json["argon_params_sign"]
                
                if not util_funcs.check_signature(server_public_key, server_sign, argon_params_string):
                    # sign is wrong
                    logger.debug("Verification of Sign from server fail")
                    raise ValueError("Server error")
                # sign is correct
                logger.debug(f"Login of {uname} success")
                argon_params = json.loads(argon_params_string)  


                """
                Decrypt response and handle login result
                """
                hash_pswd = argon2.low_level.hash_secret_raw(
                    secret=pswd,
                    salt=argon_params["salt"],
                    time_cost=argon_params["time_cost"],
                    memory_cost=argon_params["memory_cost"],
                    parallelism=argon_params["parallelism"],
                    hash_len=argon_params["memory_cost"],
                    type=argon_params["type"],
                    version=argon_params["version"]
                )
                key_json = {
                    "nonce": nonce,
                    "hash_password": hash_pswd
                }
                temp_key = hashlib.sha256(key_json.dumps().encode()).digest()
                fernet_challenge = Fernet(temp_key)
                challenge_string = fernet_challenge.decrypt(encry_challenge)
                challenge = json.loads(challenge_string)

                if challenge["nonce"] != nonce:
                    # wrong password
                    logger.debug("Wrong password")
                    raise ValueError("Wrong password")
                # login success
                logger.debug(f"Login of {uname} success")
                print(f"Login success {uname}!")

                server_mod = challenge["server_mod"]
                nonce2 = challenge["nonce2"]



                """
                Send the third step of login
                """
                session_key = pow(server_mod, exponent, LOGIN_P)
                fernet_session = Fernet(session_key)
                encrypted_message = fernet_session.encrypt(nonce2)
                message_size = struct.pack('!l', len(encrypted_message))
                s.sendall(message_size + encrypted_message.encode())




        except (socket.error, ConnectionError, ConnectionResetError) as e:
            print(f"Exception login: {e}")
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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", action="store_true", help="login username")
    group.add_argument("-p", action="store_true", help="login password")
    args = parser.parse_args()

    client = Client()

    """
    Login Server
    """
    login_status = client.login(args.u, args.p)
    if not login_status:
        # login fail
        print(f"Init login fail")
        sys.exit(1)
    client.active_time = datetime.now()

    while True:
        """
        Check active time
        """
        if datetime.now() - client.active_time >  timedelta(minutes = 10):
            # login time out
            login_status = False
            while True:
                uname = input("Login time out, please login again\nUsername:")
                pswd = input("Password: ")
                login_status = client.login(uname, pswd)
                if login_status:
                    print("Log in successfully!")
                    break
                
                # pause a second to avoid consuming to much resource
                time.sleep(1)


        user_input = input("Connect to: ")