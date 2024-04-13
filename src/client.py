import argparse
import asyncio
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

    def __init__(self, cp):
        """
        Init client class
        """
        self.active_time = datetime.now()
        self.connect_list = []
        self.login_status = False
        self.login_uname = ""
        self.server_dh_key = ""
        #self.server_dh_iv = ""
        self.cp = cp

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
                logger.debug(f"Receive challenge {response_json} from server for {uname}")
                if response_json.get("op_code") != constant.OP_LOGIN or response_json.get("event") != "auth_request_challenge":
                    # invalid message
                    logger.debug(f"Invalid format response from server {response_json} in login process")
                    raise ValueError("Server error")
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
                    logger.debug(f"Wrong password of {uname}")
                    raise ValueError("Wrong password")
                # correct password
                logger.debug(f"Correct password of {uname}")

                server_mod = challenge["server_modulo"]
                nonce2 = challenge["server_nonce"]

                """
                Send the third step of login
                """
                self.server_dh_key = pow(server_mod, exponent, constant.P)
                server_nonce_json = {
                    "server_nonce": nonce2,
                    "client_service_port": self.cp
                }
                encrypted_nonce_encoded, dh_iv_encoded = crypto.encrypt_with_dh_key(dh_key=self.server_dh_key, 
                                                                                    data=server_nonce_json)
                #self.server_dh_iv = dh_iv_encoded
                chal_resp_payload = {
                    "ciphertext": encrypted_nonce_encoded,
                    "iv": dh_iv_encoded
                }
                message_json = {
                    "op_code": constant.OP_LOGIN,
                    "event": "challenge_response",
                    "payload": json.dumps(chal_resp_payload)
                }
                s.sendall(util_funcs.pack_message(message_json))

                """
                Last part of login
                """
                msg = s.recv(4096)
                last_response_json = json.loads(msg.decode())
                if (last_response_json.get('op_code') == constant.OP_LOGIN
                    and last_response_json.get('event') == "auth successful"):
                    # login success
                    logger.debug(f"Login of {uname} success")
                    self.login_uname = uname
                    print(f"Login success {uname}!")

        except (socket.error, ConnectionError, ConnectionResetError) as e:
            logger.debug(f"Exception login: {e}")
            return False

        return True



"""
Communicate with other users
"""
class ClientCommunicationProtocol(asyncio.Protocol):
    def __init__(self, client):
        self.client = client


"""
Send list reqest to KDC
"""
async def list_request(client):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((constant.SERVER_ADDRESS, constant.SERVER_PORT))
            logger.debug(f"Connect to server for {client.login_uname} list request")

            """
            Send list request encrypted with session dh key
            """
            ciphertext_encoded, dh_iv_encoded = crypto.encrypt_with_dh_key(
                dh_key=client.server_dh_key, data={"username": client.login_uname})
            auth_json = {
                "username": client.login_uname,
                "ciphertext": ciphertext_encoded,
                "iv": dh_iv_encoded
            }
            request_json = {
                 "op_code": constant.OP_CMD,
                 "event": "LIST",
                 "payload": json.dumps(auth_json)
            }
            s.sendall(util_funcs.pack_message(request_json))


            """
            Receive list response
            """
            msg = s.recv(4096)
            response_json =json.loads(msg.decode())
            logger.debug(f"Receive list response {response_json} from server for {client.login_uname}")
            if (response_json.get("op_code") != constant.OP_CMD or 
                response_json.get("event") != "LIST_RESP" or 
                ("payload" not in response_json)):
                # receive invalid message
                logger.debug(f"Invalid format response from server {response_json} for list request")
                print("KDC error")
                raise ValueError("Server error")
            
            payload_json = json.loads(response_json["payload"])
            user_list = crypto.decrypt_with_dh_key(client.server_dh_key, 
                                                   payload_json['ciphertext'], 
                                                   payload_json['iv'])
            logger.debug(f"Complete list request")
            print(f"users list: {user_list}")

    except (socket.error, ConnectionError, ConnectionResetError, Exception) as e:
            logger.debug(f"Exception request list: {e}")

"""
Check login status
"""
async def check_status(client):
    while True:
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
Handle user input command
"""
async def handle_input(client):
    while True:
        input_cmd = input()
        try: 
            match input_cmd:
                case  "list":
                    # send list request to KDC
                    await list_request(client)
                    
                case "send":
                    # start communication with another client
                    pass
        except (socket.error, ConnectionError, ConnectionResetError, Exception ) as e:
            logger.debug(f"Exception input: {e}")


"""
Factory function
"""
def create_protocol(client):
    return lambda: ClientCommunicationProtocol(client)


async def main(client, cp):
    """
    Start client communication server
    """
    loop = asyncio.get_running_loop()
    client_server = await loop.create_server(
        create_protocol(client),
        '127.0.0.1', 
        cp
    )
    print("ready to exchange message...")

    async with client_server:
        input_task = loop.create_task(handle_input(client))

        await asyncio.wait([client_server.serve_forever(), input_task], return_when=asyncio.ALL_COMPLETED)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Messaging")
    parser.add_argument("-un", type=str, help="login username")
    parser.add_argument("-pw", type=str, help="login password")
    parser.add_argument("-cp", type=str, help="client communication port")
    args = parser.parse_args()

    client = Client(args.cp)


    """
    Login to Server
    """
    client.login_status = client.login(args.un, args.pw)
    if not client.login_status:
        # login fail
        print(f"Init login fail")
        sys.exit(1)
    # login success
    client.active_time = datetime.now()


    """
    Start a server
    """
    try:
        asyncio.run(main(client, args.cp))
    except KeyboardInterrupt:
        print('Server stopped manually')
