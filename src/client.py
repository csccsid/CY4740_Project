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
from KeyManager import AuthenticationKeyManager
import constant

from util import util_funcs, crypto


SERVER_PUBLIC_KEY_PATH = "../server_public_key.pem"

logger = logging.getLogger(__name__)
logging.basicConfig(filename='client.log', encoding='utf-8', level=logging.DEBUG)

lock = None



class Client:
    """
    Client class for security messaging
    """
    key_manager = AuthenticationKeyManager()

    def __init__(self, cp):
        """
        Init client class
        """
        self.active_time = datetime.now()
        self.users_list = {}
        self.login_status = False
        self.login_uname = ""
        self.server_dh_key = ""
        #self.server_dh_iv = ""
        self.cp = cp

    async def reset(self):
        pass

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
                    self.key_manager.add_user("KDC", self.server_dh_key, 
                                              constant.SERVER_ADDRESS, constant.SERVER_PORT)
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
        super().__init__()
        self.client = client
        self.auth_status = "AWAITING_AUTH_REQ"

    
    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        logger.debug(f"Connection from {peername}")

    
    def data_received(self, data):
        message = json.loads(data.decode())
        addr = self.transport.get_extra_info('peername')
        logger.debug(f"Service received message from {addr}: {message}")
        asyncio.create_task(self.process_message(message, addr))


    async def process_message(self, message, addr):
        try:
            match message.get('op_code'):
                case constant.OP_AUTH:
                    await self.on_auth(message, addr)

                case constant.OP_MSG:
                    await self.recv_comm_message(message)

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.transport.close()
        

    """
    Communication between clients auth process
    """
    async def on_auth(self, message, addr):
        payload_json = message.get('payload')
        # check message format
        if("nonce" not in payload_json or
           "comm_source" not in payload_json or
           "comm_recv" not in payload_json or
           "ciphertext" not in payload_json):
            # invalid format
            raise ValueError(f"Invalid communication init format {payload_json}")
        
        server_kh_key = None
        recv_name = ""
        async with lock:
            server_kh_key = self.client.server_dh_key
            recv_name = self.client.login_uname

        if self.auth_status == "AWAITING_AUTH_REQ" and message.get("event") == "comm_init":
            # check comm_recv
            if payload_json.get("comm_recv") != recv_name:
                raise ValueError(f"Invalid communication receiver {payload_json}")
            
            ciphertext_recv_json = {
                "recv_nonce": recv_name
            }

        elif self.auth_status == "AWAITING_AUTH_KEY_EST" and message.get("event") == "comm_key_init" :
            pass

        else:
            logger.debug(f"invalid message {message} from {addr}")
            raise ValueError(f"Invalid message from {addr}")
        

    """
    Func to receive communication message
    """
    def recv_comm_message(self, message):
        payload_json = message.get("payload")
        dh_key = self.key_manager.get_dh_key_by_username(payload_json.get("username"))
        if dh_key is None:
            raise ValueError("Receive message from user never connected or key expired")
        
        if message.get("event") == "send_msg":
            decrypted_json = crypto.decrypt_with_dh_key(dh_key=self.dh_key,
                                                 cipher_text=payload_json["ciphertext"],
                                                 iv=payload_json["iv"])
            print(f"Receive message {decrypted_json['msg']} from {payload_json['username']}")


    def connection_lost(self, exc):
        if exc:
            print(f"Error on connection: {exc}")
        else:
            print("Connection closed by client.")

        # TODO: also make sure to remove user from the authenticated user list
        # this is commented out for testing purposes.
        # if self.username in self.authenticated_users:
        #     asyncio.create_task(self.modify_users_remove(self.username))
        self.__init__()
        print("Client info reset completed")
        super().connection_lost(exc)


"""
Send list reqest to KDC
"""
async def list_request(client):
    try:
        temp_dh_key = None
        temp_login_uname = ""
        async with lock:
            temp_dh_key = client.key_manager.get_dh_key_by_username("KDC")
            temp_login_uname = client.login_uname

        if temp_dh_key is None:
            # login time out
            print("Login timed out")
            raise ValueError("Login timed out")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((constant.SERVER_ADDRESS, constant.SERVER_PORT))
            logger.debug(f"Connect to server for {temp_login_uname} list request")

            """
            Send list request encrypted with session dh key
            """
            ciphertext_encoded, dh_iv_encoded = crypto.encrypt_with_dh_key(
                dh_key=temp_dh_key, data={"username": temp_login_uname})
            auth_json = {
                "username": temp_login_uname,
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
            logger.debug(f"Receive list response {response_json} from server for {temp_login_uname}")
            if (response_json.get("op_code") != constant.OP_CMD or 
                response_json.get("event") != "LIST_RESP" or 
                ("payload" not in response_json)):
                # receive invalid message
                logger.debug(f"Invalid format response from server {response_json} for list request")
                print("KDC error")
                raise ValueError("Server error")
            
            payload_json = json.loads(response_json["payload"])
            user_json_list = crypto.decrypt_with_dh_key(temp_dh_key, 
                                                   payload_json['ciphertext'], 
                                                   payload_json['iv'])
            logger.debug(f"Complete list request")
            return user_json_list

    except (socket.error, ConnectionError, ConnectionResetError, Exception) as e:
            logger.debug(f"Exception request list: {e}")


"""
Send message in communication
"""
async def send_comm_message(client, destination, message_text):
    try:
            
            destination_dh_key = client.key_manager.get_dh_key_by_username(destination)
            #dest_addr, dest_port = client.key_manager.get_addr_by_username(destination)
            if destination_dh_key is None:
                # have not connected yet

                # check users_list
                temp_users_list = {}
                async with lock:
                    temp_users_list = client.users_list
                destination_info = temp_users_list.get(destination)
                if destination_info is None:
                    # not in client users_list, update users_list by KDC's version
                    temp_users_list = await list_request(client)
                    async with lock:
                        client.users_list = temp_users_list
                    destination_info = temp_users_list.get(destination)

                    # check updated users_list
                    if destination_info is None:
                        # destination has not logined
                        print(f"{destination} has not logined, cannot send message to it")
                        raise ValueError(f"Failed to send message to {destination} who has not logined")

            temp_username = ""
            async with lock:
                temp_username = client.login_uname

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((destination_info['client_service_addr'], 
                           destination_info['client_service_port']))
                logger.debug(f"Connect to server for {destination} login")

                
                msg_json = {"msg": message_text}
                msg_cipher, send_msg_iv = crypto.encrypt_with_dh_key(dh_key=temp_dh_key, 
                                                                      data=msg_json)
                payload_json = {
                    "username": temp_username,
                    "ciphertext": msg_cipher,
                    "iv": send_msg_iv
                }
                message_json = {
                    "op_code": constant.OP_MSG,
                    "event": "send_msg",
                    "payload": payload_json
                }
                s.sendall(util_funcs.pack_message(message_json))
                logger.debug(f"sent {send_msg_iv} to {destination}")    
    
    except (socket.error, ConnectionError, ConnectionResetError, Exception) as e:
        print(f"Failed to send message to {destination}")
        logger.debug(f"Exception sending message: {e}")

"""
Check login status and connected status
"""
async def check_status(client):
    while True:
        async with lock:
            active_time_temp = client.active_time

        if datetime.now() - active_time_temp > timedelta(minutes=10):
            # login time out
            async with lock:
                client.login_status = False

            while True:
                uname = input("Login time out, please login again\nUsername:")
                pswd = input("Password: ")
                async with lock:
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
        input_cmd = input().split()
        try: 
            match input_cmd[0]:
                case  "list":
                    # send list request to KDC
                    user_json_list = await list_request(client)
                    print(f"users list: {list(user_json_list.keys())}")
                    
                case "send":
                    # start communication with another client
                    await send_comm_message(client, input_cmd[1], input_cmd[2])
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
    lock = asyncio.Lock()


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
