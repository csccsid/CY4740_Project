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
import aioconsole

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
        #try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((constant.SERVER_ADDRESS, constant.SERVER_PORT))
                s.settimeout(10.0) # set socket time out in 10 second
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

        #except socket.timeout:
            #print("No data received within the time limit, closing socket.")
            #s.close()
        #except (socket.error, ConnectionError, ConnectionResetError) as e:
            #logger.debug(f"Exception login: {e}")
            #s.close()
            #return False

            return True



"""
Communicate with other users
"""
class ClientCommunicationProtocol(asyncio.Protocol):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.auth_status = "AWAITING_AUTH_REQ"
        self.channel_key = None
        self.source_name = None
        self.estab_recv_nonce = None
        self.estab_dh_key = None
        self.timeout = 20 # time out in 20 second
        self.timeout_handle = None

    
    def connection_made(self, transport):
        self.transport = transport
        self.reset_timeout()
        peername = transport.get_extra_info('peername')
        logger.debug(f"Connection from {peername}")

    
    def data_received(self, data):
        message = json.loads(data.decode())
        addr = self.transport.get_extra_info('peername')
        logger.debug(f"Service received message from {addr}: {message}")
        asyncio.create_task(self.process_message(message, addr))
    

    def reset_timeout(self):
        if self.timeout_handle:
            self.timeout_handle.cancel() 
        self.timeout_handle = asyncio.get_event_loop().call_later(
            self.timeout, self.on_timeout)
        

    """
    Time out setting to prevent DOS
    """
    def on_timeout(self):
        print("Connection timed out, closing.")
        self.transport.close()


    async def process_message(self, message, addr):
        #try:
            match message.get('op_code'):
                case constant.OP_AUTH:
                    await self.on_auth(message, addr)

                case constant.OP_MSG:
                    await self.recv_comm_message(message)

        #except Exception as e:
            #logger.error(f"Error processing message: {e}")
            #self.transport.write(util_funcs.pack_message({
                #"op_code": constant.OP_ERROR,
                #"event": "error",
                #"payload": ""
            #}))
            #self.transport.close()
        

    """
    Communication between clients auth process
    """
    async def on_auth(self, message, addr):
        print("Communication between clients auth process")
        recv_payload_json = message.get('payload')
        
        server_dh_key = None
        recv_name = ""
        async with lock:
            server_dh_key = self.client.server_dh_key
            recv_name = self.client.login_uname        

        if self.auth_status == "AWAITING_AUTH_REQ" and message.get("event") == "comm_init":
            # check comm_recv
            print(f"recv_name is {recv_name}")
            if recv_payload_json.get("comm_recv") != recv_name:
                print("")
                raise ValueError(f"Invalid communication receiver {recv_payload_json}")
            
            """
            Receive and Forward auth request
            """
            print("Receive and Forward auth request")
            self.source_name = recv_payload_json['comm_source']
            nonce = recv_payload_json['nonce']
            recv_nonce = crypto.generate_nonce()
            ciphertext_recv_json = {
                "recv_nonce": recv_nonce,
                "nonce": nonce,
                "comm_source": recv_payload_json['comm_source'],
                "comm_recv": recv_name
            }
            ciphertext_recv, cipher_recv_iv = crypto.encrypt_with_dh_key(dh_key=server_dh_key, 
                                                                         data=ciphertext_recv_json)
            payload_json = {
                "comm_source": recv_payload_json['comm_source'],
                "comm_recv": recv_name,
                "ciphertext_source": recv_payload_json['ciphertext'],
                "ciphertext_recv": ciphertext_recv,
                "cipher_source_iv": recv_payload_json['iv'],
                "cipher_recv_iv": cipher_recv_iv
            }
            request_forward_json = {
                "op_code": constant.OP_AUTH,
                "event": "request_forward",
                "payload": payload_json
            }

            KDC_msg = ""
            # open a socket to exchange request forwarding with KDC
            reader, writer = await asyncio.open_connection(constant.SERVER_ADDRESS, constant.SERVER_PORT)
            writer.write(util_funcs.pack_message(request_forward_json))
            KDC_msg = await reader.read(4096)
            writer.close()
            await writer.wait_closed()
            

            """
            Receive and verify KDC response
            """
            KDC_response_json =json.loads(KDC_msg.decode())
            if (KDC_response_json.get("op_code") != constant.OP_AUTH or
                KDC_response_json.get("event") != "auth_KDC_response"):
                # invalid response
                raise ValueError(f"Invalid format response from KDC in auth process {KDC_response_json}")
            
            # verify response
            response_payload = json.loads(KDC_response_json['payload'])
            print(f"got KDC payload {response_payload}")
            if response_payload.get("nonce") != nonce:
                # verify failed
                logger.debug(f"Nonce in response from KDC is wrong")
                raise ValueError("Invalid response from KDC in auth process")
            
            ciphertext_recv_json = crypto.decrypt_with_dh_key(dh_key=server_dh_key, 
                                                   cipher_text=response_payload['ciphertext_recv'], 
                                                   iv=response_payload['cipher_recv_iv'])
            if ciphertext_recv_json.get('nonce') != recv_nonce:
                # verify failed
                logger.debug(f"Receiver name in response from KDC is wrong")

                raise ValueError("Invalid response from KDC in auth process")
            
            self.channel_key = ciphertext_recv_json['channel_key']


            """
            Distribute key
            """
            print("Distribute key")
            dist_payload_json = {
                "ciphertext_source": response_payload['ciphertext_source'],
                "cipher_source_iv": response_payload['cipher_source_iv']
            }
            dist_json = {
                "op_code": constant.OP_AUTH,
                "event": "distribute_key",
                "payload": dist_payload_json
            }
            self.transport.write(util_funcs.pack_message(dist_json))
            self.auth_status = "AWAITING_AUTH_KEY_EST"

        elif self.auth_status == "AWAITING_AUTH_KEY_EST" and message.get("event") == "comm_dh_key_init" :
            """
            Receive dh key init request and send challenge as response
            """
            estab_init_payload_json = message['payload']
            if estab_init_payload_json.get("comm_source") != self.source_name:
                # invalid source
                raise ValueError("Invalid comm_source in comm dh key init request")
            
            estab_key_init_json = crypto.decrypt_with_dh_key(dh_key=self.channel_key,
                                                             cipher_text=estab_init_payload_json['estab_init_ciphertext'],
                                                             iv=estab_init_payload_json['estab_init_iv'])
            # verify source
            if estab_key_init_json.get("comm_source") != self.source_name:
                # verify source failed
                raise ValueError("Comm_source in comm dh key init request is wrong")
            
            self.estab_recv_nonce = crypto.generate_nonce()
            recv_exponent = crypto.generate_dh_private_key()
            self.estab_dh_key = pow(estab_key_init_json['source_modulo'], recv_exponent, constant.P)

            estab_chal_cipher_json = {
                "comm_recv": recv_name,
                "estab_source_nonce": estab_key_init_json['estab_source_nonce'],
                "estab_recv_nonce": self.estab_recv_nonce,
                "recv_modulo": pow(constant.G, recv_exponent, constant.P)
            }
            estab_chal_ciphertext, estab_chal_iv = crypto.encrypt_with_dh_key(dh_key=self.channel_key,
                                                                              data=estab_chal_cipher_json)
            estab_chal_payload_json = {
                "comm_recv": recv_name,
                "estab_chal_ciphertext": estab_chal_ciphertext,
                "estab_chal_iv": estab_chal_iv
            }
            estab_chal_json = {
                "op_code": constant.OP_AUTH,
                "event": "estab_challange",
                "payload": estab_chal_payload_json
            }
            self.transport.write(util_funcs.pack_message(estab_chal_json))
            self.auth_status = "AWAITING_CHALLENGE_RESP"

        elif self.auth_status == "AWAITING_CHALLENGE_RESP" and message.get("event") == "estab_chal_response":
            """
            Receive estab key challenge response and verify it
            """
            estab_chal_resp_payload = message['payload']
            estab_chal_resp_json = crypto.decrypt_with_dh_key(dh_key=self.estab_dh_key,
                                                              cipher_text=estab_chal_resp_payload['estab_chal_resp_ciphertext'],
                                                              iv=estab_chal_resp_payload['estab_chal_resp_iv'])
            if estab_chal_resp_json.get('estab_recv_nonce') != self.estab_recv_nonce:
                # verify failed
                raise ValueError("Verify failed in estab key challenge response")
                        
            # add source user to client connect list
            client.key_manager.add_user(self.source_name, self.estab_dh_key, 
                                        addr[0], estab_chal_resp_json['source_service_port'])
            
        else:
            logger.debug(f"invalid message {message} from {addr}")
            raise ValueError(f"Invalid message from {addr}")
        

    """
    Func to receive communication message
    """
    async def recv_comm_message(self, message):
        payload_json = message.get("payload")
        print(client.key_manager.get_all_users())
        print(payload_json.get("username"))
        dh_key = client.key_manager.get_dh_key_by_username(payload_json.get("username"))
        if dh_key is None:
            raise ValueError("Receive message from user never connected or key expired")
        
        if dh_key is not None and message.get("event") == "send_msg":
            decrypted_json = crypto.decrypt_with_dh_key(dh_key=dh_key,
                                                 cipher_text=payload_json["ciphertext"],
                                                 iv=payload_json["iv"])
            print(f"Receive message {decrypted_json['msg']} from {payload_json['username']}")


    def connection_lost(self, exc):
        if exc:
            print(f"Error on connection: {exc}")
        else:
            print("Connection closed by client.")
        
        if self.timeout_handle:
            self.timeout_handle.cancel()

        super().connection_lost(exc)


"""
Send message in communication
"""
async def send_comm_message(client, destination, message_text):
    #try:
            
            destination_dh_key = client.key_manager.get_dh_key_by_username(destination)
            dest_addr, dest_port = client.key_manager.get_addr_by_username(destination)
            temp_username = ""
            async with lock:
                temp_username = client.login_uname

            if (destination_dh_key is None or 
                dest_addr is None or
                dest_port is None):
                # have not connected yet

                # check users_list
                temp_users_list = {}
                async with lock:
                    temp_users_list = client.users_list
                destination_info = temp_users_list.get(destination)
                print("get destination_info")
                if destination_info is None:
                    # not in client users_list, update users_list by KDC's version
                    temp_users_list = await list_request(client)
                    async with lock:
                        client.users_list = temp_users_list
                    destination_info = temp_users_list.get(destination)

                    # check updated users_list
                    if destination_info is None:
                        # stil not found, destination has not logined
                        print(f"{destination} has not logined, cannot send message to it")
                        raise ValueError(f"Failed to send message to {destination} who has not logined")
                

                """
                Init communication connect
                """
                print("pending to init communication connect")
                channel_key  = None
                dest_addr = destination_info['client_service_addr']
                dest_port = int(destination_info['client_service_port'])
                print(f"port is {isinstance(dest_port, int)}, {dest_port}")

                reader, writer = await asyncio.open_connection(dest_addr, dest_port)
                logger.debug(f"Connect to server for init connection with {destination}")

                server_dh_key = client.key_manager.get_dh_key_by_username("KDC")
                if server_dh_key is None:
                    logger.debug(f"Login time out in sending process")
                    raise ValueError("Login time out")
                    
                """
                Send comm auth init request
                """
                nonce_source = crypto.generate_nonce()
                nonce = crypto.generate_nonce()
                cipher_json = {
                    "nonce_source": nonce_source,
                    "nonce": nonce,
                    "comm_source": temp_username,
                    "comm_recv": destination
                }
                print(f"destination is {destination}")
                ciphertext, cipher_iv = crypto.encrypt_with_dh_key(dh_key=server_dh_key, 
                                                                      data=cipher_json)
                payload_json = {
                    "nonce": nonce,
                    "comm_source": temp_username,
                    "comm_recv": destination,
                    "ciphertext": ciphertext,
                    "iv": cipher_iv
                }
                comm_init_json = {
                    "op_code": constant.OP_AUTH,
                    "event": "comm_init",
                    "payload": payload_json
                }
                print("A sends init to B")
                writer.write(util_funcs.pack_message(comm_init_json))
                await writer.drain()
                    

                """
                Process communication auth responsse
                """
                auth_response_msg = await reader.read(4096)
                auth_response_json = json.loads(auth_response_msg)
                print(f"receive B's response {auth_response_json}")
                if (auth_response_json.get("op_code") != constant.OP_AUTH or
                    auth_response_json.get("event") != "distribute_key"):
                    # invalid response
                    raise ValueError(f"Invalid auth response format")
                    
                response_payload_json = auth_response_json.get("payload")
                ciphertext_source_json = crypto.decrypt_with_dh_key(dh_key=server_dh_key,
                                                                        cipher_text=response_payload_json['ciphertext_source'],
                                                                        iv=response_payload_json['cipher_source_iv'])
                # verify KDC response
                if ciphertext_source_json.get("nonce") != nonce_source:
                    # verify falied
                    logger.debug(f"Source name in response from KDC is wrong")
                    raise ValueError("Invalid auth response in distributing key process")
                    
                channel_key = ciphertext_source_json['channel_key']


                """
                Establish communication dh key, send init request
                """
                print("send init reqeust to Establish communication dh key")
                estab_source_nonce = crypto.generate_nonce()
                comm_exponent = crypto.generate_dh_private_key()
                estab_key_init_json = {
                    "comm_source": temp_username,
                    "estab_source_nonce": estab_source_nonce,
                    "source_modulo": pow(constant.G, comm_exponent, constant.P)
                }
                estab_init_ciphertext, estab_init_iv = crypto.encrypt_with_dh_key(dh_key=channel_key,
                                                                                      data=estab_key_init_json)
                estab_init_payload_json = {
                    "comm_source": temp_username,
                    "estab_init_ciphertext": estab_init_ciphertext,
                    "estab_init_iv": estab_init_iv
                }
                estab_init_request_json = {
                    "op_code": constant.OP_AUTH,
                    "event": "comm_dh_key_init",
                    "payload": estab_init_payload_json
                }
                writer.write(util_funcs.pack_message(estab_init_request_json))
                await writer.drain()


                """
                Receive init response verify
                """
                print("Receive init response verify")
                estab_chal_message = await reader.read(4096)
                estab_chal_json = json.loads(estab_chal_message)
                print(f"estab_chal_json is {estab_chal_json}")
                if (estab_chal_json.get("op_code") != constant.OP_AUTH or
                    estab_chal_json.get("event" != "estab_challange")):
                    # invalid message
                    raise ValueError("Invalid establish key challenge")
                    
                estab_chal_payload_json = estab_chal_json['payload']
                establ_chal_json = crypto.decrypt_with_dh_key(dh_key=channel_key,
                                                                  cipher_text=estab_chal_payload_json['estab_chal_ciphertext'],
                                                                  iv=estab_chal_payload_json['estab_chal_iv'])
                if (establ_chal_json.get("estab_source_nonce") != estab_source_nonce or
                        estab_chal_payload_json.get("comm_recv") != destination or
                        establ_chal_json.get("comm_recv") != destination):
                        # invalid establish key challenge
                        raise ValueError("Invalid establish key challenge")
                    
                    
                """
                Establish key and send last challenge response
                """
                print("Establish key and send last challenge response")
                destination_dh_key = pow(establ_chal_json['recv_modulo'], comm_exponent, constant.P)
                # add destination to connect list
                client.key_manager.add_user(destination, destination_dh_key, dest_addr, dest_port)
                source_service_port = None
                async with lock:
                    source_service_port = client.cp
                estab_chal_resp = {
                    "estab_recv_nonce": establ_chal_json['estab_recv_nonce'],
                    "source_service_port": source_service_port
                }
                estab_chal_resp_ciphertext, estab_chal_resp_iv = crypto.encrypt_with_dh_key(dh_key=destination_dh_key,
                                                                                                data=estab_chal_resp)
                estab_chal_resp_payload = {
                    "estab_chal_resp_ciphertext": estab_chal_resp_ciphertext,
                    "estab_chal_resp_iv": estab_chal_resp_iv
                }
                estab_chal_resp_json = {
                    "op_code": constant.OP_AUTH,
                    "event": "estab_chal_response",
                    "payload": estab_chal_resp_payload
                }
                writer.write(util_funcs.pack_message(estab_chal_resp_json))
                await writer.drain()

                writer.close()
                await writer.wait_closed()


            print("already connected")
            reader_send, writer_send = await asyncio.open_connection(dest_addr, dest_port)
            logger.debug(f"Connect to server for sending message to {destination}")

                
            msg_json = {"msg": message_text}
            msg_cipher, send_msg_iv = crypto.encrypt_with_dh_key(dh_key=destination_dh_key, 
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
            writer_send.write(util_funcs.pack_message(message_json))
            await writer_send.drain()
            logger.debug(f"sent {send_msg_iv} to {destination}") 

            writer_send.close()
            await writer_send.wait_closed()   
    
    #except socket.timeout:
        #print("No data received within the time limit, closing socket.")

    #except (socket.error, ConnectionError, ConnectionResetError, Exception) as e:
        #print(f"Failed to send message to {destination}")
        #logger.debug(f"Exception sending message: {e}")


"""
Send list reqest to KDC
"""
async def list_request(client):
    #try:
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
            s.settimeout(10.0) # time out in 10 second
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

    #except socket.timeout:
        #print("No data received within the time limit, closing socket.")
        #s.close()
    
    #except (socket.error, ConnectionError, ConnectionResetError, Exception) as e:
            #logger.debug(f"Exception request list: {e}")
            #s.close()


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
        input_cmd = (await aioconsole.ainput()).split()
        #try: 
        match input_cmd[0]:
            case  "list":
                # send list request to KDC
                user_json_list = await list_request(client)
                print(f"users list: {list(user_json_list.keys())}")
                # update client users list
                async with lock:
                     client.users_list = user_json_list
                    
            case "send":
                # start communication with another client
                # check user name
                if input_cmd[1] == "KDC":
                    print("Cannot send message to KDC")
                else:
                    print("pending to send auth message")
                    await send_comm_message(client, input_cmd[1], input_cmd[2])

        #except (socket.error, ConnectionError, ConnectionResetError, Exception ) as e:
            #logger.debug(f"Exception input: {e}")


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
        int(cp)
    )
    print("ready to exchange message...")

    async with client_server:
        input_task = loop.create_task(handle_input(client))
        server_task = loop.create_task(client_server.serve_forever())

        await asyncio.wait([server_task , input_task], return_when=asyncio.ALL_COMPLETED)

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
    #try:
    asyncio.run(main(client, args.cp))
    # Exception as e:
        #print(f"server error {e}")
    #except KeyboardInterrupt:
    #except IndexError:
        #print('Server stopped manually')
