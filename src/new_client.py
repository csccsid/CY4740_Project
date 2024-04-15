"""
This is the seconds attempt of creating a new client
This client will be divided into two major part:
1. The client side server, which would be responsible for handling income requests.
2. The client console, which handle user input.
"""
import argparse
import asyncio
import base64
import datetime
import json
import logging

from aioconsole import ainput
from argon2 import PasswordHasher

from KeyManager import AuthenticationKeyManager

from util.crypto import (
    load_key,
    decrypt_with_dh_key,
    encrypt_with_public_key,
    generate_dh_private_key,
    generate_nonce,
    verify_signature,
    decrypt_with_key_prime,
    encrypt_with_dh_key,
)

from constant import (
    G, P, OP_LOGIN, OP_CMD, OP_LOGOUT, OP_AUTH
)

server_public_key = None
client_instance = None

logger = logging.getLogger(__name__)
logging.basicConfig(filename='new_client.log', encoding='utf-8', level=logging.DEBUG)


def generate_timestamp():
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = int(now.timestamp())
    return timestamp


def parse_arguments():
    """
    Parse command line arguments for the server.
    """
    parser = argparse.ArgumentParser(description="Instant message exchange app, client side")
    parser.add_argument('-host', type=str, help='Client host addr', required=True)
    parser.add_argument('-client_service_port', type=int, help='The service port client uses, for handling incoming '
                                                               'requests', required=True)
    parser.add_argument('-username', type=str, help="Username for login KDC", required=True)
    parser.add_argument('-password', type=str, help='Password for login KDC', required=True)
    parser.add_argument('-server_pub_key_path', type=str, help='Path to server public key file', required=True)
    parser.add_argument('-server_ip', type=str, help='Server ip', required=True)
    parser.add_argument('-server_port', type=int, help='Server port', required=True)

    return parser.parse_args()


class Client:
    key_manager = AuthenticationKeyManager()

    def __init__(self, username, password, client_service_port, server_ip, server_port, host):
        self.username = username
        self.password = password
        self.server_ip = server_ip
        self.server_port = server_port
        self.host = host
        self.client_service_port = client_service_port
        self.authenticated = False
        self.dh_key = ""
        self.login_state = ""
        self.private_key = generate_dh_private_key()
        self.user_list = {}
        self.otwayrees_list = {}
        self.user_info = {'client_service_addr': self.host,
                          'client_service_port': self.client_service_port}

    async def login(self):
        """
        Triggers the login process, construct a login request and send to server. This should be a linear process as
        the client should not be able to access rest of the service without login successfully
        :return: boolean indicated login status
        """
        reader, writer = await asyncio.open_connection(self.server_ip, self.server_port)
        try:
            login_request_nonce = generate_nonce()
            client_dh_modulo = pow(G, self.private_key, P)
            login_request_payload = {"username": self.username,
                                     "nonce": login_request_nonce,
                                     "modulo": client_dh_modulo}

            login_request_payload_encoded = json.dumps(login_request_payload).encode()
            login_request_payload_encoded_encrypted = encrypt_with_public_key(server_public_key,
                                                                              login_request_payload_encoded)
            login_request_payload_encoded_base64 = base64.b64encode(login_request_payload_encoded_encrypted).decode(
                'ascii')

            login_request = {"op_code": OP_LOGIN,
                             "event": "auth_request",
                             "payload": login_request_payload_encoded_base64}

            login_request_ready = json.dumps(login_request).encode()

            logger.debug(f'Sending: {login_request!r}')
            writer.write(login_request_ready)
            await writer.drain()

            # now we need to wait for the second stage of the login request, await server to send back its challenge
            # Optionally, receive a response
            challenge = await reader.read(4096)
            challenge_payload_content = json.loads(json.loads(challenge.decode('ascii'))['payload'])

            logger.debug(f'Received: {challenge_payload_content}')

            # obtain argon2 params and generate the argon2 hash locally
            argon2_params_signature_encoded = challenge_payload_content['argon2_params_signature']
            argon2_params_signature = base64.b64decode(argon2_params_signature_encoded)
            argon2_params = challenge_payload_content['argon2_params']
            argon2_params_bytes = json.dumps(argon2_params).encode('ascii')

            verify_sig = verify_signature(server_public_key,
                                          argon2_params_signature,
                                          argon2_params_bytes)
            if not verify_sig:
                print(f'Verification failed, malicious server or wrong server public key')
                exit(1)

            logger.debug("Params signature verified successfully")
            logger.debug(argon2_params)

            ph = PasswordHasher(
                time_cost=argon2_params["Time Cost"],
                memory_cost=argon2_params["Memory Cost"],
                parallelism=argon2_params["Parallelism"],
                salt_len=len(argon2_params["Salt"])
            )

            logger.debug(argon2_params["Salt"] + "==")
            decode_salt = base64.b64decode((argon2_params["Salt"] + "==").encode('utf-8'))
            logger.debug(decode_salt)
            client_hash = ph.hash(password=self.password, salt=decode_salt)

            key_prime_content = {"nonce": login_request_nonce,
                                 "password_hash": client_hash}

            challenge_ciphertext = challenge_payload_content['challenge']
            challenge_gcm_nonce = challenge_payload_content['gcm_nonce']
            challenge_gcm_tag = challenge_payload_content['gcm_tag']

            decrypted_challenge = decrypt_with_key_prime(key_prime_content,
                                                         challenge_ciphertext,
                                                         challenge_gcm_nonce,
                                                         challenge_gcm_tag)

            logger.debug(decrypted_challenge)

            if decrypted_challenge["client_nonce"] != login_request_nonce:
                logger.debug("Mismatch login request nonce")
                exit(1)

            server_nonce = decrypted_challenge["server_nonce"]
            server_modulo = decrypted_challenge["server_modulo"]

            # now construct the challenge response that contains the nonce sent from server,
            # along with our client service port, then encrypt with the established DH key.

            challenge_resp = {"server_nonce": server_nonce, "client_service_port": self.client_service_port}

            self.dh_key = pow(server_modulo, self.private_key, P)

            chal_ciphertext, chal_gcm_nonce, chal_gcm_tag = encrypt_with_dh_key(self.dh_key, challenge_resp)
            chal_resp_content = {"ciphertext": chal_ciphertext, "gcm_nonce": chal_gcm_nonce, "gcm_tag": chal_gcm_tag}
            chal_resp = {"op_code": OP_LOGIN, "event": "challenge_response", "payload": json.dumps(chal_resp_content)}
            chal_resp_ready = json.dumps(chal_resp).encode()
            writer.write(chal_resp_ready)
            await writer.drain()
            logger.debug(f'chal_resp sent {chal_resp}')

            # we should receive a response back indicating our login status.
            login_status = await reader.read(4096)
            login_status_dict = json.loads(login_status.decode('ascii'))

            if login_status_dict['event'] == 'auth successful':
                print("Auth successful")
                self.authenticated = True
            else:
                # TODO: if auth failed, client should not be able to decode the challenge,
                # aka it would never reach to this branch
                print("Auth failed")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f'TCP connection closed with {self.server_ip, self.server_port}')

    async def list(self, verbose=True):
        """
        Handles the list command, should print a list of all authenticated username,
        and store all user information in the key manager
        """
        reader, writer = await asyncio.open_connection(self.server_ip, self.server_port)

        try:
            list_payload_content = {"username": self.username}
            (list_payload_cipher,
             list_payload_gcm_nonce,
             list_payload_gcm_tag) = encrypt_with_dh_key(dh_key=self.dh_key, data=list_payload_content)

            list_request_payload = {"username": self.username,
                                    "ciphertext": list_payload_cipher,
                                    "gcm_nonce": list_payload_gcm_nonce,
                                    "gcm_tag": list_payload_gcm_tag}
            list_request = {"op_code": OP_CMD, "event": "LIST", "payload": json.dumps(list_request_payload)}
            list_request_ready = json.dumps(list_request).encode()
            writer.write(list_request_ready)
            await writer.drain()

            list_response_buffer = await reader.read(4096)
            list_response = json.loads(list_response_buffer.decode('ascii'))
            list_response_payload = json.loads(list_response["payload"])

            list_content = decrypt_with_dh_key(dh_key=self.dh_key,
                                               cipher_text=list_response_payload['ciphertext'],
                                               nonce=list_response_payload['gcm_nonce'],
                                               tag=list_response_payload['gcm_tag'])
            if verbose:
                print(list(list_content.keys()))

            self.user_list = list_content

        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f'TCP connection closed with {self.server_ip, self.server_port}')

    async def logout(self):
        """
        Notify the server that we have logged out, no response needed
        :return:
        """
        reader, writer = await asyncio.open_connection(self.server_ip, self.server_port)

        try:
            logout_content = {
                "username": self.username,
                "timestamp": generate_timestamp()
            }

            (logout_content_cipher,
             logout_content_gcm_nonce,
             logout_content_gcm_tag) = encrypt_with_dh_key(dh_key=self.dh_key, data=logout_content)

            logout_payload = {"username": self.username,
                              "ciphertext": logout_content_cipher,
                              "gcm_nonce": logout_content_gcm_nonce,
                              "gcm_tag": logout_content_gcm_tag}

            logout_request = {
                "op_code": OP_LOGOUT,
                "event": "logout",
                "payload": json.dumps(logout_payload)
            }

            logout_request_ready = json.dumps(logout_request).encode()
            writer.write(logout_request_ready)
            await writer.drain()

        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f'TCP connection closed with {self.server_ip, self.server_port}')

    async def send_msg(self, dest_username, dest_content):
        dest_user_info = self.user_list.get(dest_username)
        dest_service_ip = dest_user_info.get("client_service_addr")
        dest_service_port = dest_user_info.get("client_service_port")

        c2c_dh_key = self.key_manager.get_dh_key_by_username(dest_username)

        reader, writer = await asyncio.open_connection(dest_service_ip, dest_service_port)

        try:
            if c2c_dh_key is None:
                # welp, not dh key found, initiating ~~~keanu reeves~~~ otway rees
                session_identifier = generate_nonce()
                sender_nonce = generate_nonce()
                self.otwayrees_list[dest_username] = {
                    "session_identifier": session_identifier,
                    "sender_nonce": sender_nonce,
                    "auth_status": "AWAIT_RECEIVER_RESP"
                }

                sender_info_dump = json.dumps(self.user_info)
                receiver_info_dump = json.dumps(dest_user_info)

                sender_payload = {
                    "sender_nonce": sender_nonce,
                    "session_identifier": session_identifier,
                    "sender_info": sender_info_dump,
                    "receiver_info": receiver_info_dump
                }

                (sender_payload_cipher,
                 sender_payload_gcm_nonce,
                 sender_payload_gcm_tag) = encrypt_with_dh_key(self.dh_key, sender_payload)

                otway_payload = {
                    "session_identifier": session_identifier,
                    "sender_info": sender_info_dump,
                    "receiver_info": receiver_info_dump,
                    "sender_ciphertext": sender_payload_cipher,
                    "sender_gcm_nonce": sender_payload_gcm_nonce,
                    "sender_gcm_tag": sender_payload_gcm_tag
                }

                otway_init_request = {
                    "op_code": OP_AUTH,
                    "event": "auth_init_request",
                    "payload": json.dumps(otway_payload)
                }

                otway_init_request_ready = json.dumps(otway_init_request).encode()

                writer.write(otway_init_request_ready)
                await writer.drain()

                # the following requests should be handled with TCPClientServerProtocol
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f'TCP connection closed with {dest_service_ip, dest_service_port}')


async def handle_messages():
    while True:
        message = await ainput("")
        match message.lower():
            case "list":
                await client_instance.list()
            case "exit":
                await client_instance.logout()
                exit(0)


class TCPClientServerProtocol(asyncio.Protocol):
    key_manager = AuthenticationKeyManager()

    def __init__(self):
        super().__init__()
        self.transport = None

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
                case 3:
                    self.on_auth(message, addr)

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.transport.close()

    def on_auth(self, message, addr):
        pass

    def connection_lost(self, exc):
        if exc:
            print(f"Error on connection: {exc}")
        else:
            print("Connection closed by client.")

        self.__init__()
        print("Client info reset completed")
        super().connection_lost(exc)


async def main(client_service_port, username, password, host):
    loop = asyncio.get_running_loop()

    # client side runs a server to async-ly handle requests from all other client as well as server.
    server = await loop.create_server(TCPClientServerProtocol, '127.0.0.1', client_service_port)
    print("Starting Client server...")

    user_input_task = asyncio.create_task(handle_messages())
    server_task = asyncio.create_task(server.serve_forever())
    await asyncio.wait([user_input_task, server_task], return_when=asyncio.FIRST_COMPLETED)
    if user_input_task.done():
        server_task.cancel()  # Cancel the server task if input task is done (user typed 'exit')
        exit(0)


if __name__ == "__main__":
    args = parse_arguments()

    server_public_key = load_key(args.server_pub_key_path, public=True)
    client_instance = Client(args.username,
                             args.password,
                             args.client_service_port,
                             args.server_ip,
                             args.server_port,
                             args.host)
    try:
        if server_public_key is not None and client_instance is not None:
            asyncio.run(client_instance.login())
            asyncio.run(main(args.client_service_port, args.username, args.password, args.host))
        else:
            print(f"Client instant start failed or missing server public key")
    except KeyboardInterrupt:
        print("Server stopped manually.")
