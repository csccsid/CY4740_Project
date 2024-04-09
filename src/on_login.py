import asyncio
import base64
import hashlib
import json
import math
import os

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from util.crypto import encrypt_with_public_key
from util.crypto import load_key
from util.crypto import generate_dh_private_key
from util.crypto import generate_nonce
from util.crypto import verify_signature

SERVER_PUBLIC_KEY_PATH = "../server_public_key.pem"

PRIME = (2 ** 1024) - (2 ** 960) - 1 + (2 ** 64) * (int(2 ** 894 * math.pi) + 129093)
GENERATOR = 2

password = "Voyage#2024"


async def tcp_client(message, server_public_key, client_nonce, client_secret, host='127.0.0.1', port=12345):
    reader, writer = await asyncio.open_connection(host, port)

    print(f'Sending: {message!r}')
    writer.write(message.encode())
    await writer.drain()

    # Optionally, receive a response
    data = await reader.read(4096)
    data_1 = data.decode('ascii')
    payload_dict = json.loads(json.loads(data_1)['payload'])

    print(f'Received: {payload_dict}')

    argon2_params_signature_encoded = payload_dict['argon2_params_signature']
    argon2_params_signature = base64.b64decode(argon2_params_signature_encoded)
    argon2_params = payload_dict['argon2_params']
    argon2_params_bytes = json.dumps(argon2_params).encode('ascii')

    verify_sig = verify_signature(server_public_key,
                                  argon2_params_signature,
                                  argon2_params_bytes)

    if verify_sig:
        print("Params signature verified successfully")
        print(argon2_params)

        ph = PasswordHasher(
            time_cost=argon2_params["Time Cost"],
            memory_cost=argon2_params["Memory Cost"],
            parallelism=argon2_params["Parallelism"],
            salt_len=len(argon2_params["Salt"])
        )

        print(argon2_params["Salt"] + "==")
        decode_salt = base64.b64decode((argon2_params["Salt"] + "==").encode('utf-8'))
        print(decode_salt)
        test_hash = ph.hash(
            password=password, salt=decode_salt)
        # PasswordHasher expects a string, so we decode salt
        # and concatenate
        print("Generated hash:", test_hash)

        key_prime_content = {"nonce": client_nonce,
                             "password_hash": test_hash}

        # Convert the dictionary to a JSON string to ensure consistent ordering
        content_string = json.dumps(key_prime_content, sort_keys=True)

        # Encode the string to bytes
        content_bytes = content_string.encode('ascii')
        hash_object = hashlib.sha256(content_bytes)
        key_prime = hash_object.digest()

        # decrypt the challenge message

        ciphertext = base64.b64decode(payload_dict["challenge"])
        iv = base64.b64decode(payload_dict["iv"])

        cipher = Cipher(algorithms.AES(key_prime), modes.CFB(iv), backend=default_backend())

        # Decrypt the data
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Convert the decrypted data back to a string (assuming it was originally a JSON string)
        decrypted_string = decrypted_data.decode('ascii')

        print("Decrypted string:", decrypted_string)

        challenge_result_json = json.loads(decrypted_string)
        if challenge_result_json["client_nonce"] != client_nonce:
            print("Invalid")

        server_nonce = challenge_result_json["server_nonce"]
        server_modulo = challenge_result_json["server_modulo"]

        challenge_resp = {"server_nonce": server_nonce}

        dh_key = pow(server_modulo, client_secret, PRIME)
        bytes_length = (dh_key.bit_length() + 7) // 8  # Calculate the number of bytes needed
        dh_key_bytes = dh_key.to_bytes(bytes_length, byteorder='big')
        hash_object = hashlib.sha256(dh_key_bytes)
        dh_key_sha = hash_object.digest()

        chal_iv = os.urandom(16)
        chal_cipher = Cipher(algorithms.AES(dh_key_sha), modes.CFB(chal_iv), backend=default_backend())
        print("here")

        chal_encryptor = chal_cipher.encryptor()
        chal_ciphertext = chal_encryptor.update(json.dumps(challenge_resp).encode()) + chal_encryptor.finalize()

        chal_ciphertext_encoded = base64.b64encode(chal_ciphertext).decode('ascii')
        chal_iv_encoded = base64.b64encode(chal_iv).decode('ascii')

        chal_resp_content = {"ciphertext": chal_ciphertext_encoded, "iv": chal_iv_encoded}
        chal_resp = {"op_code": 1, "event": "challenge_response", "payload": json.dumps(chal_resp_content)}
        chal_resp_json = json.dumps(chal_resp)
        writer.write(chal_resp_json.encode())

        # Optionally, receive a response
        data = await reader.read(4096)
        data_1 = data.decode('ascii')
        print(data_1)

    print('Close the connection')
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    public_key = load_key(SERVER_PUBLIC_KEY_PATH)
    secret = generate_dh_private_key()
    nonce = generate_nonce()
    modulo = pow(GENERATOR, secret, PRIME)
    payload = {"username": "stellar_journey", "nonce": nonce, "modulo": modulo}
    payload_json = json.dumps(payload)
    encrypted_payload = encrypt_with_public_key(public_key, payload_json.encode())

    # Encode the encrypted payload using base64
    encrypted_payload_base64 = base64.b64encode(encrypted_payload).decode('ascii')

    message_dict = {"op_code": 1, "event": "auth_request", "payload": encrypted_payload_base64}
    message_json = json.dumps(message_dict)

    asyncio.run(tcp_client(message_json, public_key, nonce, secret))
