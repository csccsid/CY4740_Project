import json
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


"""
Some help functions
"""

"""
Check signature
"""
def check_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
    
"""
Help func to read the public/private key from files
"""
def load_key(file_path, public):
    try:
        with open(file_path, "rb") as key_file:
            if public:
                return serialization.load_pem_public_key(
                    key_file.read()
                )
            else:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
    except Exception as e:
        print(f"Error loading key from {file_path}: {e}")
        sys.exit(1)

"""
Pack a package
"""
def pack_message(message_json, op_cdde):
    message = json.dumps(message_json).encode()
    total_length = 4 + 1 + len(message)
    return struct.pack('!IB', total_length, op_cdde) + message