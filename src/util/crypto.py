import argparse
import os
import secrets

import argon2
from argon2.exceptions import InvalidHash
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def encrypt_with_public_key(public_key, data):
    """
    Encrypts data using an RSA public key.

    Args:
    public_key (rsa.RSAPublicKey): The RSA public key for encryption.
    data (bytes): The data to be encrypted.

    Returns:
    bytes: The encrypted data.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_with_private_key(private_key, data):
    """
    Decrypts data using an RSA private key.

    Args:
    private_key (rsa.RSAPrivateKey): The RSA private key for decryption.
    data (bytes): The data to be decrypted.

    Returns:
    bytes: The decrypted data.
    """
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sign_data(private_key, data):
    """
    Signs data using a private RSA key.

    Args:
    private_key (rsa.RSAPrivateKey): The RSA private key to sign the data.
    data (bytes): The data to be signed.

    Returns:
    bytes: The digital signature.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key, signature, data):
    """
    Verifies a digital signature using a public RSA key.

    Args:
    public_key (rsa.RSAPublicKey): The RSA public key for signature verification.
    signature (bytes): The digital signature to verify.
    data (bytes): The data that was signed.

    Returns:
    bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def load_key(filename, public=True):
    """
    Loads an RSA key (public or private) from a specified file.

    Args:
    filename (str): The path to the key file.
    public (bool): True if loading a public key, False if loading a private key.

    Returns:
    rsa.RSAPublicKey or rsa.RSAPrivateKey: The loaded RSA key.
    """
    with open(filename, "rb") as key_file:
        key_data = key_file.read()

        try:
            # Check the file extension to determine the format
            if filename.endswith('.pem'):
                if public:
                    return serialization.load_pem_public_key(
                        key_data,
                        backend=default_backend()
                    )
                else:
                    return serialization.load_pem_private_key(
                        key_data,
                        password=None,
                        backend=default_backend()
                    )
            elif filename.endswith('.der'):
                if public:
                    return serialization.load_der_public_key(
                        key_data,
                        backend=default_backend()
                    )
                else:
                    return serialization.load_der_private_key(
                        key_data,
                        password=None,
                        backend=default_backend()
                    )
            else:
                raise ValueError("Unsupported key file format. Only '.pem' and '.der' are supported.")
        except ValueError as e:
            print("Error: ", e)
            exit(1)


def fetch_argon2_params(argon2_hash):
    try:
        # Use PasswordHasher to parse the hash
        hash_info = argon2.extract_parameters(argon2_hash)

        # Extracting the components
        version = hash_info.version
        time_cost = hash_info.time_cost
        memory_cost = hash_info.memory_cost
        parallelism = hash_info.parallelism
        salt = extract_salt_from_hash(argon2_hash)

        info_dict = {
            "Version": version,
            "Time Cost": time_cost,
            "Memory Cost": memory_cost,
            "Parallelism": parallelism,
            "Salt": salt.hex() if isinstance(salt, bytes) else salt,
        }

        return info_dict

    except InvalidHash as e:
        print(f"Error parsing hash: {e}")


def extract_salt_from_hash(argon2_hash):
    """
    Extracts and returns the salt from an Argon2 hash string.

    Parameters:
    - hashed_password: The Argon2 hashed password string.

    Returns:
    - The salt as a string, or None if the format is unexpected.
    """
    parts = argon2_hash.split("$")
    if len(parts) > 4:
        # Typically, the salt is the 5th element in the list when splitting by '$'
        salt_base64 = parts[4]
        return salt_base64
    else:
        print("Unexpected hash format.")
        return None


def generate_dh_private_key(bit_length=320):
    # Generate a random 320-bit integer
    private_key = secrets.randbits(bit_length)
    return private_key


def generate_nonce(length=16):
    # Generate a cryptographically strong random string of specified length
    return secrets.token_hex(length)
