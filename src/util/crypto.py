import base64
import hashlib
import json
import os
import secrets

import argon2
from argon2.exceptions import InvalidHash
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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


def get_sha256_dh_key(dh_key):
    """
    Generates an SHA-256 hash of a Diffie-Hellman key.

    This function converts a Diffie-Hellman key from an integer to bytes,
    hashes it using SHA-256, and returns the hash as a byte string.
    This byte string can be used as a symmetric key for cryptographic algorithms.

    Parameters:
    - dh_key (int): The Diffie-Hellman key as an integer.

    Returns:
    - bytes: The SHA-256 hash of the Diffie-Hellman key.
    """
    bytes_length = (dh_key.bit_length() + 7) // 8  # Calculate the number of bytes needed
    dh_key_bytes = dh_key.to_bytes(bytes_length, byteorder='big')
    hash_object = hashlib.sha256(dh_key_bytes)
    return hash_object.digest()


def decrypt_with_dh_key(dh_key, cipher_text, iv):
    """
    Decrypts AES-encrypted data using a Diffie-Hellman key.

    Parameters:
    - dh_key (bytes): The Diffie-Hellman key.
    - cipher_text (str): Base64-encoded encrypted data.
    - iv (str): Base64-encoded initialization vector.

    Returns:
    - dict: The decrypted data parsed as JSON.
    """
    dh_key_sha = get_sha256_dh_key(dh_key)
    cipher_text = base64.b64decode(cipher_text)
    chal_iv = base64.b64decode(iv)
    cipher = Cipher(algorithms.AES(dh_key_sha), modes.CFB(chal_iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

    # Convert the decrypted data back to a string (assuming it was originally a JSON string)
    decrypted_string = decrypted_data.decode('ascii')
    return json.loads(decrypted_string)


def encrypt_with_dh_key(dh_key, data):
    """
    Encrypts the given data using the Diffie-Hellman key (dh_key) after hashing it with SHA-256.

    Parameters:
    dh_key (bytes): The Diffie-Hellman key used for encryption.
    data (dict): The data to encrypt, which must be serializable to JSON.

    Returns:
    tuple: A tuple containing two strings; the base64-encoded ciphertext and the base64-encoded initialization vector (IV).

    The encryption uses AES algorithm in CFB mode with a 16-byte IV.
    """
    dh_key_sha = get_sha256_dh_key(dh_key)

    return encrypt_with_key(dh_key_sha, data)


def encrypt_with_key(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json.dumps(data).encode()) + encryptor.finalize()

    ciphertext_encoded = base64.b64encode(ciphertext).decode('ascii')
    iv_encoded = base64.b64encode(iv).decode('ascii')
    return ciphertext_encoded, iv_encoded


def decrypt_with_key(key, cipher_encoded, iv_encoded):
    iv = base64.b64decode(iv_encoded)
    ciphertext = base64.b64decode(cipher_encoded)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return data_bytes.decode()


def encrypt_with_key_prime(key_content, data):
    # Convert the dictionary to a JSON string to ensure consistent ordering
    content_string = json.dumps(key_content, sort_keys=True)

    # Encode the string to bytes
    content_bytes = content_string.encode('ascii')
    hash_object = hashlib.sha256(content_bytes)
    key_prime = hash_object.digest()

    return encrypt_with_key(key_prime, data)


def decrypt_with_key_prime(key_content, cipher_encoded, iv_encoded):
    # Convert the dictionary to a JSON string to ensure consistent ordering
    content_string = json.dumps(key_content, sort_keys=True)

    # Encode the string to bytes
    content_bytes = content_string.encode('ascii')
    hash_object = hashlib.sha256(content_bytes)
    key_prime = hash_object.digest()

    return decrypt_with_key(key_prime, cipher_encoded, iv_encoded)
