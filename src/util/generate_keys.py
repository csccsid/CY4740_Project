import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keys():
    # private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # public key derive from private key
    public_key = private_key.public_key()

    return private_key, public_key


def save_key(key, filename, public):
    if public:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def main():
    print("Current Working Directory:", os.getcwd())
    server_private_key, server_public_key = generate_keys()

    save_key(server_public_key, '../../server_public_key.pem', True)
    save_key(server_private_key, '../../server_private_key.pem', False)


if __name__ == '__main__':
    main()
