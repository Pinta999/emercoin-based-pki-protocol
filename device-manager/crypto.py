from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def gen_rsa_key():
    try:
        f = open('keys/privkey.pem', 'rb')
        pemlines = f.read()
        private_key = load_pem_private_key(pemlines, None)
    except IOError:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        pem_priv = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('keys/privkey.pem', 'wb') as pem_out:
            pem_out.write(pem_priv)
        with open('keys/pubkey.pem', 'wb') as pem_out:
            pem_publ = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pem_out.write(pem_publ)

    return private_key

def load_pubkey_from_file(path):
    with open(path, 'rb') as input:
        pem_lines = input.read()
    return get_pubkey_from_bytes(pem_lines)

def load_privkey_from_file(path):
    with open(path, 'rb') as input:
        pem_lines = input.read()
    return load_pem_private_key(pem_lines, None)

def get_pubkey_bytes(pubkey):
    return pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def get_pubkey_from_bytes(pubkey_bytes):
    key = None
    try:
        key = load_pem_public_key(pubkey_bytes, None)
    except Exception:
        print("error in iak key")
    
    return key;

def get_pubkey_from_privkey(privkey):
    return privkey.public_key()

def asym_decrypted_message(privkey, ciphertext):
    plaintext = privkey.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return plaintext

def sign_message(privkey, message):
    signature = privkey.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
    )
    return signature


def verify_signature(pubkey, signature, message, digest = None):
    if digest != 'digest':
        pubkey.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    else:
        pubkey.verify(
            signature,
            message,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )


def get_message_digest(message):
    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(message)
    return digest_ctx.finalize()


