import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file_aes(plaintext, key, filename):
    key_bytes = base64.urlsafe_b64decode(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    tag = encryptor.tag
    key_hash = hashlib.sha256(key_bytes).hexdigest()
    return ciphertext, iv, tag, key_hash

def decrypt_file_aes(filepath, key):
    key_bytes = base64.urlsafe_b64decode(key)
    with open(filepath, "rb") as f:
        ciphertext = f.read()

    meta_path = filepath + ".json"
    with open(meta_path) as mf:
        meta = json.load(mf)

    iv = bytes.fromhex(meta["iv"])
    tag = bytes.fromhex(meta["tag"])

    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return meta["original_name"], plaintext
