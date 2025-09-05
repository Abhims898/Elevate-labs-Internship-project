import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def validate_key(user_key: str) -> bytes:
    """Validate and prepare AES key (must be 16, 24, or 32 bytes)."""
    key_bytes = user_key.encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    return key_bytes

def encrypt_file_aes(plaintext, user_key, filename):
    key_bytes = validate_key(user_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    tag = encryptor.tag
    key_hash = hashlib.sha256(key_bytes).hexdigest()
    return ciphertext, iv, tag, key_hash

def decrypt_file_aes(filepath, user_key):
    key_bytes = validate_key(user_key)
    with open(filepath, "rb") as f:
        ciphertext = f.read()

    meta_path = filepath + ".json"
    with open(meta_path) as mf:
        meta = json.load(mf)

    # ✅ Verify integrity using SHA256
    calc_hash = hashlib.sha256(ciphertext).hexdigest()
    if calc_hash != meta["sha256"]:
        raise ValueError("❌ File integrity check failed! The encrypted file may have been tampered with.")

    iv = bytes.fromhex(meta["iv"])
    tag = bytes.fromhex(meta["tag"])

    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return meta["original_name"], plaintext
