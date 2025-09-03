import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'SFS1'
VERSION = b'\x01'

def generate_master_key() -> bytes:
    key = os.urandom(32)
    return key

def save_master_key(path: str, key: bytes):
    with open(path, "wb") as f:
        f.write(base64.urlsafe_b64encode(key))

def load_master_key(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    return base64.urlsafe_b64decode(data)

def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()

def make_metadata(orig_filename: str, data_bytes: bytes) -> dict:
    return {
        "orig_filename": orig_filename,
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "sha256": sha256_hex(data_bytes),
        "size": len(data_bytes)
    }

def encrypt_file_bytes(key: bytes, orig_filename: str, plaintext: bytes) -> bytes:
    aes = AESGCM(key)
    file_nonce = os.urandom(12)
    meta_nonce = os.urandom(12)
    meta = make_metadata(orig_filename, plaintext)
    meta_plain = json.dumps(meta, separators=(',', ':')).encode('utf-8')
    meta_ct = aes.encrypt(meta_nonce, meta_plain, None)
    file_ct = aes.encrypt(file_nonce, plaintext, None)
    meta_len = len(meta_ct).to_bytes(4, 'big')
    package = MAGIC + VERSION + file_nonce + meta_nonce + meta_len + meta_ct + file_ct
    return package

def decrypt_file_bytes(key: bytes, package: bytes) -> dict:
    if len(package) < 4 + 1 + 12 + 12 + 4:
        raise ValueError("Package too small or corrupt.")
    pos = 0
    if package[pos:pos+4] != MAGIC:
        raise ValueError("Invalid magic header.")
    pos += 4
    version = package[pos:pos+1]; pos += 1
    if version != VERSION:
        raise ValueError("Unsupported version.")
    file_nonce = package[pos:pos+12]; pos += 12
    meta_nonce = package[pos:pos+12]; pos += 12
    meta_len = int.from_bytes(package[pos:pos+4], 'big'); pos += 4
    meta_ct = package[pos:pos+meta_len]; pos += meta_len
    file_ct = package[pos:]
    aes = AESGCM(key)
    meta_plain = aes.decrypt(meta_nonce, meta_ct, None)
    meta = json.loads(meta_plain.decode('utf-8'))
    plaintext = aes.decrypt(file_nonce, file_ct, None)
    expected = meta.get("sha256")
    actual = sha256_hex(plaintext)
    if expected != actual:
        raise ValueError("Integrity check failed: SHA-256 mismatch (file tampered or wrong key).")
    return {"metadata": meta, "plaintext": plaintext}
