import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'SFS1'
VERSION = b'\x01'

def load_master_key_from_env(env_name: str = "SFS_MASTER_KEY") -> bytes:
    b64 = os.environ.get(env_name)
    if not b64:
        raise RuntimeError(f"Environment variable {env_name} not set.")
    key = base64.urlsafe_b64decode(b64)
    if len(key) != 32:
        raise ValueError("Master key must be 32 bytes after base64 decoding (AES-256).")
    return key

def generate_master_key_b64() -> str:
    key = os.urandom(32)
    return base64.urlsafe_b64encode(key).decode('utf-8')

def sha256_hex(data: bytes) -> str:
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
