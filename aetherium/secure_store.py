"""
Secure storage primitives: AES-256-GCM encryption/decryption over bytes with a provided key.
The key must be 32 bytes.
"""
from __future__ import annotations

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt_bytes(key: bytes, data: bytes) -> Tuple[str, str, str, str]:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    salt = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    tag = enc.tag
    return ct.hex(), salt.hex(), iv.hex(), tag.hex()


def decrypt_bytes(key: bytes, ct_hex: str, salt_hex: str, iv_hex: str, tag_hex: str) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    ct = bytes.fromhex(ct_hex)
    iv = bytes.fromhex(iv_hex)
    tag = bytes.fromhex(tag_hex)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt
