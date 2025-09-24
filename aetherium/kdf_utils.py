"""
Key derivation utilities with Argon2id (preferred) and scrypt fallback.
"""
from __future__ import annotations

import os
from typing import Tuple

try:
    from argon2.low_level import Type, hash_secret_raw  # type: ignore
    HAS_ARGON2 = True
except Exception:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


def generate_salt(size: int = 32) -> bytes:
    return os.urandom(size)


def derive_key_argon2id(password: str, salt: bytes, length: int = 32,
                        time_cost: int = 3, memory_cost_kib: int = 64 * 1024,
                        parallelism: int = 1) -> bytes:
    if not HAS_ARGON2:
        raise RuntimeError("Argon2 not available")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )


def derive_key_scrypt(password: str, salt: bytes, length: int = 32,
                      n: int = 2**15, r: int = 8, p: int = 1) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))


def derive_key(password: str, salt: bytes, length: int = 32) -> Tuple[bytes, str]:
    """Derive a key using Argon2id if available, otherwise scrypt.
    Returns (key, algorithm_used)
    """
    if HAS_ARGON2:
        key = derive_key_argon2id(password, salt, length=length)
        return key, "argon2id"
    key = derive_key_scrypt(password, salt, length=length)
    return key, "scrypt"
