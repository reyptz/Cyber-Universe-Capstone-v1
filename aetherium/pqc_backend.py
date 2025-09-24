"""
PQC backend using Open Quantum Safe (OQS) if available.
Falls back to Ed25519 for signatures if OQS is not installed.
KEM fallback is not provided here; callers should detect and use alternative KEMs.
"""
from __future__ import annotations

from typing import Tuple, Optional

try:
    import oqs  # type: ignore
    HAS_OQS = True
except Exception:
    oqs = None
    HAS_OQS = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization, hashes


class PQC:
    KEM_ALG = "Kyber768"
    SIG_ALG = "Dilithium3"

    # ------------- KEM -------------
    @staticmethod
    def has_kem() -> bool:
        return HAS_OQS

    @staticmethod
    def kem_generate_keypair() -> Tuple[bytes, bytes]:
        if not HAS_OQS:
            raise RuntimeError("OQS not available: KEM unsupported")
        with oqs.KeyEncapsulation(PQC.KEM_ALG) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk

    @staticmethod
    def kem_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        if not HAS_OQS:
            raise RuntimeError("OQS not available: KEM unsupported")
        with oqs.KeyEncapsulation(PQC.KEM_ALG) as kem:
            ct, ss = kem.encap_secret(pk)
        return ct, ss

    @staticmethod
    def kem_decapsulate(sk: bytes, ct: bytes) -> bytes:
        if not HAS_OQS:
            raise RuntimeError("OQS not available: KEM unsupported")
        with oqs.KeyEncapsulation(PQC.KEM_ALG) as kem:
            kem.import_secret_key(sk)
            ss = kem.decap_secret(ct)
        return ss

    # ------------- SIGN -------------
    @staticmethod
    def has_sig() -> bool:
        return HAS_OQS or True  # Ed25519 fallback

    @staticmethod
    def sig_generate_keypair() -> Tuple[bytes, bytes, str]:
        if HAS_OQS:
            with oqs.Signature(PQC.SIG_ALG) as sig:
                pk = sig.generate_keypair()
                sk = sig.export_secret_key()
            return pk, sk, f"oqs:{PQC.SIG_ALG}"
        # Fallback Ed25519
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        skb = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pkb = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pkb, skb, "ed25519"

    @staticmethod
    def sig_sign(message: bytes, sk: bytes, alg: str) -> bytes:
        if alg.startswith("oqs:"):
            if not HAS_OQS:
                raise RuntimeError("OQS not available for signature")
            oqs_alg = alg.split(":", 1)[1]
            with oqs.Signature(oqs_alg) as sig:
                sig.import_secret_key(sk)
                return sig.sign(message)
        # ed25519
        sk_obj = Ed25519PrivateKey.from_private_bytes(sk)
        return sk_obj.sign(message)

    @staticmethod
    def sig_verify(message: bytes, signature: bytes, pk: bytes, alg: str) -> bool:
        if alg.startswith("oqs:"):
            if not HAS_OQS:
                return False
            oqs_alg = alg.split(":", 1)[1]
            with oqs.Signature(oqs_alg) as sig:
                return sig.verify(message, signature, pk)
        # ed25519
        try:
            pk_obj = Ed25519PublicKey.from_public_bytes(pk)
            pk_obj.verify(signature, message)
            return True
        except Exception:
            return False
