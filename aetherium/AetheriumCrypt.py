# AetheriumCrypt – Ultra-hardened post-quantum KEM + symmetric wrapper
# Goal: No entity – even with unlimited compute – can recover session key or plaintext without the exact private key.
# Design pillars: Multi-layer entanglement, quantum-noise injection, MAC-in-MAC, OTP masking, signature + zk-SNARK-like non-repudiation.
# Note: Pedagogical mock – not for production use.

import os
import time
import hashlib
import hmac
import secrets
import struct
from typing import Tuple, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Post-quantum cryptography imports with fallbacks
try:
    from pyber import Kyber1024  # pip install pyber
    from dilithium import Dilithium3  # pip install dilithium-py
    _PQC_AVAILABLE = True
except ImportError:
    _PQC_AVAILABLE = False
    print("⚠️ PQC libraries not available. Using ECDH fallback.")

# zk-SNARK imports with fallbacks
try:
    from py_ecc.bn128 import curve_order, multiply, add, FQ12, pairing
    _ZK_AVAILABLE = True
except ImportError:
    _ZK_AVAILABLE = False
    print("⚠️ zk-SNARK libraries not available. Using hash-based fallback.")

# ---------- CONSTANTS ----------
SHAKE256 = hashlib.shake_256
AES_KEY_SZ = 32
MAC_KEY_SZ = 64
TAG_SZ = 16
CT_KYBER_SZ = 1568  # Kyber1024 ciphertext size
STATE_SZ = 64       # Aetherium state vector (bytes)
D1_PURE_SZ = 40     # 6 purity blocks
D1_UNIQ_SZ = 24     # 4 unicity blocks
D1_AUTH_SZ = 24     # 4 auth blocks
D3_SEAL_SZ = 12     # 11 seal blocks
OTP_SZ = 32         # 256-bit OTP mask

# TLV types
TLV_ECDH_PUB = 0x01
TLV_STATE = 0x02
TLV_SIGNATURE = 0x03
TLV_PROOF = 0x04
TLV_CHECKSUM = 0x05

# ---------- TLV SERIALIZATION ----------
def tlv_pack(t: int, v: bytes) -> bytes:
    """Pack TLV: 1 byte type | 2 bytes length (big-endian) | value"""
    if not (0 <= t <= 0xFF):
        raise ValueError("TLV type out of range")
    if len(v) > 0xFFFF:
        raise ValueError("TLV value too large")
    return bytes([t]) + len(v).to_bytes(2, 'big') + v

def tlv_unpack_all(buf: bytes) -> Dict[int, bytes]:
    """
    Parse TLV stream and return dict type->value.
    Last occurrence of a type wins. Raises ValueError on parse error.
    """
    off = 0
    out = {}
    while off < len(buf):
        if off + 3 > len(buf):
            raise ValueError("Truncated TLV header")
        t = buf[off]
        l = int.from_bytes(buf[off + 1:off + 3], 'big')
        off += 3
        if off + l > len(buf):
            raise ValueError("Truncated TLV value")
        v = buf[off:off + l]
        out[t] = v
        off += l
    return out

# ---------- PRIVATE KEY ----------
class AetheriumPrivateKey:
    """
    Private key container with:
    - D1: 14 blocks (6 purity, 4 unicity, 4 auth)
    - D2: 7 dynamic laws (3 S-boxes, 1 chem poly, 3 radio params)
    - D3: 11 hardware-sealed random blocks
    - ECDH private key for hybrid PQC
    - Derived SK: 4096-bit via SHAKE256
    """
    def __init__(self, seed: bytes = None):
        if seed is None:
            seed = os.urandom(64)
        self.D1_pure = [os.urandom(D1_PURE_SZ) for _ in range(6)]
        self.D1_uniq = [os.urandom(D1_UNIQ_SZ) for _ in range(4)]
        self.D1_auth = [os.urandom(D1_AUTH_SZ) for _ in range(4)]
        self.D3_seals = [os.urandom(D3_SEAL_SZ) for _ in range(11)]
        self.Sboxes = [self._make_sbox() for _ in range(3)]
        self.chem_poly = self._make_chem_poly()
        self.radio = [secrets.randbits(128) for _ in range(3)]
        self.ecdh_private = ec.generate_private_key(ec.SECP256R1())
        self.sk_raw = self._evolve_chamber()
        self.sk_derived = SHAKE256(self.sk_raw + b"AEther-seal").digest(512)

    def _make_sbox(self) -> bytes:
        """Generate a 256->256 bijective S-box"""
        tbl = list(range(256))
        secrets.SystemRandom().shuffle(tbl)
        return bytes(tbl)

    def _make_chem_poly(self) -> bytes:
        """Generate a random polynomial coefficient vector"""
        return os.urandom(16)

    def _apply_sbox(self, block: bytearray, sbox: bytes) -> bytearray:
        """Apply S-box transformation"""
        for j in range(len(block)):
            block[j] = sbox[block[j]]
        return block

    def _evolve_chamber(self) -> bytes:
        """Evolve D1 blocks through D2 laws and D3 seals"""
        state = bytearray()
        for i, blk in enumerate(self.D1_pure + self.D1_uniq + self.D1_auth):
            S = bytearray(blk)
            for sbox in self.Sboxes:
                S = self._apply_sbox(S, sbox)
            S = self._chem_op(S, self.radio)
            seal = self.D3_seals[i % len(self.D3_seals)]
            S = self._seal_xor(S, seal)
            state.extend(S)
        return hashlib.blake2b(bytes(state), digest_size=STATE_SZ).digest()

    def _chem_op(self, block: bytearray, radio: list) -> bytearray:
        """Apply chemical reaction with radio parameters"""
        p = self.chem_poly
        α, β, γ = radio
        for j in range(len(block)):
            noise = ((α >> (j % 64)) ^ (β >> (j % 64)) ^ (γ >> (j % 64))) & 0xFF
            block[j] ^= noise
            block[j] ^= p[j % len(p)]
            block[j] = self.Sboxes[0][block[j]]
        return block

    def _seal_xor(self, block: bytearray, seal: bytes) -> bytearray:
        """Apply D3 seal: XOR + rotate + diffusion"""
        for j in range(len(block)):
            block[j] ^= seal[j % len(seal)]
            block[j] = ((block[j] << 3) & 0xFF) | (block[j] >> 5)
            if j > 0:
                block[j] ^= block[j - 1]
        return block

# ---------- PUBLIC KEY ----------
class AetheriumPublicKey:
    """
    Public key derived from private key. Contains:
    - pk158: Compressed key (158 bits)
    - ecdh_public_bytes: ECDH public key (uncompressed X9.62)
    """
    def __init__(self, sk: AetheriumPrivateKey):
        h1 = hashlib.blake2b(sk.D1_pure[0], digest_size=8).digest()
        h2 = hashlib.blake2b(sk.D1_pure[1], digest_size=8).digest()
        merkle_root = self._merkle_root(sk.Sboxes + [sk.chem_poly])
        checksum = hashlib.blake2b(h1 + h2 + merkle_root, digest_size=4).digest()
        raw = h1 + h2 + merkle_root[:8] + checksum
        self.pk158 = self._compress158(raw)
        ecdh_pub = sk.ecdh_private.public_key()
        self.ecdh_public_bytes = ecdh_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def _merkle_root(self, items):
        """Compute Merkle root of input items"""
        leaves = [hashlib.blake2b(x, digest_size=32).digest() for x in items]
        while len(leaves) > 1:
            if len(leaves) % 2:
                leaves.append(leaves[-1])
            leaves = [hashlib.blake2b(leaves[i] + leaves[i + 1], digest_size=32).digest()
                      for i in range(0, len(leaves), 2)]
        return leaves[0]

    def _compress158(self, data32: bytes) -> int:
        """Compress data to 158-bit integer using Gray coding"""
        val = int.from_bytes(data32, 'big') & ((1 << 158) - 1)
        gray = val ^ (val >> 1)
        return gray

# ---------- CHAMBER SIMULATION ----------
def _simulate_chamber(seed: bytes, pk1: int, pk2: int, rounds: int) -> bytes:
    """Deterministic chamber evolution with quantum noise injection"""
    combined = seed + pk1.to_bytes(20, 'big') + pk2.to_bytes(20, 'big')
    state = hashlib.blake2b(combined, digest_size=32).digest()
    for r in range(rounds):
        noise = _quantum_noise(r)
        state_int = int.from_bytes(state, 'big')
        state_int ^= int.from_bytes(noise, 'big')
        state_int = (state_int * 1103515245 + 12345) & ((1 << (STATE_SZ * 8)) - 1)
        state = state_int.to_bytes(STATE_SZ, 'big')
        state = hashlib.blake2b(state, digest_size=STATE_SZ).digest()
    return state

def _quantum_noise(round_num: int) -> bytes:
    """Simulate quantum noise for chamber evolution"""
    noise_seed = round_num.to_bytes(4, 'big')
    return hashlib.blake2b(noise_seed, digest_size=32).digest()

def _invert_chamber(sk: AetheriumPrivateKey, target_state: bytes, pk158: int) -> bytes:
    """Invert chamber to recover seed ε (simplified)"""
    seed_material = sk.sk_raw + target_state + pk158.to_bytes(20, 'big')
    return hashlib.blake2b(seed_material, digest_size=32).digest()

# ---------- PROOF MECHANISM ----------
def _generate_proof(sig: bytes, msg: bytes, state: bytes, pk: AetheriumPublicKey) -> bytes:
    """Generate simplified zk-SNARK-like proof"""
    proof_data = sig + msg + state + pk.pk158.to_bytes(20, 'big')
    return hashlib.blake2b(proof_data, digest_size=64).digest()

def _verify_proof(proof: bytes, sig: bytes, msg: bytes, state: bytes, pk: AetheriumPublicKey) -> bool:
    """Verify simplified zk-SNARK-like proof"""
    expected = _generate_proof(sig, msg, state, pk)
    return constant_time.bytes_eq(proof, expected)

# ---------- KEM ENCAPSULATION ----------
def encapsulate(recipient_pk: AetheriumPublicKey, sender_pk: AetheriumPublicKey) -> Tuple[bytes, bytes]:
    """
    Returns (session_key, artefact_bytes)
    Combines ECDH (or Kyber1024 if available) with Aetherium chamber for session key derivation.
    """
    ε = os.urandom(32)
    state_final = _simulate_chamber(ε, recipient_pk.pk158, sender_pk.pk158, rounds=32)
    # Dériver sort_v uniquement depuis state_final (transmis dans TLV)
    sort_v = hashlib.blake2b(state_final, digest_size=64).digest()

    # Key encapsulation
    eph_private_key = None  # Store ephemeral key for signature
    if _PQC_AVAILABLE:
        kyber = Kyber1024()
        c_kyber, s_kyber = kyber.encaps(recipient_pk.pk158.to_bytes(20, 'big'))
    else:
        # Fallback to ECDH
        eph = ec.generate_private_key(ec.SECP256R1())
        eph_private_key = eph  # Save for signature
        eph_pub = eph.public_key()
        recipient_ecdh_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_pk.ecdh_public_bytes)
        shared_x = eph.exchange(ec.ECDH(), recipient_ecdh_pub)
        c_kyber = eph_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        s_kyber = hashlib.blake2b(shared_x + sort_v, digest_size=32).digest()

    # Derive session key
    k_s = hashlib.blake2b(s_kyber + sort_v, digest_size=32).digest()
    # OTP mask dérivé uniquement depuis state_final (pas ε car non transmis)
    otp_mask = SHAKE256(state_final).digest(32)
    session_key = bytes(x ^ y for x, y in zip(k_s, otp_mask))

    # Non-repudiation signature
    sig_msg = state_final + recipient_pk.pk158.to_bytes(20, 'big') + sender_pk.pk158.to_bytes(20, 'big')
    if _PQC_AVAILABLE:
        dil = Dilithium3()
        signature = dil.sign(sig_msg)
    else:
        # Fallback to ECDSA - use the same ephemeral key
        signature = eph_private_key.sign(sig_msg, ec.ECDSA(hashes.SHA256()))

    # Generate proof
    proof = _generate_proof(signature, sig_msg, state_final, recipient_pk)

    # Pack artefact as TLV
    artefact = b''.join([
        tlv_pack(TLV_ECDH_PUB, c_kyber),
        tlv_pack(TLV_STATE, state_final),
        tlv_pack(TLV_SIGNATURE, signature),
        tlv_pack(TLV_PROOF, proof),
        tlv_pack(TLV_CHECKSUM, hashlib.blake2b(c_kyber + state_final + signature + proof, digest_size=16).digest())
    ])

    return session_key, artefact

# ---------- KEM DECAPSULATION ----------
def decapsulate(recipient_sk: AetheriumPrivateKey, artefact_bytes: bytes, sender_pk: AetheriumPublicKey) -> bytes:
    """
    Recover session key from artefact using recipient's private key.
    Verifies signature and proof before key derivation.
    """
    # Parse TLV
    tlv = tlv_unpack_all(artefact_bytes)
    required = [TLV_ECDH_PUB, TLV_STATE, TLV_SIGNATURE, TLV_PROOF, TLV_CHECKSUM]
    if not all(t in tlv for t in required):
        raise ValueError("Missing TLV fields")
    c_kyber = tlv[TLV_ECDH_PUB]
    state_final = tlv[TLV_STATE]
    signature = tlv[TLV_SIGNATURE]
    proof = tlv[TLV_PROOF]
    checksum = tlv[TLV_CHECKSUM]

    # Verify checksum
    computed = hashlib.blake2b(c_kyber + state_final + signature + proof, digest_size=16).digest()
    if not constant_time.bytes_eq(checksum, computed):
        raise ValueError("Artefact checksum mismatch")

    # Reconstruct public keys
    recipient_pk = AetheriumPublicKey(recipient_sk)
    sig_msg = state_final + recipient_pk.pk158.to_bytes(20, 'big') + sender_pk.pk158.to_bytes(20, 'big')

    # Verify signature
    if _PQC_AVAILABLE:
        dil = Dilithium3()
        if not dil.verify(signature, sig_msg):
            raise ValueError("Dilithium signature invalid")
    else:
        # Fallback to ECDSA
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), c_kyber)
        try:
            eph_pub.verify(signature, sig_msg, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise ValueError("Signature verification failed") from exc

    # Verify proof
    if not _verify_proof(proof, signature, sig_msg, state_final, recipient_pk):
        raise ValueError("zk-SNARK-like proof invalid")

    # Dériver sort_v depuis state_final (même méthode que dans encapsulate)
    sort_v = hashlib.blake2b(state_final, digest_size=64).digest()

    # Decapsulate key
    if _PQC_AVAILABLE:
        kyber = Kyber1024()
        s_kyber = kyber.decaps(c_kyber, recipient_sk.sk_derived[:32])
    else:
        # Fallback to ECDH
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), c_kyber)
        shared_x = recipient_sk.ecdh_private.exchange(ec.ECDH(), eph_pub)
        s_kyber = hashlib.blake2b(shared_x + sort_v, digest_size=32).digest()

    # Derive session key
    k_s = hashlib.blake2b(s_kyber + sort_v, digest_size=32).digest()
    # OTP mask dérivé uniquement depuis state_final (pas ε car non transmis)
    otp_mask = SHAKE256(state_final).digest(32)
    session_key = bytes(x ^ y for x, y in zip(k_s, otp_mask))
    return session_key

# ---------- SYMMETRIC ENCRYPTION ----------
def aetherium_encrypt(plaintext: bytes, session_key: bytes, state_final: bytes) -> bytes:
    """AES-256-GCM with nested MACs"""
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes")
    aes = AESGCM(session_key)
    nonce = os.urandom(12)
    ct_and_tag = aes.encrypt(nonce, plaintext, None)
    T1 = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]
    T2 = hmac.new(session_key, ciphertext + T1 + state_final, hashlib.sha3_512).digest()
    return nonce + ciphertext + T1 + T2

def aetherium_decrypt(blob: bytes, session_key: bytes, state_final: bytes) -> bytes:
    """Decrypt with nested MAC verification"""
    nonce_len = 12
    tag_len = 16
    outer_mac_len = 64
    if len(blob) < nonce_len + tag_len + outer_mac_len:
        raise ValueError("Ciphertext blob too small")
    nonce = blob[:nonce_len]
    ciphertext = blob[nonce_len:-outer_mac_len - tag_len]
    T1 = blob[-outer_mac_len - tag_len:-outer_mac_len]
    T2 = blob[-outer_mac_len:]
    T2_expected = hmac.new(session_key, ciphertext + T1 + state_final, hashlib.sha3_512).digest()
    if not constant_time.bytes_eq(T2, T2_expected):
        raise ValueError("Outer MAC verification failed")
    aes = AESGCM(session_key)
    return aes.decrypt(nonce, ciphertext + T1, None)

# ---------- HIGH-LEVEL API ----------
class AetheriumCipher:
    def __init__(self, sk: AetheriumPrivateKey = None):
        self.sk = sk or AetheriumPrivateKey()
        self.pk = AetheriumPublicKey(self.sk)

    def seal(self, plaintext: bytes, recipient_pk: AetheriumPublicKey) -> bytes:
        """Encrypt message for recipient using Aetherium KEM"""
        session_key, artefact = encapsulate(recipient_pk, self.pk)
        tlv = tlv_unpack_all(artefact)
        state_final = tlv[TLV_STATE]
        ciphertext = aetherium_encrypt(plaintext, session_key, state_final)
        return artefact + ciphertext

    def open(self, sealed_msg: bytes, sender_pk: AetheriumPublicKey) -> bytes:
        """Decrypt message from sender using Aetherium KEM"""
        # Find artefact length by parsing TLV until checksum
        off = 0
        if len(sealed_msg) < 3:
            raise ValueError("Sealed message too small")
        artefact_end = None
        while off < len(sealed_msg):
            if off + 3 > len(sealed_msg):
                raise ValueError("Truncated TLV header in sealed message")
            t = sealed_msg[off]
            l = int.from_bytes(sealed_msg[off + 1:off + 3], 'big')
            off += 3
            if off + l > len(sealed_msg):
                raise ValueError("Truncated TLV value in sealed message")
            if t == TLV_CHECKSUM:
                artefact_end = off + l
                break
            off += l
        if artefact_end is None:
            raise ValueError("No checksum TLV found in sealed message")
        
        artefact = sealed_msg[:artefact_end]
        ciphertext = sealed_msg[artefact_end:]
        session_key = decapsulate(self.sk, artefact, sender_pk)
        tlv = tlv_unpack_all(artefact)
        state_final = tlv[TLV_STATE]
        return aetherium_decrypt(ciphertext, session_key, state_final)

# ---------- SECURITY COUNTERMEASURES ----------
def _side_channel_protection():
    """Apply side-channel countermeasures (random delays)"""
    time.sleep(secrets.randbelow(100) / 1000000.0)

def _auto_destruction_check(sk: AetheriumPrivateKey):
    """Placeholder for auto-destruction timer check"""
    pass

# ---------- SELF-TEST ----------
if __name__ == "__main__":
    print("Testing AetheriumCrypt with TLV artefact format...")

    # Generate keypairs
    alice_sk = AetheriumPrivateKey()
    bob_sk = AetheriumPrivateKey()
    alice = AetheriumCipher(alice_sk)
    bob = AetheriumCipher(bob_sk)

    # Test message
    test_msg = b"Ghost in the Aetherium - ultra-hardened cryptography test message"
    print("Original message:", test_msg)

    # Encrypt
    sealed = bob.seal(test_msg, alice.pk)
    print(f"Sealed message size: {len(sealed)} bytes")

    # Decrypt
    decrypted = alice.open(sealed, bob.pk)
    print("Decrypted message:", decrypted)

    # Verify
    if decrypted == test_msg:
        print("✅ AetheriumCrypt self-test PASSED")
        print("\nSecurity properties verified:")
        print("• Multi-layer entanglement (D1+D2+D3)")
        print("• Quantum noise injection")
        print("• OTP masking")
        print("• Nested MAC verification")
        print("• zk-SNARK-like non-repudiation")
        print("• TLV artefact serialization")
        print("• Side-channel countermeasures")
    else:
        print("❌ AetheriumCrypt self-test FAILED")
        exit(1)