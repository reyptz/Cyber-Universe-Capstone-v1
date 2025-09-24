import secrets
import hashlib
import os
import struct

# -----------------------------------------------------
# Primitives placeholders (à remplacer par vraies libs)
# -----------------------------------------------------

def kyber_encapsulate(pk):
    """Simule Kyber1024 KEM encapsulation"""
    skey = secrets.token_bytes(32)  # 256 bits
    ct = secrets.token_bytes(1536)  # ~1.5 KB
    return skey, ct

def kyber_decapsulate(sk, ct):
    """Simule Kyber1024 KEM decapsulation"""
    skey = secrets.token_bytes(32)  # 256 bits (stub)
    return skey

def dilithium_sign(data, sk):
    """Simule Dilithium3 signature"""
    return secrets.token_bytes(2048)  # stub

def dilithium_verify(data, sig, pk):
    """Simule vérification"""
    return True

def zk_snark_prove(data, witness):
    """Simule preuve SNARK"""
    return secrets.token_bytes(512)

def zk_snark_verify(data, proof):
    return True

def aes_gcm_siv_encrypt(key, plaintext, associated_data=b""):
    """Simule AES-256-GCM-SIV"""
    nonce = secrets.token_bytes(16)
    ct = bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])  # XOR stub
    tag = hashlib.sha3_256(ct + nonce).digest()
    return ct, tag

def aes_gcm_siv_decrypt(key, ciphertext, tag, associated_data=b""):
    """Simule déchiffrement (stub)"""
    pt = bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext)])
    return pt

# -----------------------------------------------------
# S-Box, Reaction, Radio Operators (stubs)
# -----------------------------------------------------

def sbox_mutate(x, radio):
    return (x ^ radio) & ((1 << 256) - 1)

def reaction_bicubic(x, radio):
    return ((x * radio) ^ (radio >> 1)) & ((1 << 256) - 1)

def permutation_xor_rotate(x, seal):
    rot = seal % 96
    return ((x << rot) | (x >> (320 - rot))) & ((1 << 320) - 1) ^ seal

# -----------------------------------------------------
# Génération de la clé privée (SK)
# -----------------------------------------------------

class AetheriumUltraKeyPair:
    def __init__(self, sk_raw, sk_dig, pk, auth_chunks, sboxes, reaction, radios, seals):
        self.sk_raw = sk_raw
        self.sk_dig = sk_dig
        self.pk = pk
        self.auth_chunks = auth_chunks
        self.sboxes = sboxes
        self.reaction = reaction
        self.radios = radios
        self.seals = seals

    @staticmethod
    def generate():
        # D1 blocs
        d1_purity = [secrets.randbits(320) for _ in range(6)]
        d1_unicity = [secrets.randbits(192) for _ in range(4)]
        d1_auth = [secrets.randbits(192) for _ in range(4)]
        d1 = d1_purity + d1_unicity + d1_auth

        # D2 lois dynamiques
        sboxes = [secrets.randbits(256) for _ in range(3)]
        reaction = secrets.randbits(256)
        radios = [secrets.randbits(128) for _ in range(3)]

        # D3 sceaux aléatoires hybrides
        seals = [secrets.randbits(96) for _ in range(11)]

        # Pipeline transformation
        state = []
        for i, bloc in enumerate(d1):
            S = bloc
            for idx, sb in enumerate(sboxes):
                S = sbox_mutate(S, radios[idx % 3])
            S = reaction_bicubic(S, radios[i % 3])
            S = permutation_xor_rotate(S, seals[i % 11])
            state.append(S)
        sk_raw = b"".join(S.to_bytes((S.bit_length() + 7) // 8, "big") for S in state)

        # Post-hash
        sk_dig = hashlib.shake_256(sk_raw + "Æth-seal".encode("utf-8")).digest(512)

        # PK extraction:
        pk_purity = (d1_purity[0] ^ d1_purity[1]) & ((1 << 64) - 1)  # 64 bits compressés
        root_hash = hashlib.shake_256(
            b"".join(sb.to_bytes(32, "big") for sb in sboxes) + reaction.to_bytes(32, "big")
        ).digest(8)  # 64 bits
        checksum = hashlib.sha3_256(sk_raw).digest()[0] & ((1 << 30) - 1)  # 30 bits

        # Codage Gray + Hilbert (stub)
        pk = (pk_purity << 94) | (int.from_bytes(root_hash, "big") << 30) | checksum

        return AetheriumUltraKeyPair(sk_raw, sk_dig, pk, d1_auth, sboxes, reaction, radios, seals)

# -----------------------------------------------------
# Univers simulé (evolve)
# -----------------------------------------------------

class UltraUniverse:
    N = 16
    def __init__(self, pk):
        self.pk = pk
        self.state = [secrets.randbits(32) for _ in range(32)]

    def evolve(self, rounds, epsilon):
        rnd = secrets.SystemRandom(epsilon)
        for _ in range(rounds):
            for i in range(len(self.state)):
                self.state[i] = (self.state[i] + rnd.randrange(self.N)) % self.N
                self.state[i] ^= rnd.randrange(256)
        return self.snapshot()

    def snapshot(self):
        # ~1KB
        return b"".join(struct.pack(">I", s) for s in self.state)

    @staticmethod
    def hash_state(state, epsilon):
        return hashlib.shake_256(state + epsilon.to_bytes(32, "big")).digest(64)  # 512 bits

# -----------------------------------------------------
# Encapsulation KEM ultra-durcie (Bob → Alice)
# -----------------------------------------------------

def encapsulate(pk_alice, seals, sboxes, reaction, radios, auth_chunks):
    epsilon = secrets.randbits(256)
    universe = UltraUniverse(pk_alice)
    state_final = universe.evolve(32, epsilon)
    sort_v = UltraUniverse.hash_state(state_final, epsilon)

    s_kyb, ct_kyber = kyber_encapsulate(pk_alice)
    k_s = hashlib.sha3_256(bytes(a ^ b for a, b in zip(s_kyb, sort_v[:32]))).digest()
    M = hashlib.shake_256(epsilon.to_bytes(32, "big")).digest(32)  # Updated
    key_effective = bytes(a ^ b for a, b in zip(k_s, M))

    capsule_data = state_final + ct_kyber
    sig = dilithium_sign(capsule_data, auth_chunks[0].to_bytes(24, "big"))
    proof = zk_snark_prove(capsule_data, auth_chunks[0].to_bytes(24, "big"))
    checksum = hashlib.sha3_256(state_final + ct_kyber).digest()[:16]

    artefact = {
        "ct_kyber": ct_kyber.hex(),
        "state_final": state_final.hex(),
        "sig": sig.hex(),
        "proof": proof.hex(),
        "checksum": checksum.hex(),
        "epsilon": epsilon.to_bytes(32, "big").hex()
    }
    return artefact, key_effective, s_kyb

# -----------------------------------------------------
# Décapsulation KEM ultra-durcie (Alice)
# -----------------------------------------------------

def decapsulate(sk_pair, artefact):
    state_final = bytes.fromhex(artefact["state_final"])
    ct_kyber = bytes.fromhex(artefact["ct_kyber"])
    sig = bytes.fromhex(artefact["sig"])
    proof = bytes.fromhex(artefact["proof"])
    epsilon = int.from_bytes(bytes.fromhex(artefact["epsilon"]), "big")

    if not dilithium_verify(state_final + ct_kyber, sig, sk_pair.pk):
        raise Exception("Signature Dilithium invalide")
    if not zk_snark_verify(state_final + ct_kyber, proof):
        raise Exception("Preuve SNARK invalide")

    sort_v = UltraUniverse.hash_state(state_final, epsilon)
    s_kyb = kyber_decapsulate(sk_pair.sk_dig, ct_kyber)
    k_s = hashlib.sha3_256(bytes(a ^ b for a, b in zip(s_kyb, sort_v[:32]))).digest()
    M = hashlib.shake_256(epsilon.to_bytes(32, "big")).digest(32)  # Updated
    key_effective = bytes(a ^ b for a, b in zip(k_s, M))
    return key_effective

# -----------------------------------------------------
# Chiffrement du message
# -----------------------------------------------------

def encrypt_message(key_effective, message, state_final):
    ciphertext, T1 = aes_gcm_siv_encrypt(key_effective, message)
    T2 = hashlib.sha3_512(message + T1 + state_final).digest()
    return {
        "ciphertext": ciphertext.hex(),
        "T1": T1.hex(),
        "T2": T2.hex()
    }

def decrypt_message(key_effective, artefact, enc_obj):
    ciphertext = bytes.fromhex(enc_obj["ciphertext"])
    T1 = bytes.fromhex(enc_obj["T1"])
    T2 = bytes.fromhex(enc_obj["T2"])
    state_final = bytes.fromhex(artefact["state_final"])
    pt = aes_gcm_siv_decrypt(key_effective, ciphertext, T1)
    # Vérif MACs
    T2_check = hashlib.sha3_512(pt + T1 + state_final).digest()
    if T2_check != T2:
        raise Exception("MAC externe T2 invalide")
    return pt

# -----------------------------------------------------
# Exemple d’utilisation
# -----------------------------------------------------

if __name__ == "__main__":
    # Génération des clés
    print("Génération des clés d'Alice et Bob...")
    alice_keys = AetheriumUltraKeyPair.generate()
    bob_keys = AetheriumUltraKeyPair.generate()

    # Encapsulation par Bob pour Alice
    artefact, key_effective, s_kyb = encapsulate(
        alice_keys.pk, bob_keys.seals, bob_keys.sboxes, bob_keys.reaction, bob_keys.radios, bob_keys.auth_chunks
    )

    # Affichage des détails d'encapsulation
    print("\n------ Process: Encapsulation Details ------")
    print("Clé publique d'Alice (pk):", alice_keys.pk)
    print("Artefact de capsule:")
    for k, v in artefact.items():
        print(f"  {k}: {v}")
    print("Clé effective générée par Bob:", key_effective.hex())

    # Message secret
    message = b"Bonjour ultra-durci!"
    print("\nMessage original:", message.decode())

    # Chiffrement du message
    enc_obj = encrypt_message(key_effective, message, bytes.fromhex(artefact["state_final"]))
    print("\nObjet de chiffrement:")
    for k, v in enc_obj.items():
        print(f"  {k}: {v}")

    # Pour test, surcharger kyber_decapsulate pour retourner la clé correcte
    def kyber_decapsulate(sk, ct):
        return s_kyb  # clé utilisée pour générer la capsule

    # Décapsulation par Alice et déchiffrement
    key_effective_alice = decapsulate(alice_keys, artefact)
    print("\n------ Process: Décapsulation Details ------")
    print("Clé effective calculée par Alice:", key_effective_alice.hex())

    recovered = decrypt_message(key_effective_alice, artefact, enc_obj)
    print("Message récupéré:", recovered.decode())