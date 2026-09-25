"""
rsa_hybrid.py — Fitur pengayaan: Enkripsi Hibrida (AES-256-GCM + RSA-OAEP).

Data dienkripsi AES pakai session key acak, lalu session key itu
dibungkus RSA Public Key. Dekripsi: buka session key pakai RSA Private
Key, baru dekripsi datanya. RSA gak dipakai langsung ke data karena
lambat untuk data besar -- makanya cuma dipakai buat bungkus kuncinya.
"""

import os
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

SESSION_KEY_SIZE = 32  
NONCE_SIZE = 12
RSA_KEY_SIZE = 2048


class HybridDecryptionError(Exception):
    """Dilempar saat private key salah / data rusak / diubah."""
    pass


def generate_rsa_keypair(password: str):
    """
    Bikin pasangan kunci RSA baru.
    Return: (private_pem: bytes, public_pem: bytes)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def hybrid_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    Enkripsi plaintext dengan skema hibrida AES-256-GCM + RSA-OAEP.
    public_key_pem: isi file public key (.pem) dalam bytes.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)

    session_key = os.urandom(SESSION_KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, associated_data=None)

    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    header = struct.pack(">H", len(encrypted_session_key))  
    return header + encrypted_session_key + nonce + ciphertext


def hybrid_decrypt(payload: bytes, private_key_pem: bytes, password: str) -> bytes:
    """
    Dekripsi payload hasil hybrid_encrypt().
    private_key_pem: isi file private key (.pem) dalam bytes.
    Raise HybridDecryptionError kalau private key salah / data rusak.
    """
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=password.encode())
    except Exception:
        raise HybridDecryptionError("Private key tidak valid atau formatnya salah.")

    if len(payload) < 2:
        raise HybridDecryptionError("Data tidak valid atau rusak.")

    key_len = struct.unpack(">H", payload[:2])[0]
    offset = 2

    encrypted_session_key = payload[offset:offset + key_len]
    offset += key_len

    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = payload[offset:]

    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise HybridDecryptionError("Private key salah atau tidak cocok dengan public key yang dipakai enkripsi.")

    try:
        return AESGCM(session_key).decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise HybridDecryptionError("Dekripsi gagal: data telah diubah (tamper terdeteksi).")


if __name__ == "__main__":
    password = "password-rsa-kuat"
    private_pem, public_pem = generate_rsa_keypair(password)
    print("Private key (rahasia, JANGAN disebar):")
    print(private_pem.decode())
    print("Public key (boleh disebar):")
    print(public_pem.decode())

    pesan = b"Pesan rahasia yang dikirim pakai enkripsi hibrida!"
    payload = hybrid_encrypt(pesan, public_pem)
    print(f"\nUkuran payload terenkripsi: {len(payload)} byte")

    hasil = hybrid_decrypt(payload, private_pem, password)
    print("Hasil dekripsi:", hasil.decode())

    private_pem_lain, _ = generate_rsa_keypair(password)
    try:
        hybrid_decrypt(payload, private_pem_lain, password)
    except HybridDecryptionError as e:
        print("Sesuai harapan, ditolak:", e)
