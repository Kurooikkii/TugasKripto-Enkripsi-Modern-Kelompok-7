"""
test_rsa_hybrid.py
-------------------
Unit test untuk fitur pengayaan enkripsi hibrida (rsa_hybrid.py)
Jalankan dengan: python -m pytest tests/test_rsa_hybrid.py -v
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.hazmat.primitives import serialization

from rsa_hybrid import (
    generate_rsa_keypair,
    hybrid_encrypt,
    hybrid_decrypt,
    HybridDecryptionError,
    RSA_KEY_SIZE,
)


def test_generate_keypair_format_dan_ukuran():
    """Test 1: pasangan kunci yang dihasilkan harus PEM valid dan 2048-bit sesuai spesifikasi."""
    private_pem, public_pem = generate_rsa_keypair("password-test")

    private_key = serialization.load_pem_private_key(
        private_pem, password="password-test".encode("utf-8")
    )
    public_key = serialization.load_pem_public_key(public_pem)

    assert private_key.key_size == RSA_KEY_SIZE
    assert public_key.key_size == RSA_KEY_SIZE


def test_roundtrip_enkripsi_dekripsi_berhasil():
    """Test 2: enkripsi lalu dekripsi dengan kunci & password yang benar harus
    mengembalikan plaintext asli."""
    password = "password-kunci-123"
    private_pem, public_pem = generate_rsa_keypair(password)

    plaintext = b"Pesan rahasia untuk pengujian enkripsi hibrida."
    payload = hybrid_encrypt(plaintext, public_pem)
    hasil = hybrid_decrypt(payload, private_pem, password)

    assert hasil == plaintext


def test_password_private_key_salah_ditolak():
    """Test 3: private key yang benar tapi dibuka dengan password yang SALAH
    harus ditolak (HybridDecryptionError)."""
    private_pem, public_pem = generate_rsa_keypair("password-benar")

    plaintext = b"data penting"
    payload = hybrid_encrypt(plaintext, public_pem)

    with pytest.raises(HybridDecryptionError):
        hybrid_decrypt(payload, private_pem, "password-salah")


def test_private_key_tidak_cocok_ditolak():
    """Test 4: mendekripsi dengan private key dari pasangan kunci yang BEDA
    (bukan pasangan dari public key yang dipakai saat enkripsi) harus ditolak."""
    password = "password-sama"
    _, public_pem_a = generate_rsa_keypair(password)
    private_pem_b, _ = generate_rsa_keypair(password)  

    plaintext = b"pesan untuk A, bukan untuk B"
    payload = hybrid_encrypt(plaintext, public_pem_a)

    with pytest.raises(HybridDecryptionError):
        hybrid_decrypt(payload, private_pem_b, password)


def test_ciphertext_diubah_ditolak():
    """Test 5: payload hasil enkripsi yang diubah 1 byte (tamper) harus
    ditolak saat didekripsi, membuktikan integritas data terjaga."""
    password = "password-tamper-test"
    private_pem, public_pem = generate_rsa_keypair(password)

    plaintext = b"jangan diubah ya datanya"
    payload = bytearray(hybrid_encrypt(plaintext, public_pem))

    payload[-1] ^= 0xFF

    with pytest.raises(HybridDecryptionError):
        hybrid_decrypt(bytes(payload), private_pem, password)


def test_enkripsi_pesan_panjang():
    """Test tambahan: enkripsi hibrida tetap berfungsi untuk teks yang lebih
    panjang, membuktikan AES-GCM (bukan RSA langsung) yang menangani datanya."""
    password = "password-panjang"
    private_pem, public_pem = generate_rsa_keypair(password)

    plaintext = ("Teks panjang untuk diuji. " * 200).encode("utf-8")
    payload = hybrid_encrypt(plaintext, public_pem)
    hasil = hybrid_decrypt(payload, private_pem, password)

    assert hasil == plaintext