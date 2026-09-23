import pytest

from crypto_core import (
    decrypt,
    decrypt_aes_gcm,
    decrypt_chacha20,
    decrypt_file,
    encrypt,
    encrypt_aes_gcm,
    encrypt_chacha20,
    encrypt_file,
)


@pytest.mark.parametrize("algorithm", ["AES-256-GCM", "ChaCha20-Poly1305"])
def test_encrypt_decrypt_round_trip(algorithm):
    data = b"data rahasia untuk pengujian"

    payload = encrypt(data, "password-kuat", algorithm)

    assert payload != data
    assert decrypt(payload, "password-kuat") == data


def test_wrong_password_fails():
    payload = encrypt(b"rahasia", "password-benar")

    with pytest.raises(Exception):
        decrypt(payload, "password-salah")


def test_tampered_payload_fails():
    payload = bytearray(encrypt(b"rahasia", "password-benar"))
    payload[-1] ^= 1

    with pytest.raises(Exception):
        decrypt(bytes(payload), "password-benar")


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        encrypt(b"rahasia", "")


@pytest.mark.parametrize(
    ("encryptor", "decryptor"),
    [(encrypt_aes_gcm, decrypt_aes_gcm), (encrypt_chacha20, decrypt_chacha20)],
)
def test_named_api_round_trip_and_tamper_detection(encryptor, decryptor):
    payload = encryptor(b"data lebih dari sekadar rahasia", "password-benar")

    assert decryptor(payload, "password-benar") == b"data lebih dari sekadar rahasia"
    payload["ciphertext"] = payload["ciphertext"][:-2] + "AA"
    with pytest.raises(ValueError, match="Password salah atau data telah diubah"):
        decryptor(payload, "password-benar")


@pytest.mark.parametrize("algorithm", ["AES-256-GCM", "ChaCha20-Poly1305"])
def test_file_round_trip_in_chunks(tmp_path, algorithm):
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.enc"
    restored = tmp_path / "restored.bin"
    content = bytes(range(256)) * 400
    source.write_bytes(content)

    encrypt_file(str(source), str(encrypted), "password-benar", algorithm)
    decrypt_file(str(encrypted), str(restored), "password-benar")

    assert restored.read_bytes() == content


def test_file_wrong_password_fails(tmp_path):
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.enc"
    source.write_bytes(b"rahasia file")
    encrypt_file(str(source), str(encrypted), "password-benar", "aes")

    with pytest.raises(ValueError, match="Password salah atau data telah diubah"):
        decrypt_file(str(encrypted), str(tmp_path / "restored.bin"), "password-salah")
